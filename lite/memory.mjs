// LSRE-lite: локальная память на SQLite FTS5.
// Четыре слоя (Hindsight-модель): факты -> наблюдения -> граф -> страницы.
// Без эмбеддингов и без сети: только SQL, лексика и детерминированный консолидатор.
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const SCHEMA_VERSION = 1;

// --- недоверенные данные -------------------------------------------------
// Всё, что пришло из анализируемого файла, помечается и чистится от управляющих
// символов: текст из малвари не должен выглядеть как инструкция.
export function untrusted(value, source = 'file', max = 200) {
  // Экранируем, а не вырезаем < >: имя файла не должно закрыть наш маркер.
  const clean = String(value ?? '')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069]/g, '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .slice(0, max);
  return `<untrusted source="${source}">${clean}</untrusted>`;
}

const SECRET_PATTERNS = [
  [/\b(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}/gi, '$1[REDACTED]'],
  [/\b(api[_-]?key|apikey|access[_-]?key|secret|password|passwd|pwd|token)\b(\s*[=:]\s*)["']?([^\s"'`,;]{6,})/gi, '$1$2[REDACTED]'],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}/g, '[REDACTED:slack]'],
  [/\bAIza[0-9A-Za-z_-]{35}\b/g, '[REDACTED:google]'],
  [/\bAKIA[0-9A-Z]{16}\b/g, '[REDACTED:aws]'],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, '[REDACTED:github]'],
  [/(\/\/)[^/\s:@]+:[^/\s@]+@/g, '$1[REDACTED]@'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '[REDACTED:private-key]'],
];
// Длинный base64-блоб маскируем, но чистый hex (sha-хеши, GUID) — нет: это данные.
const BLOB_RE = /[A-Za-z0-9+/]{40,}={0,2}/g;

export function redact(text) {
  let output = String(text ?? '');
  const hits = [];
  for (const [pattern, replacement] of SECRET_PATTERNS) {
    output = output.replace(pattern, (...args) => {
      const match = args[0];
      hits.push(match.slice(0, 24));
      return replacement.replace(/\$(\d)/g, (_, index) => args[Number(index)] ?? '');
    });
  }
  output = output.replace(BLOB_RE, (match) => (/^[0-9a-fA-F]+$/.test(match) ? match : '[REDACTED:blob]'));
  return { output, hits };
}


// --- схема ---------------------------------------------------------------
const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS facts (
  id     INTEGER PRIMARY KEY,
  bank   TEXT NOT NULL,
  ts     TEXT NOT NULL,
  kind   TEXT NOT NULL,
  text   TEXT NOT NULL,
  tags   TEXT NOT NULL DEFAULT '',
  trust  INTEGER NOT NULL DEFAULT 1,   -- 0 файл, 1 агент, 2 человек
  source TEXT NOT NULL DEFAULT '',
  sha    TEXT NOT NULL,
  UNIQUE(bank, sha)
);
CREATE INDEX IF NOT EXISTS facts_bank_ts ON facts(bank, ts DESC);

CREATE VIRTUAL TABLE IF NOT EXISTS facts_fts USING fts5(
  text, content='facts', content_rowid='id', tokenize="unicode61 remove_diacritics 2"
);
CREATE TRIGGER IF NOT EXISTS facts_ai AFTER INSERT ON facts BEGIN
  INSERT INTO facts_fts(rowid, text) VALUES (new.id, new.text);
END;
CREATE TRIGGER IF NOT EXISTS facts_ad AFTER DELETE ON facts BEGIN
  INSERT INTO facts_fts(facts_fts, rowid, text) VALUES ('delete', old.id, old.text);
END;

CREATE TABLE IF NOT EXISTS entities (
  id   INTEGER PRIMARY KEY,
  bank TEXT NOT NULL,
  type TEXT NOT NULL,
  name TEXT NOT NULL,
  sha  TEXT,
  meta TEXT,
  UNIQUE(bank, type, name)
);
CREATE TABLE IF NOT EXISTS edges (
  id       INTEGER PRIMARY KEY,
  bank     TEXT NOT NULL,
  src      INTEGER NOT NULL,
  dst      INTEGER NOT NULL,
  rel      TEXT NOT NULL,
  weight   REAL NOT NULL DEFAULT 1,
  evidence TEXT,
  origin   TEXT NOT NULL DEFAULT 'ai' CHECK (origin IN ('user', 'ai')),
  UNIQUE(bank, src, dst, rel)
);

CREATE TABLE IF NOT EXISTS observations (
  id         INTEGER PRIMARY KEY,
  bank       TEXT NOT NULL,
  text       TEXT NOT NULL,
  support    INTEGER NOT NULL,
  signature  TEXT NOT NULL,
  updated    TEXT NOT NULL,
  UNIQUE(bank, signature)
);
CREATE TABLE IF NOT EXISTS observation_facts (
  observation_id INTEGER NOT NULL,
  fact_id        INTEGER NOT NULL,
  PRIMARY KEY (observation_id, fact_id)
);

CREATE TABLE IF NOT EXISTS pages (
  id       INTEGER PRIMARY KEY,
  bank     TEXT NOT NULL,
  slug     TEXT NOT NULL,
  question TEXT NOT NULL DEFAULT '',
  answer   TEXT NOT NULL,
  sources  TEXT NOT NULL DEFAULT '',
  updated  TEXT NOT NULL,
  UNIQUE(bank, slug)
);

CREATE TABLE IF NOT EXISTS anchors (
  bank           TEXT PRIMARY KEY,
  goal           TEXT NOT NULL DEFAULT '',
  done           TEXT NOT NULL DEFAULT '',
  next_step      TEXT NOT NULL DEFAULT '',
  open_questions TEXT NOT NULL DEFAULT '',
  updated        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`;

export function openDb(filePath) {
  if (filePath !== ':memory:') fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const db = new DatabaseSync(filePath);
  db.exec(SCHEMA);
  const version = db.prepare("SELECT value FROM meta WHERE key='schema'").get();
  if (!version) db.prepare("INSERT INTO meta(key, value) VALUES('schema', ?)").run(String(SCHEMA_VERSION));
  return db;
}

const sha256 = (text) => crypto.createHash('sha256').update(text).digest('hex');
const nowIso = () => new Date().toISOString();
const clamp = (text, max) => (text.length <= max ? text : `${text.slice(0, max - 1)}…`);

// --- токенизация для консолидатора и переранжирования --------------------
const STOP = new Set(('и в во на не что это как для при или но а то же бы по от до из ' +
  'the and for with from that this are was were not you your все его она они так ' +
  'если чем без под над при уже ещё еще быть есть был была было').split(' '));

export function tokens(text) {
  const out = new Set();
  for (const raw of String(text ?? '').toLowerCase().split(/[^\p{L}\p{N}_]+/u)) {
    if (STOP.has(raw)) continue;
    // Латиница — от 2 символов (PE, UPX, PDB, TLS, MD5), остальное — от 3.
    const latin = /^[a-z0-9_]+$/.test(raw);
    if (raw.length < (latin ? 2 : 3)) continue;
    out.add(raw);
  }
  return out;
}

const jaccard = (a, b) => {
  if (!a.size || !b.size) return 0;
  let inter = 0;
  for (const value of a) if (b.has(value)) inter += 1;
  return inter / (a.size + b.size - inter);
};

// FTS5: термин экранируем и ставим префикс — «малвар» найдёт «малварь».
function ftsQuery(query) {
  const terms = [...tokens(query)].map((t) => `${t.replace(/"/g, '""')}*`);
  return terms.length ? terms.join(' OR ') : null;
}

// --- факты ---------------------------------------------------------------
export function rememberFact(db, { bank = 'default', kind = 'note', text, tags = '', trust = 1, source = '' }) {
  const clean = redact(String(text ?? '')).output;
  const body = clamp(clean.trim(), 4000);
  if (!body) return { ok: false, error: 'пустой текст' };
  const trustLevel = Math.max(0, Math.min(2, Number(trust) || 1));
  const safeKind = clamp(String(kind ?? 'note').trim(), 40) || 'note';
  const safeSource = clamp(String(source ?? '').trim(), 300);
  const sha = sha256(body.toLowerCase());
  const exists = db.prepare('SELECT id FROM facts WHERE bank = ? AND sha = ?').get(bank, sha);
  if (exists) return { ok: true, id: exists.id, duplicate: true };
  const info = db.prepare('INSERT INTO facts(bank, ts, kind, text, tags, trust, source, sha) VALUES (?,?,?,?,?,?,?,?)')
    .run(bank, nowIso(), safeKind, body, clamp(tags, 200), trustLevel, safeSource, sha);
  return { ok: true, id: Number(info.lastInsertRowid), duplicate: false, bytes: Buffer.byteLength(body) };
}

// --- поиск ---------------------------------------------------------------
// RRF по одному каналу (bm25) плюс покрытие терминов: без эмбеддингов, но
// объяснимо и детерминированно. Порог и константа 60 — из стандартного RRF.
export function recallFacts(db, { query, bank = null, limit = 8, minScore = 0 }) {
  const fts = ftsQuery(query);
  const queryTokens = tokens(query);
  const rows = [];
  if (fts) {
    try {
      rows.push(...db.prepare(`
        SELECT f.id, f.bank, f.ts, f.kind, f.text, f.tags, f.trust, f.source, bm25(facts_fts) AS rank
        FROM facts_fts JOIN facts f ON f.id = facts_fts.rowid
        WHERE facts_fts MATCH ? ${bank ? 'AND f.bank = ?' : ''}
        ORDER BY rank LIMIT 200
      `).all(...(bank ? [fts, bank] : [fts])));
    } catch { /* битый запрос — ниже сработает LIKE */ }
  }
  if (rows.length === 0 && queryTokens.size) {
    const like = db.prepare(`
      SELECT f.id, f.bank, f.ts, f.kind, f.text, f.tags, f.trust, f.source, 0 AS rank
      FROM facts f WHERE 1=1 ${bank ? 'AND f.bank = ?' : ''}
        AND (${[...queryTokens].map(() => 'f.text LIKE ?').join(' OR ')})
      ORDER BY f.ts DESC LIMIT 200
    `);
    const args = bank ? [bank] : [];
    for (const token of queryTokens) args.push(`%${token}%`);
    try { rows.push(...like.all(...args)); } catch { /* ничего */ }
  }
  const seen = new Set();
  const scored = [];
  rows.forEach((row, index) => {
    if (seen.has(row.id)) return;
    seen.add(row.id);
    const coverage = queryTokens.size
      ? [...queryTokens].filter((t) => row.text.toLowerCase().includes(t)).length / queryTokens.size
      : 0;
    const freshness = (Date.now() - Date.parse(row.ts)) < 7 * 864e5 ? 0.05 : 0;
    const score = 1 / (60 + index + 1) + 0.6 * coverage + 0.05 * (row.trust >= 1 ? 1 : 0) + freshness;
    scored.push({ ...row, score: Math.round(score * 1e4) / 1e4, coverage: Math.round(coverage * 100) / 100 });
  });
  scored.sort((a, b) => b.score - a.score);
  return scored.filter((row) => row.score >= minScore).slice(0, limit);
}

export function renderFact(row) {
  // Файловые факты отдаём обёрнутыми: модель должна видеть, что это данные.
  // Если текст уже содержит маркеры (составлен в analyze) — не оборачиваем второй раз.
  const needsWrap = row.trust === 0 && !String(row.text).includes('<untrusted');
  const body = needsWrap ? untrusted(row.text, 'memory', 1200) : row.text;
  return `#${row.id} [${row.kind}${row.trust === 0 ? '/файл' : row.trust === 2 ? '/человек' : ''}] ${body}`;
}

export function buildContext(db, { query, bank = null, budgetBytes = 3000 }) {
  const budget = Math.max(500, Math.min(32000, Number(budgetBytes) || 3000));
  const rows = recallFacts(db, { query, bank, limit: 40 });
  const lines = [];
  let used = 0;
  for (const row of rows) {
    const line = renderFact(row);
    const size = Buffer.byteLength(`${line}\n`, 'utf8');
    if (used + size > budget) break;
    used += size;
    lines.push(line);
  }
  return { ok: true, query, count: lines.length, bytes: used, budget, context: lines.join('\n') };
}

// --- граф ----------------------------------------------------------------
// origin='user' допустим только из UI: сервер вызывает с allowUserOrigin=true,
// MCP-агент — никогда. Связь, поставленная человеком, агент изменить не может.
export function graphAdd(db, { bank = 'default', nodes = [], edges = [], origin = 'ai', allowUserOrigin = false }) {
  const forced = origin === 'user' && allowUserOrigin ? 'user' : 'ai';
  const originIgnored = origin === 'user' && !allowUserOrigin;
  const upsert = db.prepare(`
    INSERT INTO entities(bank, type, name, sha, meta) VALUES (?,?,?,?,?)
    ON CONFLICT(bank, type, name) DO UPDATE SET sha = COALESCE(excluded.sha, entities.sha),
      meta = COALESCE(excluded.meta, entities.meta)
  `);
  const find = db.prepare('SELECT id FROM entities WHERE bank = ? AND type = ? AND name = ?');
  const findAny = db.prepare('SELECT id FROM entities WHERE bank = ? AND name = ? LIMIT 1');
  const insertEdgeAi = db.prepare(`
    INSERT INTO edges(bank, src, dst, rel, weight, evidence, origin) VALUES (?,?,?,?,?,?,'ai')
    ON CONFLICT(bank, src, dst, rel) DO UPDATE SET weight = excluded.weight,
      evidence = COALESCE(excluded.evidence, edges.evidence)
    WHERE edges.origin <> 'user'
  `);
  // Человек (только из UI) может взять связь себе и изменить её.
  const insertEdgeUser = db.prepare(`
    INSERT INTO edges(bank, src, dst, rel, weight, evidence, origin) VALUES (?,?,?,?,?,?,'user')
    ON CONFLICT(bank, src, dst, rel) DO UPDATE SET weight = excluded.weight,
      evidence = COALESCE(excluded.evidence, edges.evidence), origin = 'user'
  `);
  const insertEdge = forced === 'user' ? insertEdgeUser : insertEdgeAi;
  const edgeByKey = () => db.prepare('SELECT id, origin, weight, evidence FROM edges WHERE bank=? AND src=? AND dst=? AND rel=?');

  let addedNodes = 0;
  const ids = new Map();
  for (const node of nodes.slice(0, 500)) {
    const name = clamp(String(node?.name ?? '').trim(), 200);
    if (!name) continue;
    const type = String(node?.type ?? 'node').trim() || 'node';
    upsert.run(bank, type, name, node?.sha ? String(node.sha) : null, node?.meta ? clamp(String(node.meta), 2000) : null);
    addedNodes += 1;
    const row = find.get(bank, type, name);
    if (row) ids.set(`${type}\u0000${name}`, row.id);
  }
  const resolve = (name, type) => {
    if (!name) return null;
    if (type) {
      const typed = ids.get(`${type}\u0000${name}`) ?? find.get(bank, type, name)?.id;
      if (typed) return typed;
    }
    return ids.get(`node\u0000${name}`) ?? findAny.get(bank, name)?.id ?? null;
  };

  let applied = 0;
  const skipped = [];
  for (const edge of edges.slice(0, 2000)) {
    const srcName = clamp(String(edge?.src ?? '').trim(), 200);
    const dstName = clamp(String(edge?.dst ?? '').trim(), 200);
    const src = resolve(srcName, edge?.srcType);
    const dst = resolve(dstName, edge?.dstType);
    if (!src || !dst) { skipped.push(`${srcName}->${dstName}: узел не найден`); continue; }
    const rel = String(edge?.rel ?? 'related');
    const weight = Number(edge?.weight) || 1;
    const evidence = edge?.evidence ? clamp(String(edge.evidence), 500) : null;
    const before = edgeByKey().get(bank, src, dst, rel);
    if (before && before.origin === 'user' && forced !== 'user') {
      skipped.push(`${srcName}->${dstName}: связь поставлена человеком`);
      continue;
    }
    insertEdge.run(bank, src, dst, rel, weight, evidence);
    if (before) {
      // changes() считает конфликтный UPDATE изменением даже при равных значениях,
      // поэтому сравниваем состояние до и после — иначе счётчик лжёт.
      const after = edgeByKey().get(bank, src, dst, rel);
      const weightChanged = after.weight !== before.weight || after.origin !== before.origin;
      const evidenceChanged = evidence !== null && after.evidence !== before.evidence;
      if (weightChanged || evidenceChanged) applied += 1;
      else skipped.push(`${srcName}->${dstName}: без изменений`);
    } else {
      applied += 1;
    }
  }
  return {
    ok: true, bank, nodes: addedNodes, edges_applied: applied,
    edges_skipped: skipped.length, skipped: skipped.slice(0, 10),
    note: originIgnored ? 'origin от агента проигнорирован' : undefined,
  };
}

export function graphQuery(db, { bank = 'default', node, direction = 'both', rel = null, limit = 50 }) {
  const entity = db.prepare('SELECT id, type, name, sha FROM entities WHERE bank = ? AND name = ? LIMIT 1')
    .get(bank, String(node));
  if (!entity) return { ok: false, error: `узел не найден: ${node}` };
  const cap = Math.max(1, Math.min(200, Number(limit) || 50));
  const rows = [];
  if (direction !== 'in') {
    rows.push(...db.prepare(`
      SELECT e.rel, e.weight, e.origin, t.type, t.name, 'out' AS dir
      FROM edges e JOIN entities t ON t.id = e.dst
      WHERE e.bank = ? AND e.src = ? ${rel ? 'AND e.rel = ?' : ''} LIMIT ?
    `).all(...(rel ? [bank, entity.id, rel, cap] : [bank, entity.id, cap])));
  }
  if (direction !== 'out') {
    rows.push(...db.prepare(`
      SELECT e.rel, e.weight, e.origin, t.type, t.name, 'in' AS dir
      FROM edges e JOIN entities t ON t.id = e.src
      WHERE e.bank = ? AND e.dst = ? ${rel ? 'AND e.rel = ?' : ''} LIMIT ?
    `).all(...(rel ? [bank, entity.id, rel, cap] : [bank, entity.id, cap])));
  }
  return { ok: true, node: entity, count: rows.length, neighbors: rows.slice(0, cap) };
}

export function graphStats(db, { bank = 'default' }) {
  const nodes = db.prepare('SELECT count(*) AS c FROM entities WHERE bank = ?').get(bank).c;
  const edges = db.prepare('SELECT count(*) AS c FROM edges WHERE bank = ?').get(bank).c;
  const top = db.prepare(`
    SELECT t.name, count(*) AS degree FROM (
      SELECT src AS id FROM edges WHERE bank = ? UNION ALL SELECT dst AS id FROM edges WHERE bank = ?
    ) x JOIN entities t ON t.id = x.id GROUP BY x.id ORDER BY degree DESC LIMIT 5
  `).all(bank, bank);
  return { ok: true, bank, nodes, edges, top };
}

// --- наблюдения (консолидация без LLM) -----------------------------------
export function consolidate(db, { bank = null, threshold = 0.55, dryRun = false }) {
  const banks = bank ? [bank] : db.prepare('SELECT DISTINCT bank FROM facts').all().map((r) => r.bank);
  const report = [];
  for (const name of banks) {
    // Только факты, ещё не покрытые наблюдениями, и не больше 2000 на банк:
    // консолидация O(n^2), большие банки обрабатываются порциями за прогоны.
    const facts = db.prepare(`
      SELECT f.id, f.text FROM facts f
      WHERE f.bank = ?
        AND NOT EXISTS (SELECT 1 FROM observation_facts o WHERE o.fact_id = f.id)
      ORDER BY f.id LIMIT 2000
    `).all(name);
    const sets = facts.map((f) => ({ ...f, set: tokens(f.text) }));
    const used = new Set();
    const clusters = [];
    for (let i = 0; i < sets.length; i += 1) {
      if (used.has(sets[i].id)) continue;
      const cluster = [sets[i]];
      used.add(sets[i].id);
      for (let j = i + 1; j < sets.length; j += 1) {
        if (used.has(sets[j].id)) continue;
        if (jaccard(sets[i].set, sets[j].set) >= threshold) { cluster.push(sets[j]); used.add(sets[j].id); }
      }
      if (cluster.length >= 2) clusters.push(cluster);
    }
    if (!dryRun) {
      for (const cluster of clusters) {
        const ids = cluster.map((c) => c.id).sort((a, b) => a - b);
        const signature = sha256(ids.join(','));
        const longest = cluster.reduce((a, b) => (a.text.length >= b.text.length ? a : b));
        const text = clamp(`Наблюдение (${cluster.length} подтверждений): ${longest.text}`, 2000);
        const existing = db.prepare('SELECT id FROM observations WHERE bank=? AND signature=?').get(name, signature);
        let obsId;
        if (existing) {
          obsId = existing.id;
          db.prepare('UPDATE observations SET support=?, text=?, updated=? WHERE id=?').run(cluster.length, text, nowIso(), obsId);
        } else {
          const info = db.prepare('INSERT INTO observations(bank, text, support, signature, updated) VALUES (?,?,?,?,?)')
            .run(name, text, cluster.length, signature, nowIso());
          obsId = Number(info.lastInsertRowid);
        }
        for (const id of ids) db.prepare('INSERT OR IGNORE INTO observation_facts(observation_id, fact_id) VALUES (?,?)').run(obsId, id);
      }
    }
    report.push({ bank: name, facts: facts.length, clusters: clusters.length, sizes: clusters.map((c) => c.length) });
  }
  return { ok: true, threshold, dry_run: Boolean(dryRun), banks: report };
}

// --- страницы и якорь ----------------------------------------------------
export function pageSet(db, { bank = 'default', slug, question = '', answer, sources = '' }) {
  const clean = redact(String(answer ?? '')).output;
  if (!slug || !clean) return { ok: false, error: 'нужны slug и answer' };
  db.prepare(`
    INSERT INTO pages(bank, slug, question, answer, sources, updated) VALUES (?,?,?,?,?,?)
    ON CONFLICT(bank, slug) DO UPDATE SET question=excluded.question, answer=excluded.answer,
      sources=excluded.sources, updated=excluded.updated
  `).run(bank, String(slug), String(question), clamp(clean, 8000), String(sources), nowIso());
  return { ok: true, bank, slug, bytes: Buffer.byteLength(clean) };
}

export function pageGet(db, { bank = 'default', slug }) {
  const row = db.prepare('SELECT * FROM pages WHERE bank=? AND slug=?').get(bank, String(slug));
  return row ? { ok: true, page: row } : { ok: false, error: `страница не найдена: ${slug}` };
}

export function anchorSet(db, { bank = 'default', goal = '', done = '', next_step = '', open_questions = '' }) {
  db.prepare(`
    INSERT INTO anchors(bank, goal, done, next_step, open_questions, updated) VALUES (?,?,?,?,?,?)
    ON CONFLICT(bank) DO UPDATE SET goal=excluded.goal, done=excluded.done, next_step=excluded.next_step,
      open_questions=excluded.open_questions, updated=excluded.updated
  `).run(bank, goal, done, next_step, open_questions, nowIso());
  return { ok: true, bank };
}

export function anchorGet(db, { bank = 'default' }) {
  const row = db.prepare('SELECT * FROM anchors WHERE bank=?').get(bank);
  return row ? { ok: true, anchor: row } : { ok: false, error: 'якорь пуст' };
}

export function stats(db) {
  const one = (sql) => db.prepare(sql).get();
  return {
    ok: true,
    schema: Number(db.prepare("SELECT value FROM meta WHERE key='schema'").get()?.value ?? 0),
    facts: one('SELECT count(*) c FROM facts').c,
    banks: db.prepare('SELECT bank, count(*) c FROM facts GROUP BY bank ORDER BY c DESC').all(),
    entities: one('SELECT count(*) c FROM entities').c,
    edges: one('SELECT count(*) c FROM edges').c,
    edges_user: one("SELECT count(*) c FROM edges WHERE origin='user'").c,
    observations: one('SELECT count(*) c FROM observations').c,
    pages: one('SELECT count(*) c FROM pages').c,
    facts_fts: one('SELECT count(*) c FROM facts_fts').c,
  };
}
