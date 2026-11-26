// Фабрика LSRE: единственный источник логики очереди задач.
// Импортируют: MCP-сервер LSRE (инструмент lsre_factory), веб-UI (lsre-ui.mjs).
// Схема: tasks(id,title,note,kind,priority,status,tries,result,evidence,dup_of,created,updated,stage)
//        events(id,task,at,action,detail)
// Дедуп двухступенчатый: Жаккар по словам (дёшево) → косинус эмбеддингов (если переданы).
import { DatabaseSync } from 'node:sqlite';

export const STAGES = ['triage', 'plan', 'apply', 'verify', 'done'];
const NEXT = { triage: 'plan', plan: 'apply', apply: 'verify', verify: 'done' };

export const DUP_TEXT = 0.55;      // порог Жаккара для явного текстового совпадения
export const DUP_SEMANTIC = 0.95;  // автосклейка по косинусу — только почти-тождество
export const SIMILAR = 0.86;       // «похоже, посмотрите» — совет, без склейки
const PREFILTER = 0.05;            // ниже этого Жаккара косинус не считаем (экономия на 200+ задачах)

const nowIso = () => new Date().toISOString();

export function words(text) {
  return new Set(String(text || '').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').split(' ').filter((w) => w.length > 2));
}

export function jaccard(a, b) {
  const A = words(a), B = words(b);
  if (!A.size || !B.size) return 0;
  let inter = 0;
  for (const w of A) if (B.has(w)) inter += 1;
  return inter / (A.size + B.size - inter);
}

// Лексикон расширен: слова, которые люди пишут вместо «баг».
const BUG = /(баг|bug|падает|падени|crash|ошиб|error|fix|почин|исправ|сбой|не\s*работает|зависа|утечк|виснет|сломал)/;
const KIND_RULES = [
  ['bug', BUG],
  ['test', /(тест|test|провер|проверк)/],
  ['docs', /(док|readme|\bdocs?\b|описан|инструкц)/],
  ['refactor', /(рефактор|refactor|упростить|чист[каи]|переписат)/],
  ['feature', /(фич|feature|добав|сделать|поддержк)/],
];
const PRIO_RULES = [
  ['P1', /(блокер|blocker|критич|critical|срочн|urgent|p0|p1|не\s*запуска)/],
  ['P2', /(важн|important|p2)/],
  ['P4', /(мелоч|космет|p4)/],
];

// Энтропия Шеннона текста: воспроизводимая метрика «размытости» задачи.
// Решения не принимает — только информационный сигнал рядом с confidence.
export function shannonEntropy(text) {
  if (!text || !text.trim()) return 0;
  const freq = new Map();
  for (const ch of text) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  const n = text.length;
  let h = 0;
  for (const c of freq.values()) {
    const p = c / n;
    if (p > 0) h -= p * Math.log2(p);
  }
  return Number(h.toFixed(3));
}

export function classify(title, note) {
  const t = `${title} ${note}`.toLowerCase();
  let kind = 'task';
  let kindHit = false;
  for (const [name, re] of KIND_RULES) if (re.test(t)) { kind = name; kindHit = true; break; }
  let priority = 'P3';
  let prioHit = false;
  for (const [name, re] of PRIO_RULES) if (re.test(t)) { priority = name; prioHit = true; break; }
  // confidence: оба признака распознаны — выше. Пороги не снижаются, только метрика.
  const confidence = Number(((kindHit ? 0.5 : 0) + (prioHit ? 0.5 : 0)).toFixed(2));
  return { kind, priority, entropy: shannonEntropy(t), confidence };
}

export function openFactory(filePath) {
  const db = new DatabaseSync(filePath);
  db.exec('PRAGMA busy_timeout = 5000;');
  db.exec(`
    CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      note TEXT NOT NULL DEFAULT '',
      kind TEXT NOT NULL DEFAULT 'task',
      priority TEXT NOT NULL DEFAULT 'P3',
      status TEXT NOT NULL DEFAULT 'queued',
      tries INTEGER NOT NULL DEFAULT 0,
      result TEXT,
      evidence TEXT,
      dup_of INTEGER,
      created TEXT NOT NULL DEFAULT (datetime('now')),
      updated TEXT NOT NULL DEFAULT (datetime('now')),
      stage TEXT NOT NULL DEFAULT 'triage'
    );
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      task INTEGER,
      at TEXT NOT NULL DEFAULT (datetime('now')),
      action TEXT NOT NULL,
      detail TEXT
    );
    CREATE INDEX IF NOT EXISTS tasks_status ON tasks(status);
  `);
  if (!db.prepare('PRAGMA table_info(tasks)').all().some((c) => c.name === 'stage')) {
    db.exec("ALTER TABLE tasks ADD COLUMN stage TEXT NOT NULL DEFAULT 'triage'");
  }
  return db;
}

const event = (db, task, action, detail) => db.prepare('INSERT INTO events(task,action,detail) VALUES(?,?,?)')
  .run(task ?? null, action, String(detail ?? ''));

export function describe(db, { status = null, stage = null } = {}) {
  const where = [];
  const args = [];
  if (status) { where.push('status = ?'); args.push(status); }
  if (stage) { where.push("COALESCE(stage,'triage') = ?"); args.push(stage); }
  const tasks = db.prepare(`SELECT * FROM tasks ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
    ORDER BY CASE status WHEN 'doing' THEN 0 WHEN 'queued' THEN 1 WHEN 'failed' THEN 2 ELSE 3 END,
             CASE priority WHEN 'P0' THEN 0 WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 ELSE 4 END,
             id`).all(...args);
  const byStatus = db.prepare('SELECT status, count(*) c FROM tasks GROUP BY status').all();
  const byStage = db.prepare("SELECT COALESCE(stage,'triage') stage, count(*) c FROM tasks GROUP BY 1").all();
  const events = db.prepare('SELECT id, task, at, action, detail FROM events ORDER BY id DESC LIMIT 40').all();
  return { ok: true, stages: STAGES, total: byStatus.reduce((s, r) => s + r.c, 0), byStatus, byStage, tasks, events };
}

const find = (db, id) => (id ? db.prepare('SELECT * FROM tasks WHERE id = ?').get(id) : null);

// Оценка похожести двух текстов: Жаккар всегда, косинус — если дан эмбеддер.
async function similarity(a, b, ctx) {
  const j = jaccard(a, b);
  if (!ctx.embed || j < PREFILTER) return { j, cos: null, dup: j >= DUP_TEXT, how: 'text' };
  let cos = null;
  try {
    const [va, vb] = await Promise.all([ctx.embed(a), ctx.embed(b)]);
    cos = ctx.cosine(va, vb);
  } catch { return { j, cos: null, dup: j >= DUP_TEXT, how: 'text' }; }
  return { j, cos, dup: cos >= (ctx.threshold ?? DUP_SEMANTIC), how: 'semantic' };
}

/** action(db, body, ctx) — ctx: { embed?, cosine?, threshold? }. Без ctx работает на Жаккаре. */
export async function action(db, body = {}, ctx = {}) {
  const op = String(body.op || '');
  const id = Number(body.id) || 0;
  const row = find(db, id);
  switch (op) {
    case 'enqueue': {
      const title = String(body.title || '').trim();
      if (!title) return { ok: false, error: 'нужно название' };
      const note = String(body.note || '');
      const cls = classify(title, note);
      const kind = body.kind || cls.kind;
      const priority = body.priority || cls.priority;
      const text = `${title} ${note}`;
      const pool = db.prepare("SELECT id,title,note FROM tasks WHERE status IN ('queued','doing') ORDER BY id DESC LIMIT 200").all()
        .map((r) => ({ id: r.id, j: Number(jaccard(text, `${r.title} ${r.note}`).toFixed(3)) }))
        .filter((r) => r.j >= PREFILTER)
        .sort((a, b) => b.j - a.j)
        .slice(0, Number(body.dup_limit) || 5);
      const duplicates = [];
      const similar = [];
      for (const cand of pool) {
        const src = db.prepare('SELECT title,note FROM tasks WHERE id = ?').get(cand.id);
        const sim = await similarity(text, `${src.title} ${src.note}`, ctx);
        const score = Number((sim.cos ?? sim.j).toFixed(3));
        if (sim.j >= DUP_TEXT || (sim.cos ?? 0) >= (ctx.threshold ?? DUP_SEMANTIC)) duplicates.push({ id: cand.id, score, how: sim.how, jaccard: cand.j });
        else if ((sim.cos ?? 0) >= SIMILAR) similar.push({ id: cand.id, score, jaccard: cand.j });
      }
      const info = db.prepare('INSERT INTO tasks(title,note,kind,priority,dup_of,stage) VALUES(?,?,?,?,?,?)')
        .run(title, note, kind, priority, duplicates[0]?.id ?? null, 'triage');
      const newId = Number(info.lastInsertRowid);
      event(db, newId, 'enqueue', `${kind}/${priority}${duplicates[0] ? ` dup#${duplicates[0].id}` : ''}`);
      return { ok: true, id: newId, kind, priority, duplicates, similar };
    }
    case 'claim': {
      // Конкретная задача: claim по id (исполнитель берёт именно её).
      if (body.id) {
        const one = find(db, Number(body.id));
        if (!one) return { ok: false, error: 'задача не найдена' };
        if (one.status === 'done' || one.status === 'failed') return { ok: false, error: `задача уже ${one.status}` };
        db.prepare("UPDATE tasks SET status='doing', tries=tries+1, updated=? WHERE id=?").run(nowIso(), one.id);
        event(db, one.id, 'claim', `try ${one.tries + 1}`);
        return { ok: true, claimed: [{ ...one, status: 'doing', tries: one.tries + 1 }], count: 1 };
      }
      const limit = Math.max(1, Math.min(20, Number(body.limit) || 1));
      const rows = db.prepare(`SELECT * FROM tasks WHERE status='queued'
        ORDER BY CASE priority WHEN 'P0' THEN 0 WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 ELSE 4 END, id LIMIT ?`).all(limit);
      const claimed = [];
      for (const r of rows) {
        db.prepare("UPDATE tasks SET status='doing', tries=tries+1, updated=? WHERE id=?").run(nowIso(), r.id);
        event(db, r.id, 'claim', `try ${r.tries + 1}`);
        claimed.push({ ...r, status: 'doing', tries: r.tries + 1 });
      }
      return { ok: true, claimed, count: claimed.length };
    }
    case 'done': {
      if (!row) return { ok: false, error: 'задача не найдена' };
      const evidence = String(body.evidence || '');
      if ((row.stage || 'triage') === 'verify' && !evidence.trim()) {
        return { ok: false, error: 'гейт Verify: нужны доказательства (evidence)' };
      }
      db.prepare("UPDATE tasks SET status='done', stage='done', result=?, evidence=?, updated=? WHERE id=?")
        .run(String(body.result || ''), evidence, nowIso(), id);
      event(db, id, 'done', String(body.result || '').slice(0, 200));
      return { ok: true, id, status: 'done' };
    }
    case 'fail': {
      if (!row) return { ok: false, error: 'задача не найдена' };
      const status = row.tries >= 3 ? 'failed' : 'queued';
      db.prepare('UPDATE tasks SET status=?, result=?, updated=? WHERE id=?').run(status, String(body.error || ''), nowIso(), id);
      event(db, id, 'fail', `${status}: ${String(body.error || '').slice(0, 160)}`);
      return { ok: true, id, status, tries: row.tries };
    }
    case 'triage': {
      if (!row) return { ok: false, error: 'задача не найдена' };
      const cls = classify(row.title, row.note);
      db.prepare('UPDATE tasks SET kind=?, priority=?, updated=? WHERE id=?').run(cls.kind, cls.priority, nowIso(), id);
      event(db, id, 'triage', `${cls.kind}/${cls.priority}`);
      return { ok: true, id, ...cls };
    }
    case 'advance': {
      if (!row) return { ok: false, error: 'задача не найдена' };
      const cur = STAGES.indexOf(row.stage || 'triage');
      if (cur < 0) return { ok: false, error: `неизвестная стадия: ${row.stage}` };
      if (cur >= STAGES.length - 1) return { ok: false, error: 'задача уже на финальной стадии' };
      const next = NEXT[row.stage || 'triage'];
      if (next === 'done') db.prepare("UPDATE tasks SET stage='done', status='done', updated=? WHERE id=?").run(nowIso(), id);
      else db.prepare('UPDATE tasks SET stage=?, updated=? WHERE id=?').run(next, nowIso(), id);
      event(db, id, 'advance', `${row.stage || 'triage'} → ${next}`);
      return { ok: true, id, stage: next };
    }
    case 'dedupe': {
      const threshold = Number(body.threshold) || (ctx.threshold ?? DUP_SEMANTIC);
      const rows = db.prepare('SELECT id,title,note FROM tasks ORDER BY id').all();
      // Векторы считаются один раз на задачу, а не на каждую пару.
      const vecs = new Map();
      const vecOf = async (r) => {
        if (!ctx.embed) return null;
        if (!vecs.has(r.id)) vecs.set(r.id, await ctx.embed(`${r.title} ${r.note}`).catch(() => null));
        return vecs.get(r.id);
      };
      const groups = [];
      const advisory = [];
      const used = new Set();
      for (let i = 0; i < rows.length; i += 1) {
        if (used.has(rows[i].id)) continue;
        const group = [rows[i].id];
        const left = rows.slice(i + 1).filter((r) => !used.has(r.id))
          .map((r) => ({ r, j: jaccard(`${rows[i].title} ${rows[i].note}`, `${r.title} ${r.note}`) }))
          .filter((x) => x.j >= PREFILTER)
          .sort((a, b) => b.j - a.j)
          .slice(0, 6);
        for (const cand of left) {
          const j = cand.j;
          let cos = null;
          if (ctx.cosine) {
            const [va, vb] = [await vecOf(rows[i]), await vecOf(cand.r)];
            if (va && vb) cos = ctx.cosine(va, vb);
          }
          const auto = j >= DUP_TEXT || (cos ?? 0) >= threshold;
          if (auto) { group.push(cand.r.id); used.add(cand.r.id); }
          else if ((cos ?? 0) >= SIMILAR) advisory.push({ a: rows[i].id, b: cand.r.id, cos: Number(cos.toFixed(3)), jaccard: j });
        }
        if (group.length > 1) { used.add(rows[i].id); groups.push(group); }
      }
      return { ok: true, threshold, groups, count: groups.length, advisory };
    }
    default:
      return { ok: false, error: `неизвестное действие: ${op || '(пусто)'}` };
  }
}
