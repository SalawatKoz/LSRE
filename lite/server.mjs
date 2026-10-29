// LSRE-lite: MCP-сервер (stdio JSON-RPC 2.0) без внешних зависимостей.
// Триаж + память (SQLite FTS5) + граф + страницы. REA не требуется.
// Принципы: никаких голых catch, ошибки всегда в ответе; origin человека
// от агента не принимается; все свободные текстовые поля через redact.
import { createInterface } from 'node:readline';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { triage } from './triage.mjs';
import * as mem from './memory.mjs';

const VERSION = '1.0.0';
const DB_PATH = process.env.LSRE_LITE_DB
  || (process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, 'lsre-lite', 'memory.db') : path.join(os.tmpdir(), 'lsre-lite', 'memory.db'));
const argDb = process.argv.indexOf('--db');
const dbPath = argDb !== -1 && process.argv[argDb + 1] ? process.argv[argDb + 1] : DB_PATH;

const db = mem.openDb(dbPath);
const clampInt = (value, min, max, fallback) => Math.max(min, Math.min(max, Number(value) || fallback));
const u = (value, source = 'file', max = 120) => mem.untrusted(value, source, max);

const TOOLS = [
  { name: 'lsre_analyze', description: 'Один проход: триаж по сигнатуре + факт в память + связи графа. Факт-шит ≤2 КБ. Не пишет \"pe\" без сигнатуры MZ+PE.', inputSchema: { type: 'object', properties: { path: { type: 'string', description: 'Файл для анализа' }, bank: { type: 'string', description: 'Банк памяти (default)' }, hash: { type: 'boolean', description: 'Считать sha256 (файлы ≤64 МБ)' } }, required: ['path'] } },
  { name: 'lsre_triage', description: 'Триаж без записи в память: PE (импорты с именами функций, экспорты, PDB, Rich, подпись, TLS-callbacks), ELF, Mach-O, ZIP/APK/JAR, DEX, PDF, тексты и др.', inputSchema: { type: 'object', properties: { path: { type: 'string' }, hash: { type: 'boolean' } }, required: ['path'] } },
  { name: 'lsre_recall', description: 'Поиск фактов: FTS5 bm25 + покрытие терминов + RRF. Без эмбеддингов, детерминированно.', inputSchema: { type: 'object', properties: { query: { type: 'string' }, limit: { type: 'integer', description: '1–50, по умолчанию 8' }, bank: { type: 'string' } }, required: ['query'] } },
  { name: 'lsre_context', description: 'Контекст из памяти под бюджет БАЙТ (не символов): кириллица считается по UTF-8.', inputSchema: { type: 'object', properties: { query: { type: 'string' }, budget_bytes: { type: 'integer', description: '500–8000, по умолчанию 3000' }, bank: { type: 'string' } }, required: ['query'] } },
  { name: 'lsre_remember', description: 'Сохранить факт/решение/путь. Секреты вырезаются. Доверие агента ≤1 (2 — только человек).', inputSchema: { type: 'object', properties: { text: { type: 'string' }, kind: { type: 'string', description: 'fact | decision | path | hash | todo' }, tags: { type: 'string' }, bank: { type: 'string' } }, required: ['text'] } },
  { name: 'lsre_observe', description: 'Консолидация Hindsight-lite: кластеры по Жаккару токенов → наблюдения с числом подтверждений. Без LLM.', inputSchema: { type: 'object', properties: { bank: { type: 'string' }, threshold: { type: 'number', description: '0–1, по умолчанию 0.55' }, dry_run: { type: 'boolean' } } } },
  { name: 'lsre_page_get', description: 'Прочитать страницу знаний по slug.', inputSchema: { type: 'object', properties: { slug: { type: 'string' }, bank: { type: 'string' } }, required: ['slug'] } },
  { name: 'lsre_page_set', description: 'Записать страницу знаний (соглашения, архитектура). Секреты вырезаются.', inputSchema: { type: 'object', properties: { slug: { type: 'string' }, question: { type: 'string' }, answer: { type: 'string' }, sources: { type: 'string' }, bank: { type: 'string' } }, required: ['slug', 'answer'] } },
  { name: 'lsre_anchor', description: 'Якорь сессии: цель, что сделано, следующий шаг, открытые вопросы.', inputSchema: { type: 'object', properties: { goal: { type: 'string' }, done: { type: 'string' }, next_step: { type: 'string' }, open_questions: { type: 'string' }, bank: { type: 'string' } } } },
  { name: 'lsre_resume', description: 'Прочитать якорь сессии.', inputSchema: { type: 'object', properties: { bank: { type: 'string' } } } },
  { name: 'lsre_graph_add', description: 'Добавить узлы и связи. Ответ возвращает число РЕАЛЬНО применённых связей и список пропущенных. origin от агента не принимается.', inputSchema: { type: 'object', properties: { nodes: { type: 'array', items: { type: 'object', properties: { name: { type: 'string' }, type: { type: 'string' }, sha: { type: 'string' }, meta: { type: 'string' } } } }, edges: { type: 'array', items: { type: 'object', properties: { src: { type: 'string' }, dst: { type: 'string' }, rel: { type: 'string' }, weight: { type: 'number' }, evidence: { type: 'string' } } } }, bank: { type: 'string' } } } },
  { name: 'lsre_graph_query', description: 'Соседи узла в графе.', inputSchema: { type: 'object', properties: { node: { type: 'string' }, direction: { type: 'string', description: 'out | in | both' }, rel: { type: 'string' }, limit: { type: 'integer' }, bank: { type: 'string' } }, required: ['node'] } },
  { name: 'lsre_graph_stats', description: 'Размер графа и топ узлов по связям.', inputSchema: { type: 'object', properties: { bank: { type: 'string' } } } },
  { name: 'lsre_stats', description: 'Сводка памяти: факты, банки, наблюдения, страницы, граф.', inputSchema: { type: 'object', properties: {} } },
  { name: 'lsre_doctor', description: 'Диагностика: путь БД, целостность SQLite, согласованность FTS.', inputSchema: { type: 'object', properties: {} } },
];

// Факт-шит ≤ 2 КБ: только числа и короткие выборки.
function compactSheet(sheet, budgetBytes = 2048) {
  const base = {
    file: sheet.file, size: sheet.size, type: sheet.type,
    arch: sheet.arch ?? null, bits: sheet.bits ?? null, subsystem: sheet.subsystem ?? null,
  };
  const parts = { ...base };
  if (sheet.type === 'pe') {
    parts.entry_section = sheet.entry_section;
    parts.sections = (sheet.sections ?? []).slice(0, 12).map((s) => `${s.name}:${s.ent}`);
    parts.imports = sheet.imports ? { count: sheet.imports.count, funcs: sheet.imports.funcs, dlls: sheet.imports.dlls.slice(0, 6) } : null;
    parts.exports = sheet.exports ? { count: sheet.exports.count, names: sheet.exports.names.slice(0, 6) } : null;
    parts.pdb = sheet.pdb;
    parts.signature = sheet.signature;
    parts.rich = sheet.rich ? sheet.rich.entries : null;
    parts.tls_callbacks = sheet.tls_callbacks;
    parts.overlay = sheet.overlay;
    parts.packer = sheet.packer;
    if (sheet.resources) parts.resources = {
      types: sheet.resources.types.slice(0, 10),
      version: sheet.resources.version,
      manifest: sheet.resources.manifest,
      icons: sheet.resources.icons,
    };
  } else {
    for (const key of ['names', 'entries', 'libraries', 'strings', 'classes', 'methods', 'width', 'height', 'javascript', 'open_action', 'launch', 'encoding', 'lines', 'note']) {
      if (sheet[key] !== undefined && sheet[key] !== null) parts[key] = sheet[key];
    }
  }
  parts.errors = sheet.errors ?? [];
  parts.limits = sheet.limits ?? [];
  let json = JSON.stringify(parts);
  if (Buffer.byteLength(json) <= budgetBytes) return parts;
  // Ужимаем последовательно, пока не влезем.
  const drop = ['imports', 'exports', 'sections', 'packer', 'rich', 'signature', 'limits'];
  for (const key of drop) {
    delete parts[key];
    json = JSON.stringify(parts);
    if (Buffer.byteLength(json) <= budgetBytes) break;
  }
  return parts;
}

function factText(sheet) {
  const file = u(sheet.file, 'file', 120);
  if (sheet.type === 'pe') {
    const sample = (sheet.imports?.dlls ?? []).slice(0, 5).map((name) => u(name, 'file', 48)).join(', ');
    const pdb = sheet.pdb ? `, PDB ${u(sheet.pdb, 'file', 120)}` : '';
    const sig = sheet.signature?.present ? `, подпись ${sheet.signature.size} б${sheet.signature.signer_cn ? ` (${sheet.signature.signer_cn})` : ''}` : '';
    const ver = sheet.resources?.version?.productname ? `, ${sheet.resources.version.productname}` : '';
    const tls = sheet.tls_callbacks ? `, TLS-callbacks ${sheet.tls_callbacks}` : '';
    const packer = sheet.packer?.name ? `, упаковщик: ${sheet.packer.name} (${sheet.packer.confidence})` : '';
    return `Файл ${file}: ${sheet.size} б, PE ${sheet.arch} ${sheet.bits}-bit (${sheet.subsystem}), EP ${sheet.entry_section ?? 'вне секций'}, `
      + `секций ${sheet.sections?.length ?? 0}, импорт ${sheet.imports?.count ?? 0} DLL / ${sheet.imports?.funcs ?? 0} функций (${sample}), `
      + `экспорт ${sheet.exports?.count ?? 0}${pdb}${sig}${ver}${tls}${packer}`;
  }
  return `Файл ${file}: ${sheet.size} б, тип ${sheet.type}${sheet.arch ? `, ${sheet.arch}` : ''}`;
}

const handlers = {
  lsre_analyze(args) {
    const file = String(args.path ?? '').trim().slice(0, 1000);
    if (!file) return { ok: false, error: 'нужен path' };
    if (!fs.existsSync(file)) return { ok: false, error: `файл не найден: ${file}` };
    if (!fs.statSync(file).isFile()) return { ok: false, error: `не файл: ${file}` };
    const bank = String(args.bank ?? 'default').trim().slice(0, 40) || 'default';
    const result = triage(file, { hash: Boolean(args.hash) });
    if (!result.ok) return result;
    const sheet = result.sheet;
    const text = factText(sheet);
    const memory = mem.rememberFact(db, { bank, kind: 'file', text, trust: 0, source: sheet.path, tags: `type:${sheet.type}` });
    const graph = mem.graphAdd(db, {
      bank,
      nodes: [{ name: sheet.file, type: 'binary' },
        ...(sheet.imports?.dlls ?? []).slice(0, 30).map((dll) => ({ name: dll, type: 'service' }))],
      edges: (sheet.imports?.dlls ?? []).slice(0, 30).map((dll) => ({ src: sheet.file, dst: dll, rel: 'depends_on' })),
    });
    return { ok: true, ms: result.ms, bank, memory, graph: { edges_applied: graph.edges_applied, edges_skipped: graph.edges_skipped }, fact_sheet: compactSheet(sheet) };
  },

  lsre_triage(args) {
    const file = String(args.path ?? '').trim().slice(0, 1000);
    if (!file) return { ok: false, error: 'нужен path' };
    if (!fs.existsSync(file)) return { ok: false, error: `файл не найден: ${file}` };
    if (!fs.statSync(file).isFile()) return { ok: false, error: `не файл: ${file}` };
    const result = triage(file, { hash: Boolean(args.hash) });
    if (!result.ok) return result;
    return { ok: true, ms: result.ms, sheet: compactSheet(result.sheet, 8192) };
  },

  lsre_recall(args) {
    const query = String(args.query ?? '').trim().slice(0, 500);
    if (!query) return { ok: false, error: 'пустой запрос' };
    const bank = args.bank ? String(args.bank).trim().slice(0, 40) : null;
    const rows = mem.recallFacts(db, { query, bank, limit: clampInt(args.limit, 1, 50, 8) });
    return { ok: true, query, found: rows.length, results: rows.map(mem.renderFact), scores: rows.map((r) => ({ id: r.id, score: r.score, coverage: r.coverage })) };
  },

  lsre_context(args) {
    const query = String(args.query ?? '').trim().slice(0, 500);
    if (!query) return { ok: false, error: 'пустой запрос' };
    const bank = args.bank ? String(args.bank).trim().slice(0, 40) : null;
    return mem.buildContext(db, { query, bank, budgetBytes: clampInt(args.budget_bytes, 500, 8000, 3000) });
  },

  lsre_remember(args) {
    const text = String(args.text ?? '').slice(0, 8000);
    const bank = String(args.bank ?? 'default').trim().slice(0, 40) || 'default';
    return mem.rememberFact(db, { bank, text, kind: String(args.kind ?? 'note'), tags: String(args.tags ?? ''), trust: 1, source: 'agent' });
  },

  lsre_observe(args) {
    const bank = args.bank ? String(args.bank).trim().slice(0, 40) : null;
    return mem.consolidate(db, { bank, threshold: clampInt(Number(args.threshold) * 100, 0, 100, 55) / 100, dryRun: Boolean(args.dry_run) });
  },

  lsre_page_get(args) {
    const bank = String(args.bank ?? 'default').trim().slice(0, 40) || 'default';
    return mem.pageGet(db, { bank, slug: String(args.slug ?? '').trim().slice(0, 120) });
  },

  lsre_page_set(args) {
    const bank = String(args.bank ?? 'default').trim().slice(0, 40) || 'default';
    return mem.pageSet(db, {
      bank, slug: String(args.slug ?? '').trim().slice(0, 120),
      question: String(args.question ?? '').slice(0, 500),
      answer: String(args.answer ?? '').slice(0, 16000),
      sources: String(args.sources ?? '').slice(0, 1000),
    });
  },

  lsre_anchor(args) {
    const bank = String(args.bank ?? 'default').trim().slice(0, 40) || 'default';
    return mem.anchorSet(db, {
      bank, goal: String(args.goal ?? '').slice(0, 1000), done: String(args.done ?? '').slice(0, 2000),
      next_step: String(args.next_step ?? '').slice(0, 1000), open_questions: String(args.open_questions ?? '').slice(0, 2000),
    });
  },

  lsre_resume(args) {
    const bank = String(args.bank ?? 'default').trim().slice(0, 40) || 'default';
    return mem.anchorGet(db, { bank });
  },

  lsre_graph_add(args) {
    const bank = String(args.bank ?? 'default').trim().slice(0, 40) || 'default';
    const nodes = Array.isArray(args.nodes) ? args.nodes.slice(0, 500) : [];
    const edges = Array.isArray(args.edges) ? args.edges.slice(0, 2000) : [];
    // origin в схему не входит и здесь не читается: человек — только через UI.
    return mem.graphAdd(db, { bank, nodes, edges, origin: 'ai' });
  },

  lsre_graph_query(args) {
    const bank = String(args.bank ?? 'default').trim().slice(0, 40) || 'default';
    return mem.graphQuery(db, {
      bank, node: String(args.node ?? '').trim().slice(0, 200),
      direction: String(args.direction ?? 'both'), rel: args.rel ? String(args.rel).trim().slice(0, 40) : null,
      limit: clampInt(args.limit, 1, 200, 50),
    });
  },

  lsre_graph_stats(args) {
    const bank = String(args.bank ?? 'default').trim().slice(0, 40) || 'default';
    return mem.graphStats(db, { bank });
  },

  lsre_stats() {
    return mem.stats(db);
  },

  lsre_doctor() {
    let integrity;
    try { integrity = db.prepare('PRAGMA integrity_check').all().map((r) => Object.values(r)[0]); } catch (error) { integrity = [`integrity_check недоступен: ${error.message}`]; }
    let fts = true;
    try { db.prepare("INSERT INTO facts_fts(facts_fts) VALUES('integrity-check')").run(); } catch (error) { fts = `FTS ошибка: ${error.message}`; }
    return {
      ok: true, db_path: dbPath, version: VERSION, size: fs.existsSync(dbPath) ? fs.statSync(dbPath).size : 0,
      integrity, fts, stats: mem.stats(db),
    };
  },
};

const log = (...parts) => process.stderr.write(`[lsre-lite] ${parts.join(' ')}\n`);

function respond(id, payload) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id, result: payload })}\n`);
}
function fail(id, code, message) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } })}\n`);
}

const reader = createInterface({ input: process.stdin });
reader.on('line', async (line) => {
  if (!line.trim()) return;
  let request;
  try {
    request = JSON.parse(line);
  } catch {
    log('не JSON на входе');
    return;
  }
  const { id, method, params } = request;
  try {
    if (method === 'initialize') {
      respond(id, {
        protocolVersion: params?.protocolVersion ?? '2025-06-18',
        capabilities: { tools: {} },
        serverInfo: { name: 'lsre-lite', version: VERSION },
      });
      return;
    }
    if (method === 'ping') { respond(id, {}); return; }
    if (method === 'tools/list') { respond(id, { tools: TOOLS }); return; }
    if (method === 'tools/call') {
      const name = params?.name;
      const handler = handlers[name];
      if (!handler) { fail(id, -32602, `неизвестный инструмент: ${name}`); return; }
      let payload;
      try {
        payload = handler(params?.arguments ?? {});
      } catch (error) {
        log(`инструмент ${name} упал:`, error.message);
        payload = { ok: false, error: error?.message ?? String(error) };
      }
      respond(id, { resultType: 'complete', content: [{ type: 'text', text: JSON.stringify(payload) }] });
      return;
    }
    if (method.startsWith('notifications/')) return; // initialized и т.п. — без ответа
    fail(id, -32601, `метод не найден: ${method}`);
  } catch (error) {
    log('сбой обработки строки:', error.message);
    fail(id ?? null, -32603, error.message);
  }
});

process.stderr.write(`[lsre-lite] готов, БД: ${dbPath} (фактов: ${db.prepare('SELECT count(*) c FROM facts').get().c})\n`);
