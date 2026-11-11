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
import { ghidraQuery } from './ghidra.mjs';
import * as frida from './frida.mjs';
import { parseFormat, supported as formatsSupported } from './formats.mjs';
import { parseYaml } from './parse_yaml.mjs';
import { yaraScan, yaraStatus } from './yara.mjs';

const VERSION = '1.0.0';
const DB_PATH = process.env.LSRE_LITE_DB
  || (process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, 'lsre-lite', 'memory.db') : path.join(os.tmpdir(), 'lsre-lite', 'memory.db'));
const argDb = process.argv.indexOf('--db');
const dbPath = argDb !== -1 && process.argv[argDb + 1] ? process.argv[argDb + 1] : DB_PATH;

const db = mem.openDb(dbPath);
const clampInt = (value, min, max, fallback) => Math.max(min, Math.min(max, Number(value) || fallback));
const u = (value, source = 'file', max = 120) => mem.untrusted(value, source, max);

// --- глубокий режим: эмбеддинги ------------------------------------------
// Модель грузится лениво при первом обращении. Нет модели/ONNX — сервер живёт
// как раньше, на FTS5: ни один инструмент не должен падать из-за Deep-части.
const DEEP = process.env.LSRE_DEEP !== '0';
let embedder = null;
let embedFailed = false;

async function getEmbedder() {
  if (!DEEP || embedFailed) return null;
  if (embedder) return embedder;
  try {
    const mod = await import('./embed.mjs');
    const info = await mod.initEmbeddings();
    embedder = mod;
    process.stderr.write(`[lsre-lite] эмбеддинги: ${info.model} ${info.dim}d (${info.dir})\n`);
    return embedder;
  } catch (error) {
    embedFailed = true;
    process.stderr.write(`[lsre-lite] эмбеддинги недоступны (${error?.message ?? error}); поиск лексический\n`);
    return null;
  }
}

async function embedNow(limit = 8) {
  const mod = await getEmbedder();
  if (!mod) return null;
  const model = mod.info?.().model ?? 'unknown';
  try { return await mem.embedPending(db, mod.embed, { limit, model }); } catch { return null; }
}

const TOOLS = [
  { name: 'lsre_analyze', description: 'Один проход: триаж по сигнатуре + факт в память + связи графа. Факт-шит ≤2 КБ. Не пишет \"pe\" без сигнатуры MZ+PE.', inputSchema: { type: 'object', properties: { path: { type: 'string', description: 'Файл для анализа' }, bank: { type: 'string', description: 'Банк памяти (default)' }, hash: { type: 'boolean', description: 'Считать sha256 (файлы ≤64 МБ)' } }, required: ['path'] } },
  { name: 'lsre_triage', description: 'Триаж без записи в память: PE (импорты с именами функций, экспорты, PDB, Rich, подпись, TLS-callbacks), ELF, Mach-O, ZIP/APK/JAR, DEX, PDF, тексты и др.', inputSchema: { type: 'object', properties: { path: { type: 'string' }, hash: { type: 'boolean' } }, required: ['path'] } },
  { name: 'lsre_parse_format', description: 'Разбор известного формата через Kaitai Struct: png, sqlite3, gzip, pcap. Формат определяется по сигнатуре; ничего не исполняется.', inputSchema: { type: 'object', properties: { path: { type: 'string' }, format: { type: 'string', description: 'png | sqlite3 | gzip | pcap — если нужно задать вручную' } }, required: ['path'] } },
  { name: 'lsre_parse_yaml', description: 'YAML → JSON без исполнения тегов: файл (до 1 МБ) или текст. Теги python/js/ruby запрещены.', inputSchema: { type: 'object', properties: { path: { type: 'string' }, text: { type: 'string' } } } },
  { name: 'lsre_yara_scan', description: 'YARA-X: скан файла правилами (свои по умолчанию, можно указать другой .yar). Возвращает правила, совпавшие паттерны и смещения.', inputSchema: { type: 'object', properties: { path: { type: 'string' }, rules: { type: 'string', description: 'Свой файл правил (.yar/.yara)' }, timeout_ms: { type: 'integer' } }, required: ['path'] } },
  { name: 'lsre_frida_status', description: 'Состояние Frida: доступна ли библиотека, версия. Не подключается к процессам.', inputSchema: { type: 'object', properties: {} } },
  { name: 'lsre_recall', description: 'Поиск фактов: FTS5 bm25 + покрытие терминов + RRF; в глубоком режиме — гибрид с косинусом эмбеддингов и полем why (почему всплыло).', inputSchema: { type: 'object', properties: { query: { type: 'string' }, limit: { type: 'integer', description: '1–50, по умолчанию 8' }, bank: { type: 'string' } }, required: ['query'] } },
  { name: 'lsre_embed', description: 'Локальный вектор текста rubert-tiny2 int8 (312d, без сети): вектор или косинус двух текстов. Нет модели — понятная ошибка, сервер не падает.', inputSchema: { type: 'object', properties: { text: { type: 'string' }, compare: { type: 'string', description: 'Второй текст: вернуть косинус вместо вектора' } }, required: ['text'] } },
  { name: 'lsre_similar', description: 'Похожие по смыслу факты из памяти (косинус эмбеддингов): находит перефразы, которые FTS5 пропускает.', inputSchema: { type: 'object', properties: { text: { type: 'string' }, limit: { type: 'integer', description: '1–50, по умолчанию 8' }, bank: { type: 'string' } }, required: ['text'] } },
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
  { name: 'lsre_ghidra_open', description: 'Импорт в Ghidra headless с кэшем проекта + обзор: число функций, строки, внешние символы. Первый вызов 30–120 с, дальше быстро.', inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] } },
  { name: 'lsre_ghidra_decompile', description: 'Псевдокод функции (имя или 0x-адрес). Вывод ограничен ~10 КБ.', inputSchema: { type: 'object', properties: { path: { type: 'string' }, function: { type: 'string' } }, required: ['path', 'function'] } },
  { name: 'lsre_ghidra_strings', description: 'Строки программы с фильтром по подстроке.', inputSchema: { type: 'object', properties: { path: { type: 'string' }, filter: { type: 'string' } }, required: ['path'] } },
  { name: 'lsre_ghidra_xrefs', description: 'Кто ссылается на функцию/адрес.', inputSchema: { type: 'object', properties: { path: { type: 'string' }, target: { type: 'string' } }, required: ['path', 'target'] } },
  { name: 'lsre_frida_processes', description: 'Список процессов (pid, имя) — цель для attach/spawn.', inputSchema: { type: 'object', properties: {} } },
  { name: 'lsre_frida_modules', description: 'Модули процесса: имя, база, размер, путь.', inputSchema: { type: 'object', properties: { target: { type: 'string', description: 'pid или имя процесса' } }, required: ['target'] } },
  { name: 'lsre_frida_run', description: 'Выполнить Frida-скрипт в процессе: attach или spawn, сбор сообщений за время. Явная цель обязательна.', inputSchema: { type: 'object', properties: { script: { type: 'string' }, target: { type: 'string', description: 'pid или имя процесса' }, mode: { type: 'string', description: 'attach | spawn' }, timeout_ms: { type: 'integer', description: '100–60000, по умолчанию 8000' } }, required: ['script', 'target'] } },
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
    for (const key of ['names', 'entries', 'libraries', 'strings', 'classes', 'methods', 'width', 'height', 'javascript', 'open_action', 'launch', 'encoding', 'lines', 'note', 'magic', 'header_hex', 'header_u32', 'zlib_streams_1mb', 'zlib_offsets', 'zip_headers_1mb', 'ifc_refs_4mb', 'tail_hex']) {
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
  if (sheet.type === 'pln') {
    return `Файл ${file}: ${sheet.size} б, контейнер ArchiCAD 'ROF FDB', заголовок ${sheet.header_hex}, `
      + `zlib-потоков в 1-м МБ: ${sheet.zlib_streams_1mb}, IFC-ссылок в 4-х МБ: ${sheet.ifc_refs_4mb}, хвост: ${sheet.tail_hex}`;
  }
  return `Файл ${file}: ${sheet.size} б, тип ${sheet.type}${sheet.arch ? `, ${sheet.arch}` : ''}`;
}

// Режим для внешних оболочек (Craft Anything и т.п.), которые сами добавляют префикс
// набора инструментов: отдаём имена без «lsre_», чтобы не получалось lsre_lsre_analyze.
const PLAIN_NAMES = process.env.LSRE_PLAIN_NAMES === '1';
const EXPOSED_TOOLS = PLAIN_NAMES ? TOOLS.map((tool) => ({ ...tool, name: tool.name.replace(/^lsre_/, '') })) : TOOLS;

const handlers = {
  async lsre_analyze(args) {
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
    if (memory?.ok && !memory.duplicate) await embedNow(2);
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

  lsre_parse_format(args) {
    const file = String(args.path ?? '').trim().slice(0, 1000);
    if (!file) return { ok: false, error: 'нужен path' };
    if (!fs.existsSync(file)) return { ok: false, error: `файл не найден: ${file}` };
    if (!fs.statSync(file).isFile()) return { ok: false, error: `не файл: ${file}` };
    const manual = String(args.format ?? '').trim().toLowerCase();
    if (manual && !formatsSupported().includes(manual)) {
      return { ok: false, error: `неизвестный формат: ${manual}`, supported: formatsSupported() };
    }
    const result = parseFormat(file);
    if (!result.ok) return result;
    return { ...result, supported: formatsSupported() };
  },

  lsre_parse_yaml(args) {
    const file = args.path ? String(args.path).trim().slice(0, 1000) : null;
    const text = args.text ? String(args.text).slice(0, 1024 * 1024) : null;
    if (!file && !text) return { ok: false, error: 'нужен path или text' };
    if (file && !fs.existsSync(file)) return { ok: false, error: `файл не найден: ${file}` };
    return parseYaml({ file, text });
  },

  async lsre_yara_scan(args) {
    const file = String(args.path ?? '').trim().slice(0, 1000);
    if (!file) return { ok: false, error: 'нужен path' };
    const result = await yaraScan({
      file,
      rules: args.rules ? String(args.rules).trim().slice(0, 1000) : null,
      timeoutMs: clampInt(args.timeout_ms, 1000, 120000, 20000),
    });
    return result;
  },

  async lsre_frida_status() {
    const status = yaraStatus();
    try {
      const mod = await import('frida');
      const lib = mod.default ?? mod;
      return { ok: true, frida: Boolean(lib), version: lib?.version ?? null, yara: { present: status.present, rules: status.rules } };
    } catch (error) {
      return { ok: false, error: `frida недоступна: ${error?.message ?? error}`, yara: { present: status.present, rules: status.rules } };
    }
  },

  async lsre_recall(args) {
    const query = String(args.query ?? '').trim().slice(0, 500);
    if (!query) return { ok: false, error: 'пустой запрос' };
    const bank = args.bank ? String(args.bank).trim().slice(0, 40) : null;
    const limit = clampInt(args.limit, 1, 50, 8);
    let rows = mem.recallFacts(db, { query, bank, limit });
    let hybrid = false;
    const mod = await getEmbedder();
    if (mod) {
      try {
        const queryVec = await mod.embed(query, 'query');
        rows = mem.recallHybrid(db, { query, queryVec, bank, limit });
        hybrid = true;
      } catch { /* вектор не вышел — остаёмся на лексике, это не ошибка */ }
    }

    // Страницы знаний не входят в facts_fts, поэтому ищем их отдельно:
    // иначе память проекта (HANDOVER, соглашения) не находится через recall.
    const tokens = query.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter((token) => token.length > 2);
    let pageHits = [];
    if (tokens.length) {
      const where = tokens.map(() => "(lower(slug) || ' ' || lower(question) || ' ' || lower(answer) LIKE ?)").join(' OR ');
      const params = tokens.map((token) => `%${token}%`);
      const sql = bank
        ? `select slug, question, answer from pages where bank = ? and (${where}) limit 10`
        : `select slug, question, answer from pages where ${where} limit 10`;
      const bound = bank ? [bank, ...params] : params;
      pageHits = db.prepare(sql).all(...bound)
        .map((row) => {
          const haystack = `${row.slug} ${row.question} ${row.answer}`.toLowerCase();
          const hits = tokens.filter((token) => haystack.includes(token)).length;
          return { slug: row.slug, question: row.question, excerpt: String(row.answer).replace(/\s+/g, ' ').slice(0, 400), score: hits / tokens.length };
        })
        .sort((a, b) => b.score - a.score)
        .slice(0, 3);
    }

    const result = { ok: true, query, hybrid, found: rows.length, results: rows.map(mem.renderFact), scores: rows.map((r) => ({ id: r.id, score: r.score, coverage: r.coverage, why: r.why })) };
    if (pageHits.length) result.pages = pageHits;
    return result;
  },

  async lsre_embed(args) {
    const text = String(args.text ?? '').trim().slice(0, 4000);
    if (!text) return { ok: false, error: 'нужен text' };
    const mod = await getEmbedder();
    if (!mod) return { ok: false, error: 'эмбеддинги недоступны: нет модели или onnxruntime', deep: DEEP };
    const vec = await mod.embed(text, 'query');
    const model = mod.info?.().model ?? 'unknown';
    if (args.compare) {
      const other = await mod.embed(String(args.compare).slice(0, 4000), 'query');
      return { ok: true, dim: vec.length, model, cosine: Math.round(mod.cosine(vec, other) * 1e4) / 1e4 };
    }
    return { ok: true, dim: vec.length, model, vector: [...vec].map((v) => Math.round(v * 1e4) / 1e4) };
  },

  async lsre_similar(args) {
    const text = String(args.text ?? '').trim().slice(0, 4000);
    if (!text) return { ok: false, error: 'нужен text' };
    const bank = args.bank ? String(args.bank).trim().slice(0, 40) : null;
    const mod = await getEmbedder();
    if (!mod) return { ok: false, error: 'эмбеддинги недоступны: нет модели или onnxruntime' };
    const queryVec = await mod.embed(text, 'query');
    const rows = mem.semanticTop(db, { queryVec, bank, limit: clampInt(args.limit, 1, 50, 8) });
    return { ok: true, model: mod.info?.().model ?? null, found: rows.length, results: rows.map((r) => ({ id: r.id, cos: r.cos, text: mem.renderFact(r) })) };
  },

  lsre_context(args) {
    const query = String(args.query ?? '').trim().slice(0, 500);
    if (!query) return { ok: false, error: 'пустой запрос' };
    const bank = args.bank ? String(args.bank).trim().slice(0, 40) : null;
    return mem.buildContext(db, { query, bank, budgetBytes: clampInt(args.budget_bytes, 500, 8000, 3000) });
  },

  async lsre_remember(args) {
    const text = String(args.text ?? '').slice(0, 8000);
    const bank = String(args.bank ?? 'default').trim().slice(0, 40) || 'default';
    const result = mem.rememberFact(db, { bank, text, kind: String(args.kind ?? 'note'), tags: String(args.tags ?? ''), trust: 1, source: 'agent' });
    if (result.ok && !result.duplicate) {
      const done = await embedNow(4);
      if (done) result.embedded = done.embedded > 0;
    }
    return result;
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

  lsre_ghidra_open(args) {
    const file = String(args.path ?? '').trim().slice(0, 1000);
    if (!fs.existsSync(file)) return { ok: false, error: `файл не найден: ${file}` };
    const result = ghidraQuery(file, 'overview');
    if (!result.ok) return result;
    const data = result.data ?? {};
    // Экономим токены: выборки обрезаны ещё на стороне сервера.
    return {
      ok: true, ms: result.ms, project: result.project,
      functions: data.functions ?? null,
      sample: (data.sample ?? []).slice(0, 25),
      strings: (data.strings ?? []).slice(0, 80),
      external: (data.external ?? []).slice(0, 60),
      note: 'дальше — lsre_ghidra_decompile / _strings / _xrefs по кэшированному проекту',
    };
  },

  lsre_ghidra_decompile(args) {
    const file = String(args.path ?? '').trim().slice(0, 1000);
    const fn = String(args.function ?? '').trim().slice(0, 200);
    if (!file || !fn) return { ok: false, error: 'нужны path и function' };
    const result = ghidraQuery(file, 'decompile', fn);
    if (!result.ok) return result;
    const code = result.data?.code;
    return {
      ok: true, ms: result.ms, function: result.data?.function, address: result.data?.address,
      error: result.data?.error, code_bytes: code ? Buffer.byteLength(code) : 0,
      code: code ? code.slice(0, 10000) : null,
    };
  },

  lsre_ghidra_strings(args) {
    const file = String(args.path ?? '').trim().slice(0, 1000);
    const filter = String(args.filter ?? '').slice(0, 100);
    if (!fs.existsSync(file)) return { ok: false, error: `файл не найден: ${file}` };
    const result = ghidraQuery(file, 'strings', filter);
    if (!result.ok) return result;
    return { ok: true, ms: result.ms, count: result.data?.strings?.length ?? 0, strings: (result.data?.strings ?? []).slice(0, 200) };
  },

  lsre_ghidra_xrefs(args) {
    const file = String(args.path ?? '').trim().slice(0, 1000);
    const target = String(args.target ?? '').trim().slice(0, 200);
    if (!file || !target) return { ok: false, error: 'нужны path и target' };
    const result = ghidraQuery(file, 'xrefs', target);
    if (!result.ok) return result;
    return { ok: true, ms: result.ms, count: result.data?.xrefs?.length ?? 0, xrefs: (result.data?.xrefs ?? []).slice(0, 100) };
  },

  async lsre_frida_processes() {
    try {
      const processes = await frida.listProcesses();
      return { ok: true, count: processes.length, processes };
    } catch (error) {
      return { ok: false, error: `frida недоступна: ${error?.message ?? error}` };
    }
  },

  async lsre_frida_modules(args) {
    const target = String(args.target ?? '').trim();
    if (!target) return { ok: false, error: 'нужна цель: pid или имя процесса' };
    try {
      const modules = await frida.listModules(target);
      return { ok: true, count: modules.length, modules };
    } catch (error) {
      return { ok: false, error: `frida: ${error?.message ?? error}` };
    }
  },

  async lsre_frida_run(args) {
    const script = String(args.script ?? '');
    const target = String(args.target ?? '').trim();
    if (!script || !target) return { ok: false, error: 'нужны script и target' };
    try {
      const result = await frida.runScript({
        script, target,
        mode: String(args.mode ?? 'attach') === 'spawn' ? 'spawn' : 'attach',
        timeoutMs: clampInt(args.timeout_ms, 100, 60000, 8000),
      });
      return { ...result, messages: result.messages ?? [] };
    } catch (error) {
      return { ok: false, error: `frida: ${error?.message ?? error}` };
    }
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
    if (method === 'tools/list') { respond(id, { tools: EXPOSED_TOOLS }); return; }
    if (method === 'tools/call') {
      const rawName = params?.name;
      const name = PLAIN_NAMES && rawName && !rawName.startsWith('lsre_') ? `lsre_${rawName}` : rawName;
      const handler = handlers[name];
      if (!handler) { fail(id, -32602, `неизвестный инструмент: ${rawName}`); return; }
      let payload;
      try {
        payload = await handler(params?.arguments ?? {});
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
