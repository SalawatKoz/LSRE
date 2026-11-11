// YAML → JSON без исполнения тегов: только данные, лимиты на размер и глубину.
import fs from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
let yaml = null;
function runtime() {
  if (!yaml) yaml = require('yaml');
  return yaml;
}

const MAX_CHARS = 1024 * 1024;

function summarize(value, depth = 0, seen = new Set()) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'string') {
    return typeof value === 'string' ? value.slice(0, 400) : value;
  }
  if (depth > 6 || seen.has(value)) return '<…>';
  seen.add(value);
  if (Array.isArray(value)) {
    const items = value.slice(0, 50).map((item) => summarize(item, depth + 1, seen));
    if (value.length > 50) items.push(`… ещё ${value.length - 50}`);
    return items;
  }
  const out = {};
  for (const key of Object.keys(value)) {
    out[key] = summarize(value[key], depth + 1, seen);
    if (Object.keys(out).length >= 100) { out['…'] = 'обрезано'; break; }
  }
  return out;
}

/** Разобрать YAML из файла или строки: { ok, kind, data }. */
export function parseYaml({ file, text } = {}) {
  let source = text;
  if (file) {
    if (!fs.existsSync(file)) return { ok: false, error: `файл не найден: ${file}` };
    const size = fs.statSync(file).size;
    if (size > MAX_CHARS) return { ok: false, error: 'YAML больше 1 МБ — отказ' };
    source = fs.readFileSync(file, 'utf8');
  }
  if (!source || !source.trim()) return { ok: false, error: 'пустой YAML' };
  if (source.length > MAX_CHARS) return { ok: false, error: 'YAML больше 1 МБ — отказ' };
  try {
    const doc = runtime().parseDocument(source, { customTags: [], strict: true, uniqueKeys: false });
    if (doc.errors?.length) {
      return { ok: false, error: doc.errors[0].message, line: doc.errors[0].linePos?.[0]?.line };
    }
    return { ok: true, kind: file ? 'file' : 'text', data: summarize(doc.toJS()) };
  } catch (error) {
    return { ok: false, error: String(error?.message ?? error) };
  }
}
