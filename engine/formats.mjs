// Форматы через Kaitai Struct: png, sqlite3, gzip, pcap. Скомпилированные парсеры лежат
// рядом (formats/*.js), рантайм — node_modules/kaitai-struct. Ничего не исполняется из файла.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const KaitaiStream = require(path.join(here, 'node_modules', 'kaitai-struct', 'KaitaiStream.js'));

const PARSERS = {
  png: { file: 'Png.js', magic: (b) => b.length > 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 },
  sqlite3: { file: 'Sqlite3.js', magic: (b) => b.length > 16 && b.subarray(0, 15).toString('latin1') === 'SQLite format 3' },
  gzip: { file: 'Gzip.js', magic: (b) => b.length > 2 && b[0] === 0x1f && b[1] === 0x8b },
  pcap: {
    file: 'Pcap.js',
    magic: (b) => b.length > 4 && (
      (b[0] === 0xd4 && b[1] === 0xc3 && b[2] === 0xb2 && b[3] === 0xa1)
      || (b[0] === 0xa1 && b[1] === 0xb2 && b[2] === 0xc3 && b[3] === 0xd4)
      || (b[0] === 0x4d && b[1] === 0x3c && b[2] === 0xb2 && b[3] === 0xa1)
      || (b[0] === 0xa1 && b[1] === 0xb2 && b[2] === 0x3c && b[3] === 0x4d)
    ),
  },
};

/** Какой формат узнаём по сигнатуре (без чтения целиком). */
export function detect(file) {
  const head = Buffer.alloc(64);
  const fd = fs.openSync(file, 'r');
  try { fs.readSync(fd, head, 0, head.length, 0); } finally { fs.closeSync(fd); }
  for (const [name, spec] of Object.entries(PARSERS)) if (spec.magic(head)) return name;
  return null;
}

export function supported() {
  return Object.keys(PARSERS);
}

function summarize(value, depth = 0, seen = new Set()) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'bigint') return Number(value);
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'string') {
    return typeof value === 'string' ? value.slice(0, 300) : value;
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const hex = Buffer.from(value).subarray(0, 24).toString('hex');
    return `<${value.length} байт: ${hex}${value.length > 24 ? '…' : ''}>`;
  }
  if (depth > 3 || seen.has(value)) return '<…>';
  seen.add(value);
  if (Array.isArray(value)) {
    const items = value.slice(0, 12).map((item) => summarize(item, depth + 1, seen));
    if (value.length > 12) items.push(`… ещё ${value.length - 12}`);
    return items;
  }
  const out = {};
  for (const key of Object.keys(value)) {
    if (key.startsWith('_') || key === 'parent') continue;
    out[key] = summarize(value[key], depth + 1, seen);
    if (Object.keys(out).length >= 40) { out['…'] = 'обрезано'; break; }
  }
  return out;
}

const EXPORT_NAME = { png: 'Png', sqlite3: 'Sqlite3', gzip: 'Gzip', pcap: 'Pcap' };

/** Разобрать известный формат: { ok, format, size, data }. */
export function parseFormat(file) {
  const format = detect(file);
  if (!format) return { ok: false, error: `формат не поддержан (есть: ${supported().join(', ')})`, supported: supported() };
  const size = fs.statSync(file).size;
  if (size > 64 * 1024 * 1024) return { ok: false, error: 'файл больше 64 МБ — разбор ограничен' };
  const mod = require(path.join(here, 'formats', PARSERS[format].file));
  const Parser = mod[EXPORT_NAME[format]] ?? Object.values(mod)[0];
  if (typeof Parser !== 'function') return { ok: false, error: `парсер ${format} не загрузился` };
  const bytes = fs.readFileSync(file);
  const stream = new KaitaiStream(bytes);
  const parsed = new Parser(stream);
  return { ok: true, format, size, data: summarize(parsed) };
}
