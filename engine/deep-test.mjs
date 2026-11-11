// Проверка Deep-режима через настоящий MCP-канал (stdio): память, гибридный recall, эмбеддинги.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const dbPath = path.join(here, '..', 'lsre-memory', 'deep-test.db');
for (const suffix of ['', '-wal', '-shm']) { try { fs.unlinkSync(dbPath + suffix); } catch { /* нет файла */ } }

const child = spawn(process.execPath, [path.join(here, 'server.mjs'), '--db', dbPath], {
  stdio: ['pipe', 'pipe', 'pipe'],
  env: { ...process.env, LSRE_EMBED_DIR: process.env.LSRE_EMBED_DIR ?? 'D:\\WORK\\SMART BUILDER\\LSRE-deep\\models\\e5-small' },
});
let buffer = '';
const pending = new Map();
let nextId = 1;
const errors = [];
child.stderr.on('data', (chunk) => errors.push(String(chunk)));
child.stdout.on('data', (chunk) => {
  buffer += chunk;
  let index;
  while ((index = buffer.indexOf('\n')) !== -1) {
    const line = buffer.slice(0, index).trim();
    buffer = buffer.slice(index + 1);
    if (!line) continue;
    try {
      const msg = JSON.parse(line);
      const resolve = pending.get(msg.id);
      if (resolve) { pending.delete(msg.id); resolve(msg); }
    } catch { errors.push(`битая строка: ${line.slice(0, 120)}`); }
  }
});

const rpc = (method, params) => new Promise((resolve, reject) => {
  const id = nextId++;
  const timer = setTimeout(() => reject(new Error(`таймаут ${method}`)), 30000);
  pending.set(id, (msg) => { clearTimeout(timer); resolve(msg); });
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
});
const tool = async (name, args = {}) => {
  const reply = await rpc('tools/call', { name, arguments: args });
  if (reply.error) throw new Error(`${name}: ${JSON.stringify(reply.error)}`);
  const text = reply.result?.content?.[0]?.text ?? '{}';
  return { json: JSON.parse(text), bytes: Buffer.byteLength(text) };
};
const check = (label, ok, extra = '') => console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${extra ? ` — ${extra}` : ''}`);
const fails = [];
const assert = (label, ok, extra = '') => { if (!ok) fails.push(label); check(label, ok, extra); };

try {
  await rpc('initialize', { protocolVersion: '2025-06-18', clientInfo: { name: 'deep-test' } });
  const list = await rpc('tools/list');
  const names = list.result.tools.map((t) => t.name);
  assert('инструментов 24, есть lsre_embed/lsre_similar', names.length === 24 && names.includes('lsre_embed') && names.includes('lsre_similar'), `${names.length} шт.`);

  const t0 = Date.now();
  const first = await tool('lsre_remember', { text: 'Стена из кирпича 400 мм, утеплитель 100 мм, несущая для второго этажа', tags: 'bim', bank: 'deep' });
  assert('remember с вектором', first.json.ok && first.json.embedded === true, `${Date.now() - t0} мс`);

  await tool('lsre_remember', { text: 'В ArchiCAD окно вставляется в стену автоматически, отверстие вырезается профилем', bank: 'deep' });
  await tool('lsre_remember', { text: 'PE-файл: импорты kernel32.dll, упаковщик UPX, Rich header указывает линкер VC++', bank: 'deep' });

  const vec = await tool('lsre_embed', { text: 'Кирпичная стена толщиной 400 мм', compare: 'Стена из кирпича 400 мм, утеплитель 100 мм' });
  assert('косинус пары', vec.json.ok && vec.json.cosine > 0.6, `cos=${vec.json.cosine}, ${vec.bytes} Б`);

  const recall = await tool('lsre_recall', { query: 'кладка сорок сантиметров', bank: 'deep', limit: 5 });
  assert('гибридный recall включён', recall.json.hybrid === true);
  assert('перефраз найден без общих слов', recall.json.found > 0 && String(recall.json.results[0]).includes('кирпича'), `ответ ${recall.bytes} Б`);
  assert('в ответе есть why', Boolean(recall.json.scores?.[0]?.why));

  const similar = await tool('lsre_similar', { text: 'толщина кладки 0,4 м', bank: 'deep', limit: 3 });
  assert('lsre_similar находит по смыслу', similar.json.ok && similar.json.found > 0, `cos=${similar.json.results?.[0]?.cos}`);

  const stats = await tool('lsre_stats');
  assert('stats видит embeddings', stats.json.embeddings >= 3, `векторов ${stats.json.embeddings}`);

  const size = fs.statSync(dbPath).size;
  const recallBytes = recall.bytes;
  console.log(`INFO  БД ${(size / 1024).toFixed(1)} КБ, ответ recall ${recallBytes} Б, ошибки stderr: ${errors.filter((e) => !e.includes('эмбеддинги:')).length}`);
} catch (error) {
  console.log(`FAIL  исключение: ${error.message}`);
  fails.push('exception');
} finally {
  child.stdin.end();
  child.kill();
  console.log(`\nитого: провалов ${fails.length}`);
  if (fails.length) process.exitCode = 1;
}
