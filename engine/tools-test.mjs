// РџСЂРѕРІРµСЂРєР° РїРѕР»РЅРѕРіРѕ РЅР°Р±РѕСЂР° РёРЅСЃС‚СЂСѓРјРµРЅС‚РѕРІ lite-РґРІРёР¶РєР°: Kaitai, YAML, YARA, Frida.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const dbPath = path.join(here, '..', 'lsre-memory', 'tools-test.db');
for (const s of ['', '-wal', '-shm']) { try { fs.unlinkSync(dbPath + s); } catch { /* РЅРµС‚ */ } }

const child = spawn(process.execPath, [path.join(here, 'server.mjs'), '--db', dbPath], {
  stdio: ['pipe', 'pipe', 'pipe'],
  env: { ...process.env, LSRE_EMBED_DIR: 'D:\\WORK\\SMART BUILDER\\LSRE-deep\\models\\e5-small' },
});
let buf = '';
const pending = new Map();
let id = 0;
child.stdout.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\n')) !== -1) {
    const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
    if (!line) continue;
    try { const m = JSON.parse(line); pending.get(m.id)?.(m); } catch { /* РјСѓСЃРѕСЂ */ }
  }
});
const rpc = (method, params) => new Promise((res, rej) => {
  const n = ++id; const t = setTimeout(() => rej(new Error('С‚Р°Р№РјР°СѓС‚ ' + method)), 60000);
  pending.set(n, (m) => { clearTimeout(t); res(m); });
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: n, method, params }) + '\n');
});
const tool = async (name, args = {}) => {
  const r = await rpc('tools/call', { name, arguments: args });
  if (r.error) throw new Error(name + ': ' + JSON.stringify(r.error));
  const text = r.result?.content?.[0]?.text ?? '{}';
  return { json: JSON.parse(text), bytes: Buffer.byteLength(text) };
};
let fails = 0;
const check = (label, ok, extra = '') => { if (!ok) fails++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${extra ? ' вЂ” ' + extra : ''}`); };

try {
  await rpc('initialize', { protocolVersion: '2025-06-18', clientInfo: { name: 'tools-test' } });
  const list = await rpc('tools/list');
  const names = list.result.tools.map((t) => t.name);
  check('РёРЅСЃС‚СЂСѓРјРµРЅС‚РѕРІ 28, РµСЃС‚СЊ РЅРѕРІС‹Рµ', names.length === 28 && ['lsre_parse_format', 'lsre_parse_yaml', 'lsre_yara_scan', 'lsre_frida_status'].every((n) => names.includes(n)), `${names.length} С€С‚.`);

  const png = await tool('lsre_parse_format', { path: 'D:\\WORK\\SMART BUILDER\\LSRE-repo\\assets\\logo-256.png' });
  check('Kaitai PNG', png.json.ok === true && png.json.format === 'png' && png.json.data?.width === 256, `wd=${png.json.data?.width}x${png.json.data?.height}, ${png.bytes} Р‘`);

  const gz = await tool('lsre_parse_format', { path: 'D:\\WORK\\SMART BUILDER\\LSRE-build\\payload.tar.zst' });
  check('РЅРµРёР·РІРµСЃС‚РЅС‹Р№ С„РѕСЂРјР°С‚ вЂ” С‡РµСЃС‚РЅС‹Р№ РѕС‚РєР°Р·', gz.json.ok === false, gz.json.error);

  const yamlText = await tool('lsre_parse_yaml', { text: 'name: LSRE\nversion: 3\nitems:\n  - a\n  - b\n' });
  check('YAML С‚РµРєСЃС‚', yamlText.json.ok === true && yamlText.json.data?.items?.length === 2);

  const yamlBad = await tool('lsre_parse_yaml', { text: 'a: 1\n b: 2\n' });
  check('YAML СЃ РѕС€РёР±РєРѕР№ вЂ” РѕС‚РєР°Р· СЃ СЃС‚СЂРѕРєРѕР№', yamlBad.json.ok === false, String(yamlBad.json.error).slice(0, 40));

  const yara = await tool('lsre_yara_scan', { path: 'C:\\Windows\\System32\\notepad.exe' });
  check('YARA СЃРєР°РЅ notepad', yara.json.ok === true, `РїСЂР°РІРёР» СЃСЂР°Р±РѕС‚Р°Р»Рѕ: ${yara.json.count}, ${yara.bytes} Р‘`);

  const fr = await tool('lsre_frida_status');
  check('Frida СЃС‚Р°С‚СѓСЃ', fr.json.ok === true || fr.json.error, JSON.stringify(fr.json).slice(0, 80));
} catch (error) {
  console.log('FAIL  ' + error.message); fails++;
} finally {
  child.stdin.end(); child.kill();
  console.log(`\nРїСЂРѕРІР°Р»РѕРІ: ${fails}`);
  if (fails) process.exitCode = 1;
}

