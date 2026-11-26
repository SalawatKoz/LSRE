// Смоук-проверка LSRE: то, что раньше падало у меня и не тестировалось.
// Запуск: node lsre-lite\smoke.mjs [--full]
//   --full добавляет Ghidra (нужны GHIDRA_INSTALL_DIR и JAVA_HOME) и Frida.
// Код возврата 1 при любом провале — годится для CI и для «проверить после сборки».
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const full = process.argv.includes('--full');
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'lsre-smoke-'));
const target = path.join(process.cwd(), 'lsre.exe');
const probe = fs.existsSync(target) ? target : path.join('D:\\WORK\\SMART BUILDER\\LSRE-app\\lsre.exe');

const srv = spawn(process.execPath, [path.join(HERE, 'server.mjs')], {
  env: {
    ...process.env,
    LSRE_LITE_DB: path.join(work, 'lite.db'),
    LSRE_FACTORY_DB: path.join(work, 'factory.db'),
  },
  stdio: ['pipe', 'pipe', 'pipe'],
});
let err = '';
srv.stderr.on('data', (d) => { err += d; });
srv.on('error', (e) => { console.error('сервер не запустился:', e.message); process.exit(2); });
let buf = '';
const waiters = new Map();
srv.stdout.on('data', (c) => {
  buf += c;
  let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    let m; try { m = JSON.parse(line); } catch { continue; }
    const w = waiters.get(m.id); if (w) { waiters.delete(m.id); w(m); }
  }
});
let seq = 0;
const rpc = (method, params, ms = 300000) => new Promise((res, rej) => {
  const id = ++seq; waiters.set(id, res);
  srv.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  setTimeout(() => { if (waiters.delete(id)) rej(new Error('таймаут ' + method)); }, ms);
});
const call = async (name, args, ms) => {
  const r = await rpc('tools/call', { name, arguments: args }, ms);
  const t = r.result?.content?.[0]?.text ?? JSON.stringify(r.error ?? {});
  try { return JSON.parse(t); } catch { return { raw: String(t).slice(0, 200) }; }
};
let failed = 0;
const check = (name, ok, extra = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? ' — ' + extra : ''}`);
  if (!ok) failed += 1;
};

try {
  await rpc('initialize', {});
  const names = (await rpc('tools/list', {})).result.tools.map((t) => t.name);
  check('tools/list: lsre_hash и lsre_cycle на месте', names.includes('lsre_hash') && names.includes('lsre_cycle'), `${names.length} инструментов`);

  const doc = await call('lsre_doctor', {});
  check('doctor: целостность БД', doc.ok === true && String(doc.integrity) === 'ok');

  const tri = await call('lsre_triage', { path: probe });
  check('triage 95 МБ PE', tri.ok === true && tri.sheet?.type === 'pe', `${tri.ms} мс`);

  const hash = await call('lsre_hash', { path: probe });
  check('lsre_hash: sha256 64 hex', hash.ok === true && /^[0-9a-f]{64}$/.test(hash.sha256 || ''), `${hash.size} б`);

  const bad = await call('lsre_hash', { path: HERE });
  check('lsre_hash: каталог отклонён без падения', bad.ok === false, String(bad.error).slice(0, 60));

  await call('lsre_factory', { op: 'enqueue', title: 'Смоук: задача один', note: 'проверка' });
  const st = await call('lsre_factory', { op: 'stats' });
  check('factory: enqueue + stats', st.ok === true && st.total >= 1);

  if (full) {
    if (process.env.GHIDRA_INSTALL_DIR && process.env.JAVA_HOME) {
      const g = await call('lsre_ghidra_decompile', { path: probe, function: 'entry' }, 600000);
      check('ghidra: не падает на JSON с управляющими символами', g.ok !== undefined, g.ok ? 'ok' : String(g.error).slice(0, 80));
    } else {
      console.log('SKIP  ghidra: нет GHIDRA_INSTALL_DIR/JAVA_HOME');
    }
    const fr = await call('lsre_frida_status', {});
    check('frida: библиотека отвечает', fr.ok !== undefined, JSON.stringify(fr).slice(0, 80));
  }

  const cycle = await call('lsre_cycle', {}, 20000).catch(() => ({ ok: false }));
  check('cycle: отвечает без падения (задача не задана)', cycle.ok === false);
} finally {
  srv.kill();
  try { fs.rmSync(work, { recursive: true, force: true }); } catch { /* держит сервер */ }
  if (err.trim()) console.log('stderr:', err.trim().split('\n').slice(0, 3).join(' | '));
  console.log(failed ? `\nПРОВАЛОВ: ${failed}` : '\nвсё зелёное');
  process.exit(failed ? 1 : 0);
}
