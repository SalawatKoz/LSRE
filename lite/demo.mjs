import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lsre-lite-demo-'));
const child = spawn(process.execPath, [path.join(here, 'server.mjs'), '--db', path.join(tmp, 'demo.db')], { stdio: ['pipe', 'pipe', 'inherit'] });
const pending = new Map();
let id = 1;
createInterface({ input: child.stdout }).on('line', (line) => {
  const msg = JSON.parse(line);
  if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
});
const rpc = (method, params) => new Promise((resolve) => { const n = id++; pending.set(n, resolve); child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: n, method, params })}\n`); });
const call = async (name, args) => JSON.parse((await rpc('tools/call', { name, arguments: args })).result.content[0].text);

await rpc('initialize', {});
const t0 = Date.now();
const big = await call('lsre_analyze', { path: 'D:\\WORK\\SMART BUILDER\\LSRE-build\\LSRE.exe', bank: 'demo' });
console.log(`\nLSRE.exe (286 МБ): ${big.ms} мс, факт-шит ${Buffer.byteLength(JSON.stringify(big.fact_sheet))} б`);
console.log(JSON.stringify(big.fact_sheet, null, 1).slice(0, 1200));
const notepad = await call('lsre_analyze', { path: 'C:\\Windows\\System32\\notepad.exe', bank: 'demo' });
console.log(`\nnotepad.exe: ${notepad.ms} мс, id=${notepad.memory.id}, связей применено=${notepad.graph.edges_applied}`);
const stats = await call('lsre_stats', {});
console.log('память:', JSON.stringify(stats));
const ctx = await call('lsre_context', { query: 'node pdb tls callbacks', bank: 'demo', budget_bytes: 800 });
console.log('контекст:', ctx.bytes, 'б,', ctx.count, 'фактов');
console.log(ctx.context.split('\n')[0]?.slice(0, 400));
await new Promise((resolve) => { child.on('exit', resolve); child.kill(); });
fs.rmSync(tmp, { recursive: true, force: true });
console.log(`итого с запуском сервера: ${Date.now() - t0} мс`);
