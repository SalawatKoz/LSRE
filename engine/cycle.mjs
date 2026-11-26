// Полный цикл задачи на ВСТРОЕННОЙ локальной модели: Triage → Plan → Apply → Verify.
// Модель (Ollama, по умолчанию gemma4-lsre) предлагает план и правки в строгом JSON;
// применение — только через бэкап, проверка — только кодом возврата команды.
// Ошибка проверки откатывает файлы из бэкапа и возвращает задачу в очередь.
//
// CLI: node lsre-lite\cycle.mjs --id 13 [--apply] [--verify "node lsre-lite/test.mjs"]
//      node lsre-lite\cycle.mjs --next --apply --verify "node lsre-lite/test.mjs"
//      --dry  — план и предложенные правки без записи; --model gemma4-lsre
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import * as factory from './factory.mjs';

const ROOT = 'D:\\WORK\\SMART BUILDER';
const OLLAMA = process.env.OLLAMA_URL || 'http://127.0.0.1:11434';
const MODEL_PREF = process.env.LSRE_CYCLE_MODEL || 'gemma4-lsre';
const MODEL = MODEL_PREF;
let _resolvedModel = null;
// Выбор модели по факту доступности: предпочтение → inkling2-mini → gemma4-lsre.
async function pickModel() {
  if (_resolvedModel) return _resolvedModel;
  const want = [MODEL_PREF, 'inkling2-mini', 'gemma4-lsre'];
  try {
    const r = await fetch(OLLAMA + '/api/tags');
    if (r.ok) {
      const names = new Set((await r.json()).models.map((m) => m.name));
      for (const n of want) if (names.has(n)) return (_resolvedModel = n);
      throw new Error(`модель недоступна: ${MODEL_PREF}; доступны: ${[...names].join(', ') || '(пусто)'}`);
    }
  } catch (error) {
    if (String(error.message).startsWith('модель недоступна')) throw error;
  }
  return (_resolvedModel = MODEL_PREF);
}
const MAX_FILE = 200 * 1024;
const TEXT_EXT = /\.(mjs|cjs|js|json|md|txt|rs|cpp|cc|h|hpp|toml|ps1|cmd|vbs|html|css|ts|yml|yaml)$/i;
const FORBIDDEN = /(\.dsh-backups|lsre-memory|node_modules|\\target\\|\.git\\)/i;

const log = (...a) => console.log('[cycle]', ...a);
const nowIso = () => new Date().toISOString();

async function ollama(prompt, { json = true, timeoutSec = 900 } = {}) {
  const body = {
    model: await pickModel(),
    prompt,
    stream: false,
    format: json ? 'json' : undefined,
    // num_predict: без него модель генерирует «до конца контекста» и упирается в таймаут.
    options: { num_ctx: 16384, num_predict: 800, temperature: 0.2, top_p: 0.9 },
  };
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutSec * 1000);
  try {
    const res = await fetch(OLLAMA + '/api/generate', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body), signal: ctl.signal,
    });
    if (!res.ok) throw new Error(`ollama ${res.status}: ${(await res.text()).slice(0, 200)}`);
    const j = await res.json();
    return { text: (j.response || '').trim(), tps: Number(((j.eval_count || 0) / ((j.eval_duration || 1) / 1e9)).toFixed(1)) };
  } finally { clearTimeout(timer); }
}

function parseJson(text) {
  try { return JSON.parse(text); } catch { /* ниже — вытащим блок */ }
  const m = text.match(/\{[\s\S]*\}/);
  if (!m) return null;
  try { return JSON.parse(m[0]); } catch { return null; }
}

function safePath(rel) {
  if (typeof rel !== 'string' || !rel.trim()) return null;
  const abs = path.resolve(ROOT, rel);
  if (!abs.startsWith(ROOT + path.sep)) return null;
  if (FORBIDDEN.test(abs)) return null;
  if (!TEXT_EXT.test(abs)) return null;
  return abs;
}

function runCmd(cmd, { cwd = ROOT, timeoutSec = 900 } = {}) {
  return new Promise((resolve) => {
    const isWin = process.platform === 'win32';
    const child = spawn(isWin ? 'cmd' : 'sh', isWin ? ['/c', cmd] : ['-c', cmd], { cwd, windowsHide: true });
    let out = '';
    let done = false;
    const finish = (code) => { if (done) return; done = true; clearTimeout(timer); resolve({ code, out }); };
    const timer = setTimeout(() => { try { child.kill(); } catch { /* мёртв */ } finish(-2); }, timeoutSec * 1000);
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { out += d; });
    child.on('error', (e) => { out += String(e.message); finish(-1); });
    child.on('exit', (code) => setTimeout(() => finish(code ?? -1), 500));
  });
}

async function backup(absPath) {
  const script = path.join(ROOT, 'backup.ps1');
  const r = await runCmd(`powershell -NoProfile -ExecutionPolicy Bypass -File "${script}" -Path "${absPath}" -Note "cycle: авто-бэкап перед правкой"`, { timeoutSec: 120 });
  const m = r.out.match(/D:\\WORK\\SMART BUILDER\\\.dsh-backups\\[^\s"]+/);
  return { ok: r.code === 0, dir: m ? m[0] : null, out: r.out.slice(-300) };
}

export function triageLocal(task) {
  return factory.classify(task.title, task.note || '');
}

export async function planLocal(task) {
  const prompt = [
    'Ты — планировщик задач проекта LSRE (реверс-инжиниринг и приложения).',
    `Задача #${task.id} (${task.kind}/${task.priority}): ${task.title}`,
    task.note ? `Детали: ${task.note}` : '',
    `Корень проекта: ${ROOT}.`,
    'Верни JSON: {"steps":["..."],"files":["относительные пути"],"verify":"команда проверки или пустая строка"}',
    'Правила: 3–6 шагов, файлы только из проекта, проверка — одна команда. Без пояснений вне JSON.',
  ].filter(Boolean).join('\n');
  const r = await ollama(prompt);
  const j = parseJson(r.text) || {};
  return {
    steps: Array.isArray(j.steps) ? j.steps.map(String).slice(0, 8) : [],
    files: Array.isArray(j.files) ? j.files.map(String).slice(0, 6) : [],
    verify: typeof j.verify === 'string' ? j.verify.trim() : '',
    tps: r.tps,
  };
}

export async function proposeLocal(task, plan, lastError = '') {
  const readable = [];
  const wanted = new Set((plan.files || []).map(String));
  // Скрипт проверки тоже даём модели: иначе она «забывает», что именно должно выполняться.
  for (const m of `${task.note || ''} ${plan.verify || ''}`.matchAll(/([\w./\\-]+\.mjs)/g)) wanted.add(m[1]);
  for (const rel of [...wanted]) {
    const abs = safePath(rel);
    if (!abs) continue;
    if (!fs.existsSync(abs)) { readable.push({ rel, exists: false, content: '' }); continue; }
    const st = fs.statSync(abs);
    if (st.size > MAX_FILE) continue;
    readable.push({ rel, exists: true, content: fs.readFileSync(abs, 'utf8') });
  }
  const prompt = [
    'Ты — исполнитель задач LSRE. Верни ПОЛНОЕ новое содержимое изменяемых файлов.',
    `Задача: ${task.title}${task.note ? ` (${task.note})` : ''}`,
    `План: ${(plan.steps || []).join('; ') || '—'}`,
    lastError ? `ПРЕДЫДУЩАЯ ПОПЫТКА ПРОВАЛИЛАСЬ, исправь это обязательно:\n${lastError.slice(0, 1200)}` : '',
    'Текущее содержимое файлов:',
    ...readable.map((f) => `--- ${f.rel} ---\n${f.content.slice(0, 8000) || '(файла нет)'}`),
    'Верни JSON: {"edits":[{"path":"относительный путь","content":"полное содержимое"}],"note":"коротко что сделано"}',
    'Правила: только текстовые файлы внутри проекта; правки минимальные; JSON без пояснений.',
  ].filter(Boolean).join('\n');
  const r = await ollama(prompt, { timeoutSec: 1200 });
  const j = parseJson(r.text) || {};
  const edits = [];
  for (const e of Array.isArray(j.edits) ? j.edits : []) {
    const abs = safePath(e?.path);
    if (!abs || typeof e.content !== 'string') continue;
    if (e.content.length > MAX_FILE) continue;
    edits.push({ rel: path.relative(ROOT, abs), abs, content: e.content });
  }
  return { edits, note: typeof j.note === 'string' ? j.note.slice(0, 400) : '', tps: r.tps };
}

export async function runCycle({ db, id = 0, next = false, apply = false, dry = false, verify = '', model = MODEL, limitSteps = 1 }) {
  if (model && model !== MODEL) process.env.LSRE_CYCLE_MODEL = model;
  let task = id ? db.prepare('SELECT * FROM tasks WHERE id = ?').get(id) : null;
  if (!task && next) {
    task = db.prepare(`SELECT * FROM tasks WHERE status='queued'
      ORDER BY CASE priority WHEN 'P0' THEN 0 WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 ELSE 4 END, id LIMIT 1`).get();
  }
  if (!task) return { ok: false, error: 'задача не найдена', applied: false };
  if (task.status === 'done' || task.status === 'failed') return { ok: false, error: `задача уже ${task.status}`, applied: false };

  const cls = triageLocal(task);
  const atStage = (stage) => db.prepare('SELECT stage FROM tasks WHERE id = ?').get(task.id)?.stage === stage;
  const advanceTo = async (stage) => {
    const order = ['triage', 'plan', 'apply'];
    for (let i = 0; i < 3; i += 1) {
      const cur = db.prepare('SELECT stage FROM tasks WHERE id = ?').get(task.id)?.stage;
      if (cur === stage || order.indexOf(cur) >= order.indexOf(stage)) break;
      await factory.action(db, { op: 'advance', id: task.id }, {});
    }
  };
  if (!dry) {
    await factory.action(db, { op: 'claim', id: task.id }, {});
    await advanceTo('plan');
  }
  const plan = await planLocal(task);
  if (!dry) await advanceTo('apply');

  const verifyCmd = verify || plan.verify || 'node lsre-lite/test.mjs';
  const attemptsMax = apply && !dry ? 3 : 1;
  const result = { ok: false, applied: false, task: task.id, cls, plan, edits: [], note: '', model, verifyCmd, attempts: [] };

  let lastError = '';
  for (let attempt = 1; attempt <= attemptsMax; attempt += 1) {
    const proposal = await proposeLocal(task, plan, lastError);
    result.edits = proposal.edits.map((e) => e.rel);
    result.note = proposal.note;
    result.tps = { ...(result.tps || {}), plan: plan.tps, apply: proposal.tps, [`испыт${attempt}`]: proposal.tps };
    if (proposal.edits.length === 0) { lastError = `попытка ${attempt}: модель не предложила правок`; continue; }
    if (dry) { result.ok = true; result.applied = false; result.note = proposal.note || 'пробный прогон'; return result; }

    // Бэкап (по правилу проекта) + снимок в памяти для гарантированного откката.
    const backups = [];
    for (const e of proposal.edits) {
      const before = fs.existsSync(e.abs) ? fs.readFileSync(e.abs) : null;
      const b = await backup(e.abs);
      backups.push({ ...e, backup: b.dir, before });
      fs.mkdirSync(path.dirname(e.abs), { recursive: true });
      fs.writeFileSync(e.abs, e.content, 'utf8');
    }
    result.applied = true;

    const v = await runCmd(verifyCmd);
    const tail = v.out.trim().split('\n').slice(-10).join('\n');
    result.attempts.push({ attempt, exit: v.code, tail: tail.slice(0, 400) });
    if (v.code === 0) {
      await factory.action(db, { op: 'done', id: task.id, result: result.note || 'правки применены', evidence: `verify: ${verifyCmd} → exit 0 (попытка ${attempt})\n${tail}` }, {});
      result.ok = true;
      result.attempt = attempt;
      return result;
    }

    // откат и сигнал модели, что именно не так
    for (const b of backups) {
      try {
        if (b.before === null) fs.rmSync(b.abs, { force: true });
        else fs.writeFileSync(b.abs, b.before);
      } catch { /* фиксируем ниже общим сообщением */ }
    }
    lastError = `exit ${v.code}\n${tail}`;
    result.applied = false;
  }

  await factory.action(db, { op: 'fail', id: task.id, error: `проверка не прошла после ${attemptsMax} попыток: ${(lastError || '').slice(0, 500)}` }, {});
  result.ok = false;
  result.lastError = lastError;
  return result;
}

if (process.argv[1] && process.argv[1].endsWith('cycle.mjs')) {
  const a = process.argv.slice(2);
  const argOf = (n, d = '') => { const i = a.indexOf(n); return i >= 0 && a[i + 1] && !a[i + 1].startsWith('--') ? a[i + 1] : d; };
  const dbPath = argOf('--db') || path.join(ROOT, 'lsre-memory', 'factory.db');
  const db = factory.openFactory(dbPath);
  const res = await runCycle({
    db,
    id: Number(argOf('--id', '0')) || 0,
    next: a.includes('--next'),
    apply: a.includes('--apply'),
    dry: a.includes('--dry'),
    verify: argOf('--verify', ''),
    model: argOf('--model', MODEL),
  });
  console.log(JSON.stringify(res, null, 2));
  process.exit(res.ok ? 0 : 1);
}
