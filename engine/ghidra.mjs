// ghidra.mjs — диспетчер Ghidra headless: импорт с кэшем проекта + экспорт через ghidra_export.java.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
// Ghidra — внешняя программа: путь берём из GHIDRA_INSTALL_DIR (или LSRE_GHIDRA_DIR),
// а если не задан — ищем рядом с типичными местами установки. Никаких путей разработчика.
function findGhidra() {
  const fromEnv = process.env.GHIDRA_INSTALL_DIR || process.env.LSRE_GHIDRA_DIR;
  if (fromEnv && fs.existsSync(path.join(fromEnv, 'support'))) return fromEnv;
  const roots = [
    process.env.ProgramFiles, process.env['ProgramFiles(x86)'], process.env.LOCALAPPDATA,
    process.env.USERPROFILE, 'C:\\',
  ].filter(Boolean);
  for (const root of roots) {
    let entries = [];
    try { entries = fs.readdirSync(root); } catch { continue; }
    for (const name of entries) {
      if (!/^ghidra/i.test(name)) continue;
      const candidate = path.join(root, name);
      if (fs.existsSync(path.join(candidate, 'support'))) return candidate;
    }
  }
  return '';
}
const GHIDRA = findGhidra();
const PROJECTS = process.env.GHIDRA_PROJECTS
  || path.join(process.env.LOCALAPPDATA || os.tmpdir(), 'lsre-lite', 'ghidra-projects');

const escArg = (value) => String(value).replace(/"/g, '').slice(0, 200);

function runHeadless(file, mode, arg, fresh) {
  if (!GHIDRA) {
    return { ok: false, error: 'Ghidra не найдена: задайте GHIDRA_INSTALL_DIR (папка с support/ и Ghidra/)' };
  }
  const support = path.join(GHIDRA, 'support');
  const launcher = path.join(GHIDRA, 'Ghidra', 'Framework', 'Utility', 'lib', 'Utility.jar');
  const javaHome = process.env.JAVA_HOME || '';
  const javaFromHome = javaHome ? path.join(javaHome, 'bin', 'java.exe') : '';
  const java = javaFromHome && fs.existsSync(javaFromHome) ? javaFromHome : 'java';
  if (!fs.existsSync(launcher)) return { ok: false, error: `Ghidra не найдена: ${launcher}` };
  if (java !== 'java' && !fs.existsSync(java)) return { ok: false, error: `Java не найдена: ${java} (нужен JAVA_HOME)` };
  const sha = crypto.createHash('sha1').update(file + ':' + (fs.existsSync(file) ? fs.statSync(file).size : 0)).digest('hex').slice(0, 12);
  const projDir = path.join(PROJECTS, sha);
  const projName = 'p';
  const base = path.basename(file);
  fs.mkdirSync(projDir, { recursive: true });
  let headlessArgs;
  if (fresh || !fs.existsSync(path.join(projDir, projName + '.rep'))) {
    headlessArgs = [projDir, projName, '-import', file, '-overwrite',
      '-scriptPath', HERE, '-postScript', 'ghidra_export.java', mode, arg];
  } else {
    headlessArgs = [projDir, projName, '-process', base, '-noanalysis',
      '-scriptPath', HERE, '-postScript', 'ghidra_export.java', mode, arg];
  }
  // Прямой запуск java: ghidra.Ghidra поднимает headless; нужен системный class loader.
  const args = ['-Djava.system.class.loader=ghidra.GhidraClassLoader', '-cp', launcher,
    'ghidra.Ghidra', 'ghidra.app.util.headless.AnalyzeHeadless', ...headlessArgs];
  const started = Date.now();
  const run = spawnSync(java, args, {
    cwd: support,
    encoding: 'utf8',
    timeout: 12 * 60 * 1000,
    maxBuffer: 128 * 1024 * 1024,
    env: { ...process.env, JAVA_HOME: javaHome, GHIDRA_INSTALL_DIR: GHIDRA },
  });
  const out = String(run.stdout ?? '');
  const BEGIN = '===JSON_BEGIN===';
  const END = '===JSON_END===';
  const begin = out.indexOf(BEGIN);
  const end = out.indexOf(END);
  if (begin === -1 || end === -1) {
    const tail = String(run.stderr ?? '').split('\n').slice(-6).join(' | ').slice(0, 600);
    return { ok: false, error: `Ghidra не вернул JSON${run.error ? ` (${run.error.message})` : ''}`, tail };
  }
  let data;
  try { data = JSON.parse(out.slice(begin + BEGIN.length, end)); } catch (parseError) {
    const offset = Number(/(\d+)/.exec(String(parseError.message))?.[1] ?? 0);
    return {
      ok: false, error: `битый JSON от Ghidra: ${parseError.message.slice(0, 80)}`,
      snippet: out.slice(begin + BEGIN.length + Math.max(0, offset - 60), begin + BEGIN.length + offset + 60),
    };
  }
  return { ok: true, ms: Date.now() - started, project: sha, data };
}

export function ghidraQuery(file, mode, arg = '') {
  if (!fs.existsSync(file)) return { ok: false, error: `файл не найден: ${file}` };
  let result = runHeadless(file, mode, escArg(arg), false);
  if (!result.ok && /JSON|Ghidra не/.test(result.error)) {
    // Проекта нет или он битый — полный импорт заново.
    result = runHeadless(file, mode, escArg(arg), true);
  }
  return result;
}
