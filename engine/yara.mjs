// YARA-X: скан файла правилами (свои + дополнительные). Бинарник yr.exe рядом, BSD-3.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const YR = path.join(here, 'tools', 'yara-x', 'yr.exe');
const DEFAULT_RULES = path.join(here, 'rules.yar');

export function yaraStatus() {
  return { engine: 'YARA-X (yr.exe)', binary: YR, present: fs.existsSync(YR), rules: fs.existsSync(DEFAULT_RULES), default_rules: DEFAULT_RULES };
}

function run(args, timeoutMs) {
  return new Promise((resolve) => {
    const child = spawn(YR, args, { windowsHide: true });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => { try { child.kill(); } catch { /* уже */ } }, timeoutMs);
    child.stdout.on('data', (chunk) => { if (stdout.length < 1024 * 1024) stdout += chunk; });
    child.stderr.on('data', (chunk) => { if (stderr.length < 64 * 1024) stderr += chunk; });
    child.on('error', (error) => { clearTimeout(timer); resolve({ code: -1, stdout, stderr: String(error.message) }); });
    child.on('exit', (code) => { clearTimeout(timer); resolve({ code: code ?? -1, stdout, stderr }); });
  });
}

/** Скан: { ok, matches:[{rule,namespace,file,patterns}], count }. */
export async function yaraScan({ file, rules, timeoutMs = 20000 } = {}) {
  if (!fs.existsSync(YR)) return { ok: false, error: 'не найден yr.exe (tools/yara-x/yr.exe)' };
  if (!file || !fs.existsSync(file)) return { ok: false, error: `файл не найден: ${file ?? ''}` };
  const rulesPath = rules && fs.existsSync(rules) ? rules : DEFAULT_RULES;
  if (!fs.existsSync(rulesPath)) return { ok: false, error: `правила не найдены: ${rulesPath}` };
  const result = await run(['scan', rulesPath, file, '--output-format=json', '--max-matches-per-pattern=5'], timeoutMs);
  if (!result.stdout.trim()) {
    return { ok: result.code === 0, code: result.code, count: 0, matches: [], stderr: result.stderr.slice(0, 400), rules: rulesPath };
  }
  try {
    const parsed = JSON.parse(result.stdout);
    // YARA-X 1.22 отдаёт {"version": "...", "matches":[{"rule","file"}]}
    const raw = Array.isArray(parsed?.matches) ? parsed.matches
      : Array.isArray(parsed) ? parsed
        : Array.isArray(parsed?.events) ? parsed.events.map((e) => e?.data ?? e) : [];
    const matches = [];
    for (const item of raw) {
      if (!item) continue;
      const rule = typeof item.rule === 'string' ? item.rule : item.rule?.identifier;
      if (!rule) continue;
      matches.push({
        rule,
        namespace: typeof item.rule === 'object' ? (item.rule?.namespace ?? null) : (item.namespace ?? null),
        file: item.file ?? file,
        patterns: (item.patterns ?? []).slice(0, 10).map((p) => ({
          id: p.identifier ?? p.id,
          offsets: (p.matches ?? []).slice(0, 5).map((m) => m.offset ?? m),
        })),
      });
    }
    return { ok: true, count: matches.length, matches: matches.slice(0, 50), rules: rulesPath, truncated: matches.length > 50 };
  } catch (error) {
    return { ok: false, error: `разбор вывода yr: ${error.message}`, bytes: result.stdout.length };
  }
}
