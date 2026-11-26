// CLI-шов для приложения LSRE: очередь и полный цикл из одного процесса.
// Приложение вызывает этот файл и читает JSON из stdout — логика остаётся одна (factory.mjs/cycle.mjs).
//   node factory-cli.mjs --op list
//   node factory-cli.mjs --op enqueue --title "..."
//   node factory-cli.mjs --op claim|advance|done|fail|triage|dedupe --id N [--evidence "..."] [--result "..."]
//   node factory-cli.mjs --op cycle --id N --apply --verify "node lsre-lite/test.mjs"
import path from 'node:path';
import * as factory from './factory.mjs';
import * as cycle from './cycle.mjs';

const args = process.argv.slice(2);
const argOf = (name, fallback = '') => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : fallback;
};
const has = (name) => args.includes(name);

const dbPath = process.env.FACTORY_DB || argOf('--db')
  || path.join('D:\\WORK\\SMART BUILDER', 'lsre-memory', 'factory.db');

const out = (payload) => { process.stdout.write(JSON.stringify(payload) + '\n'); };

try {
  const db = factory.openFactory(dbPath);
  const op = argOf('--op', 'list');
  const id = Number(argOf('--id', '0')) || 0;

  if (op === 'list') {
    out({ ok: true, db: dbPath, ...factory.describe(db, { status: argOf('--status', '') || null, stage: argOf('--stage', '') || null }) });
  } else if (op === 'stats') {
    const s = factory.describe(db, {});
    out({ ok: true, db: dbPath, total: s.total, byStatus: s.byStatus, byStage: s.byStage });
  } else if (op === 'cycle') {
    const res = await cycle.runCycle({
      db, id, next: has('--next'), apply: has('--apply'), dry: has('--dry'),
      verify: argOf('--verify', ''), model: argOf('--model', ''),
    });
    out({ ...res, db: dbPath });
  } else {
    const body = {
      op, id,
      title: argOf('--title', ''), note: argOf('--note', ''),
      result: argOf('--result', ''), evidence: argOf('--evidence', ''),
      error: argOf('--error', ''), kind: argOf('--kind', ''), priority: argOf('--priority', ''),
      threshold: Number(argOf('--threshold', '0')) || undefined,
    };
    const res = await factory.action(db, body, {});
    out({ ...res, db: dbPath });
  }
} catch (error) {
  out({ ok: false, error: error?.message ?? String(error), db: dbPath });
  process.exitCode = 1;
}
