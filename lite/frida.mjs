// frida.mjs — тонкая обёртка над единственной копией frida (та же, что грузит сервер).
// Ленивая загрузка: сервер стартует и без frida; прогрев = первый вызов, без двойников.
let frida = null;

async function load() {
  if (!frida) {
    const mod = await import('frida');
    // frida 17 — ESM: берём default-модуль (attach/spawn/getLocalDevice).
    frida = mod.default ?? mod;
  }
  return frida;
}

export async function listProcesses() {
  const F = await load();
  // В frida 17 перечисление процессов — через устройство, scope minimal.
  const device = await F.getLocalDevice();
  const processes = await device.enumerateProcesses({ scope: 'minimal' });
  return processes
    .map((p) => ({ pid: p.pid, name: p.name }))
    .sort((a, b) => String(a.name).localeCompare(String(b.name)))
    .slice(0, 400);
}

export async function listModules(target) {
  const F = await load();
  const session = await F.attach(Number.isFinite(Number(target)) ? Number(target) : String(target));
  try {
    // В frida 17 host-API перечисления модулей нет — спрашиваем у агента внутри процесса.
    const modules = [];
    const script = await session.createScript(`
      send(JSON.stringify(Process.enumerateModules().slice(0, 200).map(function (m) {
        return { name: m.name, base: String(m.base), size: m.size, path: m.path };
      })));
    `);
    script.message.connect((msg) => {
      if (msg.type === 'send') { try { modules.push(...JSON.parse(msg.payload)); } catch { /* битый ответ агента */ } }
    });
    await script.load();
    await new Promise((resolve) => setTimeout(resolve, 800));
    await script.unload();
    return modules.slice(0, 200);
  } finally {
    await session.detach().catch(() => {});
  }
}

export async function runScript({ script, target, mode = 'attach', timeoutMs = 8000 }) {
  const F = await load();
  let session;
  let spawned = false;
  const numeric = Number.isFinite(Number(target));
  if (mode === 'spawn' && !numeric) {
    session = await F.spawn(String(target));
    spawned = true;
  } else {
    session = await F.attach(numeric ? Number(target) : String(target));
  }
  const messages = [];
  let scriptError = null;
  try {
    const s = await session.createScript(String(script).slice(0, 20000));
    s.message.connect((msg, data) => {
      messages.push({
        type: msg.type,
        payload: msg.payload === undefined ? undefined : JSON.stringify(msg.payload).slice(0, 2000),
        data: data ? String(data).slice(0, 400) : undefined,
      });
    });
    await s.load();
    if (spawned) await session.resume();
    await new Promise((resolve) => setTimeout(resolve, Math.max(100, Math.min(60000, Number(timeoutMs) || 8000))));
    await s.unload();
  } catch (error) {
    scriptError = error?.message ?? String(error);
  }
  await session.detach().catch(() => {});
  return { ok: scriptError === null, error: scriptError, messages: messages.slice(0, 40) };
}
