// LSRE-lite: быстрый триаж без зависимостей.
// Читаем только нужные смещения через fd — файл целиком в память не грузим.
import fs from 'node:fs';
import crypto from 'node:crypto';

const MAX_DLLS = 128;
const MAX_FUNCS_PER_DLL = 10;
const MAX_EXPORTS = 40;
const MAX_SECTION_BYTES = 16 * 1024 * 1024;

export class Reader {
  constructor(path) {
    this.path = path;
    this.fd = fs.openSync(path, 'r');
    this.size = fs.fstatSync(this.fd).size;
  }
  read(offset, length) {
    if (offset < 0 || length <= 0 || offset >= this.size) return Buffer.alloc(0);
    const want = Math.min(length, this.size - offset);
    const buf = Buffer.allocUnsafe(want);
    let got = 0;
    while (got < want) {
      const n = fs.readSync(this.fd, buf, got, want - got, offset + got);
      if (n <= 0) break;
      got += n;
    }
    return got === want ? buf : buf.subarray(0, got);
  }
  close() {
    try { fs.closeSync(this.fd); } catch { /* уже закрыт */ }
  }
}

const u16 = (b, o) => (o + 2 <= b.length ? b.readUInt16LE(o) : 0);
const u32 = (b, o) => (o + 4 <= b.length ? b.readUInt32LE(o) : 0);
const i32 = (b, o) => (o + 4 <= b.length ? b.readInt32LE(o) : 0);
const u64 = (b, o) => (o + 8 <= b.length ? Number(b.readBigUInt64LE(o)) : 0);

export function entropy(buf) {
  if (!buf.length) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < buf.length; i += 1) counts[buf[i]] += 1;
  let h = 0;
  for (let i = 0; i < 256; i += 1) {
    if (!counts[i]) continue;
    const p = counts[i] / buf.length;
    h -= p * Math.log2(p);
  }
  return Math.round(h * 100) / 100;
}

// Управляющие символы и bidi-переопределения не должны доезжать до модели.
export const cleanText = (value, max = 200) => String(value ?? '')
  .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069]/g, '')
  .slice(0, max);

const MACHINE = {
  0x0: 'unknown', 0x14c: 'x86', 0x8664: 'x86_64', 0x1c0: 'arm', 0x1c4: 'arm', 0xaa64: 'arm64',
  0x200: 'ia64', 0x5032: 'riscv32', 0x5064: 'riscv64', 0x1a2: 'sh', 0x166: 'mips',
};

const SUBSYSTEM = {
  1: 'native', 2: 'gui', 3: 'console', 5: 'os2', 7: 'posix', 9: 'win-ce', 10: 'efi-app',
  11: 'efi-boot', 12: 'efi-rom', 14: 'xbox',
};

const DLL_FLAGS = [
  [0x0020, 'high-entropy-va'], [0x0040, 'dynamic-base'], [0x0080, 'force-integrity'],
  [0x0100, 'nx-compat'], [0x0200, 'no-isolation'], [0x0400, 'no-seh'], [0x0800, 'no-bind'],
  [0x1000, 'app-container'], [0x2000, 'wdm-driver'], [0x4000, 'guard-cf'], [0x8000, 'terminal-server'],
];

const PACKER_SECTIONS = [
  ['.UPX0', 'UPX'], ['.UPX1', 'UPX'], ['.UPX2', 'UPX'], ['UPX0', 'UPX'], ['UPX1', 'UPX'],
  ['.MPRESS1', 'MPRESS'], ['.MPRESS2', 'MPRESS'], ['.aspack', 'ASPack'], ['.adata', 'ASPack'],
  ['.ASPack', 'ASPack'], ['.petite', 'Petite'], ['.nsp0', 'NsPack'], ['.nsp1', 'NsPack'],
  ['.vmp0', 'VMProtect'], ['.vmp1', 'VMProtect'], ['.themida', 'Themida'], ['.enigma1', 'Enigma'],
  ['.boom', 'Themida'], ['.perplex', 'Perplex'], ['.packed', 'packed'],
];

const toOffset = (sections, rva, headerSize) => {
  if (rva < headerSize) return rva;
  for (const s of sections) {
    const span = Math.max(s.vsize, s.raw_size);
    if (rva >= s.va && rva < s.va + span) {
      const delta = rva - s.va;
      return delta < s.raw_size ? s.raw_ptr + delta : -1;
    }
  }
  return -1;
};

const flagsOf = (value, table) => table.filter(([bit]) => value & bit).map(([, name]) => name);

// ---------- PE ----------
function triagePE(reader, sheet, ctx) {
  const { errors, limits } = ctx;
  const dos = reader.read(0, 0x40);
  const peOff = u32(dos, 0x3c);
  if (peOff < 0x40 || peOff + 24 > reader.size) {
    sheet.type = 'unknown-mz';
    errors.push('PE: битое e_lfanew');
    return;
  }
  const sig = reader.read(peOff, 4);
  if (sig.toString('latin1') !== 'PE\0\0') {
    sheet.type = 'dos-exe';
    sheet.note = 'MZ без PE-заголовка (DOS-программа)';
    return;
  }
  const coff = reader.read(peOff + 4, 20);
  const machine = u16(coff, 0);
  const sectionCount = u16(coff, 2);
  const stamp = u32(coff, 4);
  const optSize = u16(coff, 16);
  const characteristics = u16(coff, 18);

  const opt = reader.read(peOff + 24, Math.min(optSize || 240, 512));
  const magic = u16(opt, 0);
  const is64 = magic === 0x20b;
  const bits = is64 ? 64 : magic === 0x10b ? 32 : 0;
  const entryRva = u32(opt, 16);
  const imageBase = is64 ? u64(opt, 24) : u32(opt, 28);
  const subsystem = u16(opt, 68);
  const dllFlags = u16(opt, 70);
  const ddBase = is64 ? 112 : 96;
  const ddCount = u32(opt, is64 ? 108 : 92);
  const dir = (index) => ({ rva: u32(opt, ddBase + index * 8), size: u32(opt, ddBase + index * 8 + 4) });
  const dirs = { export: dir(0), import: dir(1), resource: dir(2), reloc: dir(5), debug: dir(6), tls: dir(9), clr: dir(14), security: dir(4) };

  const sections = [];
  const rawSections = reader.read(peOff + 24 + (optSize || 240), sectionCount * 40);
  for (let i = 0; i < sectionCount; i += 1) {
    const o = i * 40;
    if (o + 40 > rawSections.length) break;
    const name = cleanText(rawSections.subarray(o, o + 8).toString('latin1').replace(/\0+$/, ''), 8);
    const vsize = u32(rawSections, o + 8);
    const va = u32(rawSections, o + 12);
    const rawSize = u32(rawSections, o + 16);
    const rawPtr = u32(rawSections, o + 20);
    const chars = u32(rawSections, o + 36);
    sections.push({ name, vsize, va, raw_size: rawSize, raw_ptr: rawPtr, flags: chars });
  }

  sheet.type = 'pe';
  sheet.arch = MACHINE[machine] ?? `machine-0x${machine.toString(16)}`;
  sheet.bits = bits;
  sheet.subsystem = SUBSYSTEM[subsystem] ?? String(subsystem);
  sheet.dll_characteristics = flagsOf(dllFlags, DLL_FLAGS);
  sheet.dll = Boolean(characteristics & 0x2000);
  sheet.entry_rva = entryRva;
  sheet.image_base = imageBase;
  sheet.timestamp_utc = stamp > 0 && new Date(stamp * 1000).getUTCFullYear() > 1990 && stamp * 1000 < Date.now() + 86400000
    ? new Date(stamp * 1000).toISOString() : null;

  const vaCandidates = sections.map((s) => s.va).filter((v) => v > 0);
  const headerSize = vaCandidates.length ? Math.min(...vaCandidates, 0x1000) : 0x1000;
  const rvaToOffset = (rva) => toOffset(sections, rva, headerSize);

  // Секции: энтропия по фактическим байтам, не по заголовку.
  const display = [];
  for (const s of sections) {
    const length = Math.min(s.raw_size, MAX_SECTION_BYTES);
    const data = length > 0 ? reader.read(s.raw_ptr, length) : Buffer.alloc(0);
    s.ent = entropy(data);
    if (s.raw_size > MAX_SECTION_BYTES) limits.push(`энтропия ${s.name}: прочитано ${MAX_SECTION_BYTES} из ${s.raw_size}`);
    display.push({
      name: s.name,
      ent: s.ent,
      raw: s.raw_size,
      ratio: s.vsize > 0 && s.raw_size > 0 ? Math.round((s.vsize / s.raw_size) * 100) / 100 : null,
    });
  }
  sheet.sections = display;

  // Импорты: имена функций, а не только DLL.
  const imports = { count: 0, dlls: [], funcs: 0, sample: [] };
  try {
    let desc = dirs.import.rva;
    for (let i = 0; i < MAX_DLLS && desc; i += 1) {
      const off = rvaToOffset(desc);
      if (off < 0) break;
      const d = reader.read(off, 20);
      if (d.length < 20) break;
      const originalThunk = u32(d, 0);
      const nameRva = u32(d, 12);
      const firstThunk = u32(d, 16);
      if (!nameRva && !firstThunk) break;
      const nameOff = rvaToOffset(nameRva);
      const dllName = nameOff >= 0 ? cleanText(reader.read(nameOff, 128).toString('latin1').split('\0')[0], 64) : `rva:0x${nameRva.toString(16)}`;
      imports.dlls.push(dllName);
      const thunkRva = originalThunk || firstThunk;
      const funcs = [];
      const thunkSize = is64 ? 8 : 4;
      let thunkOff = rvaToOffset(thunkRva);
      for (let t = 0; t < 2000 && thunkOff >= 0; t += 1) {
        const raw = reader.read(thunkOff, thunkSize);
        if (raw.length < thunkSize) break;
        // 64-битные значения через BigInt: побитовые операции над Number режутся до int32.
        const value = is64 ? raw.readBigUInt64LE(0) : BigInt(raw.readUInt32LE(0));
        if (value === 0n) break;
        const byOrdinal = is64 ? Boolean(value & 0x8000000000000000n) : Boolean(value & 0x80000000n);
        if (byOrdinal) {
          funcs.push(`#${Number(value & 0xffffn)}`);
        } else {
          const hintOff = rvaToOffset(Number(value) + 2);
          const fnName = hintOff >= 0 ? cleanText(reader.read(hintOff, 96).toString('latin1').split('\0')[0], 64) : null;
          if (fnName) funcs.push(fnName);
        }
        thunkOff += thunkSize;
      }
      imports.count += 1;
      imports.funcs += funcs.length;
      if (funcs.length && imports.sample.length < MAX_DLLS * MAX_FUNCS_PER_DLL) {
        imports.sample.push({ dll: dllName, funcs: funcs.slice(0, MAX_FUNCS_PER_DLL), total: funcs.length });
      }
      desc += 20;
    }
    if (imports.count >= MAX_DLLS) limits.push(`импорт: показаны первые ${MAX_DLLS} DLL`);
  } catch (error) { errors.push(`импорт: ${error.message}`); }
  sheet.imports = imports;

  // Экспорты.
  const exports = { count: 0, names: [] };
  try {
    if (dirs.export.rva && dirs.export.size) {
      const off = rvaToOffset(dirs.export.rva);
      const d = off >= 0 ? reader.read(off, 40) : Buffer.alloc(0);
      if (d.length >= 40) {
        exports.count = u32(d, 20);
        const namesRva = u32(d, 32);
        const namesOff = rvaToOffset(namesRva);
        if (namesOff >= 0) {
          const table = reader.read(namesOff, Math.min(exports.count, MAX_EXPORTS) * 4);
          for (let i = 0; i + 4 <= table.length; i += 4) {
            const nOff = rvaToOffset(u32(table, i));
            if (nOff < 0) continue;
            const nm = cleanText(reader.read(nOff, 128).toString('latin1').split('\0')[0], 96);
            if (nm) exports.names.push(nm);
          }
        }
      }
    }
  } catch (error) { errors.push(`экспорт: ${error.message}`); }
  sheet.exports = exports;

  // PDB из CodeView.
  sheet.pdb = null;
  try {
    if (dirs.debug.rva && dirs.debug.size) {
      const off = rvaToOffset(dirs.debug.rva);
      const d = off >= 0 ? reader.read(off, 28) : Buffer.alloc(0);
      if (d.length >= 28) {
        const dataSize = u32(d, 16);
        const dataPtr = u32(d, 24);
        const cv = reader.read(dataPtr, Math.min(dataSize, 1024));
        if (cv.subarray(0, 4).toString('latin1') === 'RSDS' && cv.length > 24) {
          sheet.pdb = cleanText(cv.subarray(24).toString('latin1').split('\0')[0], 180);
        }
      }
    }
  } catch (error) { errors.push(`debug: ${error.message}`); }

  // Rich header: ищем маркер, ключ и расшифровываем назад до DanS.
  sheet.rich = null;
  try {
    const head = reader.read(0x40, Math.max(0, peOff - 0x40));
    const richAt = head.lastIndexOf('Rich', undefined, 'latin1');
    if (richAt >= 8) {
      const key = head.readUInt32LE(richAt + 4);
      let danS = -1;
      for (let p = richAt - 4; p >= 0; p -= 4) {
        if ((head.readUInt32LE(p) ^ key) === 0x536e6144) { danS = p; break; }
      }
      if (danS >= 0) {
        const entries = [];
        for (let p = danS + 16; p + 8 <= richAt; p += 8) {
          const compid = head.readUInt32LE(p) ^ key;
          const count = head.readUInt32LE(p + 4) ^ key;
          entries.push({ product: (compid >>> 16) & 0xffff, build: compid & 0xffff, count });
        }
        sheet.rich = {
          entries: entries.length,
          sample: entries.slice(0, 8).map((e) => `p${e.product}/b${e.build}x${e.count}`),
        };
      }
    }
  } catch (error) { errors.push(`rich: ${error.message}`); }

  // TLS-callbacks: VA -> RVA -> файл.
  sheet.tls_callbacks = 0;
  try {
    if (dirs.tls.rva) {
      const off = rvaToOffset(dirs.tls.rva);
      const d = off >= 0 ? reader.read(off, is64 ? 40 : 32) : Buffer.alloc(0);
      if (d.length >= (is64 ? 40 : 32)) {
        const callbacksVa = is64 ? u64(d, 24) : u32(d, 12);
        if (callbacksVa && callbacksVa >= imageBase) {
          const cbOff = rvaToOffset(callbacksVa - imageBase);
          const ptrSize = is64 ? 8 : 4;
          const arr = cbOff >= 0 ? reader.read(cbOff, ptrSize * 16) : Buffer.alloc(0);
          for (let i = 0; i + ptrSize <= arr.length; i += ptrSize) {
            const va = is64 ? u64(arr, i) : u32(arr, i);
            if (!va) break;
            sheet.tls_callbacks += 1;
          }
        }
      }
    }
  } catch (error) { errors.push(`tls: ${error.message}`); }

  // Подпись Authenticode: наличие, размер, тип сертификата + подписант из PKCS7.
  sheet.signature = { present: false };
  try {
    if (dirs.security.size > 0) {
      const hdr = reader.read(dirs.security.rva, 8);
      if (hdr.length >= 8) {
        const revision = u16(hdr, 4) === 0x0200 ? '2.0' : `0x${u16(hdr, 4).toString(16)}`;
        const type = u16(hdr, 6) === 0x0002 ? 'pkcs7' : `0x${u16(hdr, 6).toString(16)}`;
        sheet.signature = { present: true, size: dirs.security.size, revision, type };
        const blob = reader.read(dirs.security.rva + 8, Math.min(dirs.security.size - 8, 2 << 20));
        Object.assign(sheet.signature, parsePkcs7(blob));
      } else {
        sheet.signature = { present: true, size: dirs.security.size, revision: null, type: null };
      }
    }
  } catch (error) { errors.push(`signature: ${error.message}`); }

  // Ресурсы: типы, версия, манифест, иконки.
  try {
    if (dirs.resource.size > 0) triageResources(reader, dirs, rvaToOffset, sheet, { errors });
  } catch (error) { errors.push(`resources: ${error.message}`); }

  // Overlay и точка входа вне секций.
  const rawEnd = sections.reduce((max, s) => Math.max(max, s.raw_ptr + s.raw_size), 0);
  sheet.overlay = reader.size > rawEnd && rawEnd > 0 ? reader.size - rawEnd : 0;
  const epSection = sections.find((s) => entryRva >= s.va && entryRva < s.va + Math.max(s.raw_size, s.vsize));
  sheet.entry_section = epSection?.name ?? null;
  sheet.entry_outside = !epSection;

  // Упаковщик: имена секций + энтропия + мало импортов + EP вне кода.
  const evidence = [];
  const named = PACKER_SECTIONS.find(([name]) => sections.some((s) => s.name.toLowerCase() === name.toLowerCase()));
  if (named) evidence.push(`секция ${named[0]}`);
  const highEnt = sections.filter((s) => s.ent >= 7.2 && s.raw > 4096);
  if (highEnt.length) evidence.push(`энтропия ${highEnt.map((s) => `${s.name}:${s.ent}`).join(', ')}`);
  if (imports.count > 0 && imports.count <= 2) evidence.push(`всего ${imports.count} DLL в импорте`);
  if (sheet.entry_outside) evidence.push('точка входа вне секций');
  if (sheet.overlay > 0 && sheet.overlay > reader.size * 0.2) evidence.push(`overlay ${Math.round(sheet.overlay / 1024)} КБ`);
  const confidence = Math.min(1, Math.round((evidence.length / 4) * 100) / 100);
  sheet.packer = { name: named ? named[1] : (confidence >= 0.75 ? 'unknown-packer' : null), confidence, evidence };

  sheet.dirs = {
    import: dirs.import.size, export: dirs.export.size, resource: dirs.resource.size,
    reloc: dirs.reloc.size, debug: dirs.debug.size, tls: dirs.tls.size,
    clr: dirs.clr.size, security: dirs.security.size,
  };
  sheet.is_dotnet = dirs.clr.size > 0;
  sheet.has_tls = Boolean(dirs.tls.rva);
  if (ddCount < 16) limits.push(`каталогов данных ${ddCount} из 16 — старый PE`);
}

// ---------- прочие форматы ----------
function triageELF(reader, sheet, ctx) {
  const { errors } = ctx;
  const h = reader.read(0, 64);
  const is64 = h[4] === 2;
  const le = h[5] === 1;
  if (!le) { sheet.note = 'big-endian ELF: поддерживается только заголовок'; }
  const type = (off) => (le ? h.readUInt16LE(off) : h.readUInt16BE(off));
  const word = (off) => (le ? h.readUInt32LE(off) : h.readUInt32BE(off));
  const addr = (off) => (is64 ? Number(le ? h.readBigUInt64LE(off) : h.readBigUInt64BE(off)) : word(off));
  const machine = type(18);
  sheet.type = 'elf';
  sheet.arch = { 3: 'x86', 62: 'x86_64', 40: 'arm', 183: 'arm64', 243: 'riscv64', 8: 'mips' }[machine] ?? `machine-${machine}`;
  sheet.bits = is64 ? 64 : 32;
  sheet.entry = addr(24);
  try {
    const shoff = is64 ? addr(40) : word(32);
    const shentsize = is64 ? h.readUInt16LE(58) : h.readUInt16LE(46);
    const shnum = is64 ? h.readUInt16LE(60) : h.readUInt16LE(48);
    const shstrndx = is64 ? h.readUInt16LE(62) : h.readUInt16LE(50);
    if (shoff && shnum && shnum < 4096) {
      const table = reader.read(shoff, shentsize * shnum);
      const strHeader = reader.read(shoff + shentsize * shstrndx, shentsize);
      const strTabOff = is64 ? Number(strHeader.readBigUInt64LE(24)) : strHeader.readUInt32LE(16);
      const strTabSize = is64 ? Number(strHeader.readBigUInt64LE(32)) : strHeader.readUInt32LE(20);
      const strTab = reader.read(strTabOff, Math.min(strTabSize, 1 << 20));
      const names = [];
      for (let i = 0; i < shnum; i += 1) {
        const o = i * shentsize;
        if (o + 32 > table.length) break;
        const nameOff = table.readUInt32LE(o);
        const nm = cleanText(strTab.subarray(nameOff, strTab.indexOf(0, nameOff) === -1 ? nameOff + 32 : strTab.indexOf(0, nameOff)).toString('latin1'), 40);
        names.push(nm);
      }
      sheet.sections = names.filter(Boolean).slice(0, 40);
    }
  } catch (error) { errors.push(`ELF sections: ${error.message}`); }
}

function triageMachO(reader, sheet) {
  const h = reader.read(0, 32);
  const magic = h.readUInt32BE(0);
  if (magic === 0xcafebabe) {
    sheet.type = 'macho-universal';
    sheet.slices = h.readUInt32BE(4);
    return;
  }
  const is64 = magic === 0xfeedfacf;
  sheet.type = 'macho';
  sheet.bits = is64 ? 64 : 32;
  const cputype = h.readUInt32LE(4);
  sheet.arch = { 7: 'x86', 0x01000007: 'x86_64', 12: 'arm', 0x0100000c: 'arm64' }[cputype] ?? `cpu-${cputype}`;
  sheet.filetype = ['object', 'exe', 'fvmlib', 'core', 'preload', 'dylib', 'dylinker', 'bundle', 'dylib_stub', 'dsym', 'kext'][h.readUInt32LE(12)] ?? 'unknown';
  const ncmds = h.readUInt32LE(16);
  const libs = [];
  let off = is64 ? 32 : 28;
  for (let i = 0; i < ncmds && i < 512; i += 1) {
    const cmd = reader.read(off, 8);
    if (cmd.length < 8) break;
    const type = cmd.readUInt32LE(0);
    const size = cmd.readUInt32LE(4);
    if (size < 8) break;
    if ((type === 0xc || type === 0xd) && size < 4096) {
      const data = reader.read(off, size);
      const nameOff = data.readUInt32LE(8);
      const nm = cleanText(data.subarray(nameOff).toString('latin1').split('\0')[0], 120);
      if (nm) libs.push(nm);
    } else if (type === 0x80000028 && size >= 24) {
      const body = reader.read(off, size);
      sheet.entry = Number(body.readBigUInt64LE(8));   // entryoff: смещение точки входа в файле
      sheet.stack_size = Number(body.readBigUInt64LE(16));
    }
    off += size;
  }
  sheet.libraries = libs.slice(0, 30);
}

function triageZip(reader, sheet, ctx) {
  const { errors } = ctx;
  const tailLen = Math.min(reader.size, 66 * 1024);
  const tail = reader.read(reader.size - tailLen, tailLen);
  let eocd = -1;
  for (let i = tail.length - 22; i >= 0; i -= 1) {
    if (tail.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) { ctx.limits.push('ZIP: EOCD не найден'); return; }
  const count = tail.readUInt16LE(eocd + 10);
  const cdSize = tail.readUInt32LE(eocd + 12);
  const cdOff = tail.readUInt32LE(eocd + 16);
  sheet.entries = count;
  const cd = reader.read(cdOff, Math.min(cdSize, 256 * 1024));
  const names = [];
  let p = 0;
  while (p + 46 <= cd.length && names.length < 200) {
    if (cd.readUInt32LE(p) !== 0x02014b50) break;
    const nameLen = cd.readUInt16LE(p + 28);
    const extraLen = cd.readUInt16LE(p + 30);
    const commentLen = cd.readUInt16LE(p + 32);
    const nm = cleanText(cd.subarray(p + 46, p + 46 + nameLen).toString('utf8'), 160);
    if (nm) names.push(nm);
    p += 46 + nameLen + extraLen + commentLen;
  }
  sheet.names = names.slice(0, 12);
  const lower = names.map((n) => n.toLowerCase());
  if (lower.includes('androidmanifest.xml')) sheet.type = 'apk';
  else if (lower.includes('meta-inf/manifest.mf')) sheet.type = 'jar';
  else if (lower.includes('word/document.xml') || lower.includes('ppt/presentation.xml') || lower.includes('xl/workbook.xml')) sheet.type = 'ooxml';
  else if (names.length && names.every((n) => n.startsWith('META-INF/') || n.includes('/'))) sheet.type = 'zip';
  if (!sheet.type) sheet.type = 'zip';
  const exe = names.filter((n) => /\.(exe|dll|scr|sys)$/i.test(n));
  if (exe.length) sheet.contains_executables = exe.slice(0, 8);
  void errors;
}

// ---------- PLN (ArchiCAD) ----------
// Контейнер начинается с ASCII-магии "ROF FDB"; структура проприетарная,
// поэтому честно сообщаем только измеренное, без догадок о версиях.
function triagePLN(reader, sheet) {
  const h = reader.read(0, 64);
  sheet.magic = h.subarray(0, 8).toString('latin1').trim();
  sheet.header_hex = h.subarray(8, 24).toString('hex');
  sheet.header_u32 = [u32(h, 8), u32(h, 12), u32(h, 16), u32(h, 20)];
  const probe = reader.read(0, Math.min(reader.size, 1 << 20));
  let zlibCount = 0;
  for (let i = 0; i + 1 < probe.length; i += 1) {
    if (probe[i] === 0x78 && (probe[i + 1] === 0x01 || probe[i + 1] === 0x9c || probe[i + 1] === 0xda)) zlibCount += 1;
  }
  let pkCount = 0;
  for (let i = 0; i + 3 < probe.length; i += 1) {
    if (probe[i] === 0x50 && probe[i + 1] === 0x4b && probe[i + 2] === 0x03 && probe[i + 3] === 0x04) pkCount += 1;
  }
  const latin = reader.read(0, Math.min(reader.size, 4 << 20)).toString('latin1');
  sheet.zlib_streams_1mb = zlibCount;
  sheet.zip_headers_1mb = pkCount;
  sheet.ifc_refs_4mb = latin.split('IFC').length - 1;
}

// ---------- PKCS7 (минимальный DER) ----------
const readTlvAt = (buf, pos) => {
  if (pos === undefined || pos < 0 || pos >= buf.length) return null;
  const tag = buf[pos];
  let p = pos + 1;
  if (p >= buf.length) return null;
  let len = buf[p];
  p += 1;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (p + n > buf.length) return null;
    len = 0;
    for (let i = 0; i < n; i += 1) len = len * 256 + buf[p + i];
    p += n;
  }
  if (p + len > buf.length) return null;
  return { tag, start: p, len, end: p + len };
};

const DIGEST_OIDS = {
  '2a864886f70d010105': 'sha1',
  '608648016503040201': 'sha256',
  '608648016503040202': 'sha384',
  '608648016503040203': 'sha512',
  '2a8648ce3d040303': 'sha384-ecdsa',
};

function derString(buf, tlv, encoding) {
  if (!tlv) return null;
  return cleanText(buf.subarray(tlv.start, tlv.end).toString(encoding ?? 'latin1').split('\0')[0], 120);
}

export function parsePkcs7(blob) {
  const out = { cert_count: 0, signer_cn: null, digest: null, signing_time: null };
  // Субъектный CN: OID 2.5.4.3 = 06 03 55 04 03. Первый сертификат идёт раньше
  // остальных структур; берём 2-е вхождение (1-е — issuer CN).
  const cns = [];
  let pos = 0;
  const cnOid = Buffer.from('0603550403', 'hex');
  while ((pos = blob.indexOf(cnOid, pos)) !== -1) {
    const tlv = readTlvAt(blob, pos + cnOid.length);
    if (tlv) {
      const value = [0x0c, 0x13, 0x16, 0x1e].includes(tlv.tag)
        ? blob.subarray(tlv.start, tlv.end).toString(tlv.tag === 0x0c ? 'utf8' : tlv.tag === 0x1e ? 'utf16be' : 'latin1').split('\0')[0]
        : null;
      if (value) cns.push(cleanText(value, 120));
    }
    pos += cnOid.length;
  }
  out.signer_cn = cns[1] ?? cns[0] ?? null;
  // Алгоритм дайджеста: OID sha1/sha256/… внутри signerInfos.
  for (const [oid, name] of Object.entries(DIGEST_OIDS)) {
    if (blob.includes(Buffer.from(oid, 'hex'))) { out.digest = name; break; }
  }
  // signingTime: OID 1.2.840.113549.1.9.5 = 06 09 2A 86 48 86 F7 0D 01 09 05, затем SET и время.
  const stOid = Buffer.from('06092a864886f70d010905', 'hex');
  const stPos = blob.indexOf(stOid);
  if (stPos !== -1) {
    let tlv = readTlvAt(blob, stPos + stOid.length);
    if (tlv && tlv.tag === 0x31) tlv = readTlvAt(blob, tlv.start);
    if (tlv && (tlv.tag === 0x17 || tlv.tag === 0x18)) {
      const raw = blob.subarray(tlv.start, tlv.end).toString('latin1');
      out.signing_time = raw;
    }
  }
  // Сертификаты: считаем вхождения заголовка SEQ{SEQ{INT — слишком грубо;
  // честнее: считаем CN-вхождения (issuer+subject на сертификат с CN).
  out.cert_count = cns.length > 0 ? Math.round(cns.length / 2) : 0;
  return out;
}

// ---------- PE-ресурсы ----------
const RES_TYPES = {
  1: 'cursor', 2: 'bitmap', 3: 'icon', 4: 'menu', 5: 'dialog', 6: 'string', 7: 'fontdir',
  8: 'font', 9: 'accel', 10: 'rcdata', 11: 'messagetable', 12: 'group_cursor', 14: 'group_icon', 16: 'version', 24: 'manifest',
};

function parseVersionInfo(buf) {
  const out = {};
  if (buf.length < 40) return out;
  // wLength(2), wValueLength(2), wType(2), szKey — UTF-16 до нуля, выравнивание по 4.
  let p = 6;
  while (p + 1 < buf.length && buf.readUInt16LE(p) !== 0) p += 2;
  p = (p + 2 + 3) & ~3;
  if (p + 52 > buf.length) return out;
  // DWORD в LE: старшее слово лежит старше, поэтому major/minor читаются со смещением 2.
  out.file_version = `${buf.readUInt16LE(p + 10)}.${buf.readUInt16LE(p + 8)}.${buf.readUInt16LE(p + 14)}.${buf.readUInt16LE(p + 12)}`;
  out.product_version = `${buf.readUInt16LE(p + 18)}.${buf.readUInt16LE(p + 16)}.${buf.readUInt16LE(p + 22)}.${buf.readUInt16LE(p + 20)}`;
  const text = buf.toString('utf16le');
  for (const key of ['CompanyName', 'FileDescription', 'FileVersion', 'ProductName', 'ProductVersion', 'LegalCopyright', 'OriginalFilename']) {
    const index = text.indexOf(key);
    if (index >= 0) {
      // После ключа — терминатор и до трёх выравнивающих нулей, затем значение.
      let start = index + key.length;
      let skipped = 0;
      while (skipped < 4 && text[start] === '\0') { start += 1; skipped += 1; }
      const value = text.slice(start, start + 200).split('\0')[0].trim();
      if (value) out[key.toLowerCase()] = cleanText(value, 120);
    }
  }
  return out;
}

function triageResources(reader, dirs, rvaToOffset, sheet, ctx) {
  const root = rvaToOffset(dirs.resource.rva);
  if (root < 0) return;
  const result = { types: [], version: null, manifest: null, icons: 0 };
  const datas = new Map(); // typeId -> [{rva, size}]
  const walk = (baseOff, level, typeId) => {
    if (level > 3) return;
    const hdr = reader.read(baseOff, 16);
    if (hdr.length < 16) return;
    const total = u16(hdr, 12) + u16(hdr, 14);
    if (total === 0 || total > 4096) return;
    const entries = reader.read(baseOff + 16, total * 8);
    for (let i = 0; i < total; i += 1) {
      const name = u32(entries, i * 8);
      const offset = u32(entries, i * 8 + 4);
      if (level === 0 && !(name & 0x80000000)) result.types.push(name);
      if (offset & 0x80000000) {
        walk(root + (offset & 0x7fffffff), level + 1, level === 0 ? name : typeId);
      } else {
        const de = reader.read(root + offset, 16);
        if (de.length >= 12) {
          const rva = u32(de, 0);
          const size = u32(de, 4);
          if (!datas.has(typeId)) datas.set(typeId, []);
          datas.get(typeId).push({ rva, size });
        }
      }
    }
  };
  walk(root, 0, 0);
  result.types = result.types.map((t) => ({ id: t, name: RES_TYPES[t] ?? `type-${t}` })).slice(0, 20);

  const versionData = datas.get(16);
  if (versionData?.length) {
    const entry = versionData[0];
    const off = rvaToOffset(entry.rva);
    if (off >= 0) result.version = parseVersionInfo(reader.read(off, Math.min(entry.size, 1 << 20)));
  }
  const manifestData = datas.get(24);
  if (manifestData?.length) {
    const entry = manifestData[0];
    const off = rvaToOffset(entry.rva);
    if (off >= 0) {
      const raw = reader.read(off, Math.min(entry.size, 1 << 20));
      let text = raw.toString('utf8');
      if (text.includes('\u0000')) text = raw.toString('utf16le');
      const level = /requestedExecutionLevel[^>]*level\s*=\s*"([^"]+)"/i.exec(text);
      const uiAccess = /uiAccess\s*=\s*"true"/i.test(text);
      result.manifest = { level: level?.[1] ?? null, ui_access: uiAccess, bytes: raw.length };
    }
  }
  result.icons = (datas.get(3)?.length ?? 0) + (datas.get(14)?.length ?? 0);
  sheet.resources = result;
}

const TYPE_BY_MAGIC = [
  [[0x1f, 0x8b], 'gzip'], [[0x42, 0x5a, 0x68], 'bzip2'], [[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], 'xz'],
  [[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], '7z'], [[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07], 'rar'],
  [[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], 'png'], [[0xff, 0xd8, 0xff], 'jpeg'],
  [[0x47, 0x49, 0x46, 0x38], 'gif'], [[0x25, 0x50, 0x44, 0x46], 'pdf'],
  [[0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00], 'sqlite'],
  [[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], 'ole2'], [[0x00, 0x61, 0x73, 0x6d], 'wasm'],
  [[0xca, 0xfe, 0xba, 0xbe], 'java-class'], [[0x50, 0x4b, 0x03, 0x04], 'zip'], [[0x50, 0x4b, 0x05, 0x06], 'zip'],
  [[0x52, 0x4f, 0x46, 0x20, 0x46, 0x44, 0x42], 'pln'],
];



export function triage(path, options = {}) {
  const started = process.hrtime.bigint();
  const errors = [];
  const limits = [];
  const sheet = { path: path.slice(0, 300), file: cleanText(path.split(/[\\/]/).pop(), 120) };
  let reader;
  try {
    reader = new Reader(path);
  } catch (error) {
    return { ok: false, error: `не открыть: ${error.code ?? error.message}` };
  }
  try {
    sheet.size = reader.size;
    const head = reader.read(0, 64);
    if (head.length < 2) {
      sheet.type = 'empty';
    } else if (head[0] === 0x4d && head[1] === 0x5a) {
      triagePE(reader, sheet, { errors, limits });
    } else if (head.subarray(0, 4).toString('latin1') === '\x7fELF') {
      triageELF(reader, sheet, { errors, limits });
    } else if ([0xfeedface, 0xfeedfacf, 0xcffaedfe, 0xcefaedfe, 0xcafebabe].includes(head.readUInt32BE(0))) {
      triageMachO(reader, sheet);
    } else if (head.subarray(0, 4).toString('latin1') === 'dex\n' || head.subarray(0, 4).toString('latin1') === 'dey\n') {
      sheet.type = 'dex';
      sheet.arch = 'dalvik';
      const dex = reader.read(0, 112);
      sheet.strings = u32(dex, 56);
      sheet.classes = u32(dex, 96);
      sheet.methods = u32(dex, 88);
    } else if (head[0] === 0xd4 && head[1] === 0xc3 && head[2] === 0xb2 && head[3] === 0xa1) {
      sheet.type = 'pcap';
      const gh = reader.read(0, 24);
      sheet.linktype = u32(gh, 20);
      sheet.snaplen = u32(gh, 16);
      if (reader.size > 24) sheet.first_packet_bytes = reader.size - 24;
    } else if (head.readUInt32BE(0) === 0x0a0d0d0a) {
      sheet.type = 'pcapng';
    } else {
      const magic = TYPE_BY_MAGIC.find(([bytes]) => head.subarray(0, bytes.length).equals(Buffer.from(bytes)));
      if (magic) {
        sheet.type = magic[1];
        if (sheet.type === 'zip') triageZip(reader, sheet, { errors, limits });
        if (sheet.type === 'pln') triagePLN(reader, sheet);
        if (sheet.type === 'png' && head.length >= 24) {
          sheet.width = head.readUInt32BE(16);
          sheet.height = head.readUInt32BE(20);
        }
        if (sheet.type === 'pdf') {
          const probe = reader.read(0, Math.min(reader.size, 1 << 20)).toString('latin1');
          sheet.javascript = /\/JavaScript|\/JS\b/.test(probe);
          sheet.open_action = /\/OpenAction/.test(probe);
          sheet.launch = /\/Launch/.test(probe);
        }
      } else {
        const probe = reader.read(0, Math.min(reader.size, 8192));
        let decoded = null;
        let decodedAs = 'utf-8';
        if (head[0] === 0xff && head[1] === 0xfe) {
          decodedAs = 'utf-16le';
          try { decoded = new TextDecoder('utf-16le', { fatal: true }).decode(probe.subarray(2)); } catch { decoded = null; }
        } else if (head[0] === 0xfe && head[1] === 0xff) {
          decodedAs = 'utf-16be';
          try { decoded = new TextDecoder('utf-16be', { fatal: true }).decode(probe.subarray(2)); } catch { decoded = null; }
        } else {
          try { decoded = new TextDecoder('utf-8', { fatal: true }).decode(probe); } catch { decoded = null; }
        }
        if (decoded !== null) {
          const controls = [...decoded].filter((ch) => {
            const code = ch.codePointAt(0);
            return (code < 32 && code !== 9 && code !== 10 && code !== 13) || code === 0x7f;
          }).length;
          if (controls / Math.max(1, decoded.length) < 0.01) {
            sheet.type = 'text';
            sheet.encoding = decodedAs;
            const sample = reader.read(0, Math.min(reader.size, 65536)).toString(decodedAs === 'utf-8' ? 'utf8' : decodedAs);
            sheet.lines = sample.split('\n').length;
            if (/^#!/.test(sample)) sheet.shebang = cleanText(sample.split('\n')[0], 80);
            else if (/^\s*[[{]/.test(sample)) sheet.text_kind = 'json';
            else if (/^\s*<\?xml|^\s*<[a-z]/i.test(sample)) sheet.text_kind = 'markup';
            else if (/^\s*(diff --git|From [0-9a-f]{40})/.test(sample)) sheet.text_kind = 'patch';
          } else {
            sheet.type = 'unknown';
            sheet.head_hex = head.subarray(0, 16).toString('hex');
          }
        } else {
          sheet.type = 'unknown';
          sheet.head_hex = head.subarray(0, 16).toString('hex');
        }
      }
    }

    if (options.hash && reader.size <= (options.hashLimit ?? 64 * 1024 * 1024)) {
      const hash = crypto.createHash('sha256');
      const chunk = 1 << 20;
      for (let off = 0; off < reader.size; off += chunk) hash.update(reader.read(off, Math.min(chunk, reader.size - off)));
      sheet.sha256 = hash.digest('hex');
    }
    sheet.errors = errors;
    sheet.limits = limits;
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    return { ok: true, sheet, ms: Math.round(ms * 10) / 10 };
  } finally {
    reader.close();
  }
}
