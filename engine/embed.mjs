// LSRE Deep: локальные эмбеддинги, без сети. Два профиля моделей:
//   wordpiece  — rubert-tiny2 (vocab.txt), 312d, 27,9 МБ, быстрый;
//   unigram    — multilingual-e5-small (tokenizer.json), 384d, ~113 МБ, точнее.
// Профиль определяется по файлам в папке модели. Префиксы e5 ("query: "/"passage: ")
// задаются в meta.json рядом с моделью: {"prefix":{"query":"query: ","passage":"passage: "}}.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const MAX_CHARS = 4000;
const MAX_WORD_CHARS = 64;

let ort = null;
function loadOrt() {
  if (ort) return ort;
  const require = createRequire(import.meta.url);
  const candidates = [
    null,
    process.env.LSRE_ONNX_DIR,
    path.join(here, 'node_modules', 'onnxruntime-node'),
    path.join(here, '..', 'LSRE-build', 'app', 'node_modules', 'onnxruntime-node'),
  ];
  for (const dir of candidates) {
    try {
      ort = dir ? require(dir) : require('onnxruntime-node');
      if (ort?.InferenceSession) return ort;
    } catch { /* следующий путь */ }
  }
  throw new Error('onnxruntime-node не найден');
}

// --- WordPiece (rubert-tiny2) -------------------------------------------
function loadWordPiece(dir) {
  const vocab = new Map();
  for (const [i, tok] of fs.readFileSync(path.join(dir, 'vocab.txt'), 'utf8').split(/\r?\n/).entries()) {
    if (tok !== '') vocab.set(tok, i);
  }
  return vocab;
}

function basicTokens(text) {
  const norm = String(text).toLowerCase().normalize('NFC');
  const out = [];
  const re = /([a-zа-яё0-9]+)|([^\sa-zа-яё0-9])/giu;
  let m;
  while ((m = re.exec(norm)) !== null) {
    if (m[1]) out.push(m[1]);
    else if (m[2]) out.push(m[2]);
  }
  return out;
}

function wordpieceTokens(text, vocab, maxTokens) {
  const ids = [vocab.get('[CLS]') ?? 101];
  const push = (id) => { if (ids.length < maxTokens - 1) ids.push(id); };
  outer:
  for (const word of basicTokens(String(text).slice(0, MAX_CHARS))) {
    if (vocab.has(word)) { push(vocab.get(word)); continue; }
    if (word.length > MAX_WORD_CHARS) { push(vocab.get('[UNK]') ?? 100); continue; }
    let start = 0;
    while (start < word.length) {
      let end = word.length;
      let found = null;
      while (start < end) {
        let piece = word.slice(start, end);
        if (start > 0) piece = '##' + piece;
        if (vocab.has(piece)) { found = vocab.get(piece); break; }
        end -= 1;
      }
      if (found === null) { push(vocab.get('[UNK]') ?? 100); break; }
      push(found);
      start = end;
      if (ids.length >= maxTokens - 1) break outer;
    }
  }
  ids.push(vocab.get('[SEP]') ?? 102);
  return ids;
}

// --- Unigram (multilingual-e5-small, XLM-R) -----------------------------
function loadUnigram(dir) {
  const spec = JSON.parse(fs.readFileSync(path.join(dir, 'tokenizer.json'), 'utf8'));
  const model = spec.model;
  if (model.type !== 'Unigram') throw new Error(`неожиданный токенизатор: ${model.type}`);
  const index = new Map();
  let maxLen = 1;
  model.vocab.forEach(([piece, score], i) => {
    index.set(piece, { id: i, score });
    if (piece.length > maxLen) maxLen = Math.min(piece.length, 32);
  });
  return { index, unkId: model.unk_id ?? 3, maxLen, maxTokens: 512 };
}

// Metaspace: пробел -> U+2581, префикс U+2581 в начале слова.
function metaspace(text) {
  const clean = String(text).slice(0, MAX_CHARS).normalize('NFC').replace(/\s+/g, ' ').trim();
  return `▁${clean.replace(/ /g, '▁')}`;
}

function unigramTokens(text, uni) {
  const chars = [...metaspace(text)];
  const n = chars.length;
  const best = new Float64Array(n + 1).fill(-Infinity);
  const back = new Int32Array(n + 1).fill(-1);
  const backLen = new Int32Array(n + 1).fill(0);
  best[0] = 0;
  for (let i = 0; i < n; i += 1) {
    if (best[i] === -Infinity) continue;
    for (let len = 1; len <= uni.maxLen && i + len <= n; len += 1) {
      const piece = chars.slice(i, i + len).join('');
      const hit = uni.index.get(piece);
      if (!hit) continue;
      const score = best[i] + hit.score;
      if (score > best[i + len]) { best[i + len] = score; back[i + len] = i; backLen[i + len] = len; }
    }
    // Неизвестный символ: один unk за шаг, иначе текст из эмодзи развалит выравнивание.
    if (back[i + 1] === -1 && best[i + 1] === -Infinity) {
      best[i + 1] = best[i] - 20;
      back[i + 1] = i;
      backLen[i + 1] = 1;
    }
  }
  const ids = [];
  let pos = n;
  while (pos > 0) {
    const start = back[pos];
    if (start < 0) break;
    const piece = chars.slice(start, pos).join('');
    const hit = uni.index.get(piece);
    ids.push(hit ? hit.id : uni.unkId);
    pos = start;
  }
  ids.reverse();
  const max = uni.maxTokens - 2;
  const body = ids.length > max ? ids.slice(0, max) : ids;
  return [0, ...body, 2];
}

// --- общий эмбеддер -----------------------------------------------------
export function resolveModelDir() {
  const candidates = [
    process.env.LSRE_EMBED_DIR,
    path.join(here, 'embed'),
    path.join(here, '..', 'rea-clean', 'embed'),
    path.join(here, '..', 'LSRE-deep', 'models', 'e5-small'),
  ];
  for (const dir of candidates) {
    if (!dir) continue;
    const hasOnnx = fs.existsSync(path.join(dir, 'model_int8.onnx'));
    const hasTok = fs.existsSync(path.join(dir, 'vocab.txt')) || fs.existsSync(path.join(dir, 'tokenizer.json'));
    if (hasOnnx && hasTok) return dir;
  }
  return null;
}

function readMeta(dir) {
  for (const name of ['meta.json', 'lsre-embed.json']) {
    const file = path.join(dir, name);
    if (fs.existsSync(file)) {
      try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return {}; }
    }
  }
  return {};
}

export function createEmbedder(dir) {
  const state = { session: null, profile: null, tok: null, dim: 312, model: 'unknown', prefixes: { query: '', passage: '' } };

  async function init() {
    if (state.session) return info();
    const runtime = loadOrt();
    const meta = readMeta(dir);
    if (fs.existsSync(path.join(dir, 'tokenizer.json'))) {
      state.profile = 'unigram';
      state.tok = loadUnigram(dir);
      state.model = meta.model ?? 'multilingual-e5-small-int8';
    } else {
      state.profile = 'wordpiece';
      state.tok = loadWordPiece(dir);
      state.model = meta.model ?? 'rubert-tiny2-int8';
    }
    state.prefixes = { query: meta.prefix?.query ?? '', passage: meta.prefix?.passage ?? '' };
    state.session = await runtime.InferenceSession.create(path.join(dir, 'model_int8.onnx'), {
      executionProviders: ['cpu'],
      graphOptimizationLevel: 'all',
    });
    state.dim = meta.dim ?? (state.profile === 'unigram' ? 384 : 312);
    return info();
  }

  function info() {
    return { dim: state.dim, model: state.model, profile: state.profile, dir, prefixes: state.prefixes };
  }

  function encode(text, mode) {
    const prefix = state.prefixes[mode] ?? '';
    const body = `${prefix}${text}`;
    if (state.profile === 'unigram') return unigramTokens(body, state.tok);
    return wordpieceTokens(body, state.tok, 128);
  }

  async function embed(text, mode = 'passage') {
    if (!state.session) throw new Error('эмбеддер не инициализирован');
    const runtime = loadOrt();
    const ids = encode(text, mode);
    const seq = ids.length;
    const mask = new Array(seq).fill(1);
    // Паддинг кратным 32: короче вход — быстрее CPU, но форма остаётся предсказуемой.
    let padTo = state.profile === 'unigram' ? Math.max(32, Math.ceil(seq / 32) * 32) : 128;
    if (state.fixedShape && padTo !== state.fixedShape) padTo = state.fixedShape;
    let out;
    for (let attempt = 0; ; attempt += 1) {
      while (ids.length < padTo) { ids.push(0); mask.push(0); }
      const inputIds = new runtime.Tensor('int64', BigInt64Array.from(ids.map(BigInt)), [1, padTo]);
      const attention = new runtime.Tensor('int64', BigInt64Array.from(mask.map(BigInt)), [1, padTo]);
      const feeds = { input_ids: inputIds, attention_mask: attention };
      if (state.session.inputNames.includes('token_type_ids')) {
        feeds.token_type_ids = new runtime.Tensor('int64', new BigInt64Array(padTo), [1, padTo]);
      }
      try {
        out = await state.session.run(feeds);
        break;
      } catch (error) {
        // Модель с жёсткой формой: один раз переключаемся на 512 и повторяем.
        if (attempt > 0) throw error;
        state.fixedShape = 512;
        padTo = 512;
        ids.length = seq;
        mask.length = seq;
      }
    }
    const first = out[state.session.outputNames[0]];
    const [, , dim] = first.dims;
    const data = first.data;
    const vec = new Float32Array(dim);
    let count = 0;
    for (let t = 0; t < seq; t += 1) {
      if (!mask[t]) continue; // считаем только реальные токены, не паддинг
      count += 1;
      for (let d = 0; d < dim; d += 1) vec[d] += data[t * dim + d];
    }
    let norm = 0;
    for (let d = 0; d < dim; d += 1) { vec[d] /= Math.max(count, 1); norm += vec[d] * vec[d]; }
    norm = Math.sqrt(norm) || 1;
    for (let d = 0; d < dim; d += 1) vec[d] /= norm;
    return vec;
  }

  return { init, embed, info, state };
}

// --- синглтон для сервера ------------------------------------------------
let singleton = null;
let initError = null;

export async function initEmbeddings(dir = resolveModelDir()) {
  if (singleton) return singleton.state.session ? info() : (await singleton.init());
  if (!dir) { initError = 'модель не найдена (LSRE_EMBED_DIR)'; throw new Error(initError); }
  try {
    singleton = createEmbedder(dir);
    return await singleton.init();
  } catch (error) {
    initError = String(error?.message ?? error);
    throw error;
  }
}

export function embedStatus() {
  return { ready: Boolean(singleton?.state.session), model: singleton?.state.model ?? null, error: initError };
}

export async function embed(text, mode = 'passage') {
  if (!singleton) throw new Error('эмбеддинги не инициализированы: initEmbeddings()');
  return singleton.embed(text, mode);
}

export function info() {
  return singleton ? singleton.info() : { ready: false, error: initError };
}

export function cosine(a, b) {
  let s = 0;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) s += a[i] * b[i];
  return s;
}

// int8-квантование: 312/384 Б вместо 1248/1536 Б, потеря ~0.4 % — приемлемо для поиска.
export function quantize(vec) {
  let max = 0;
  for (const v of vec) max = Math.max(max, Math.abs(v));
  const scale = max ? max / 127 : 1;
  const bytes = Buffer.allocUnsafe(vec.length);
  for (let i = 0; i < vec.length; i += 1) bytes[i] = Math.max(-127, Math.min(127, Math.round(vec[i] / scale))) & 0xff;
  return { bytes, scale };
}

export function dequantize(bytes, scale, dim = bytes.length) {
  const vec = new Float32Array(dim);
  for (let i = 0; i < dim; i += 1) vec[i] = ((bytes[i] << 24) >> 24) * scale;
  return vec;
}
