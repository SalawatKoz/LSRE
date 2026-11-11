# Архитектура

## Слои

```
LSRE.exe (Rust/egui, форк Craft Anything)
├─ ui-egui        экраны: чат, код, архитектура, настройки, workbench
├─ engine (Rust)  реестр инструментов, проекты .cany, evidence, consent-политика
└─ plugins.mcp    шов: внешний MCP-сервер → набор инструментов
        │  stdio JSON-RPC
        ▼
engine/server.mjs (Node 22+, 28 инструментов)
├─ triage.mjs      PE/ELF/Mach-O/ZIP/APK/DEX/PDF, энтропия, импорты, подпись
├─ memory.mjs      SQLite WAL, FTS5, схема v2, граф, страницы, якорь
├─ embed.mjs       e5-small int8 (unigram) и rubert-tiny2 (wordpiece)
├─ formats.mjs     Kaitai: png, sqlite3, gzip, pcap
├─ parse_yaml.mjs  YAML → JSON
├─ yara.mjs        обёртка YARA-X (yr.exe)
├─ ghidra.mjs      Ghidra headless + кэш проектов
└─ frida.mjs       Frida 17: процессы, модули, скрипты
```

## Почему плагин, а не «всё в Rust»
У оболочки есть штатный механизм: сервер из `config.toml` становится набором инструментов,
его результаты попадают в evidence, вызовы идут через таймауты и consent. Это даёт:

- нулевую правку реестра при добавлении инструмента;
- один язык для движка (JS) и быстрые итерации;
- возможность менять движок, не пересобирая оболочку.

Цена — два рантайма. В full-сборке Node вложен, поэтому для пользователя это невидимо.

## Схема памяти (v2)

```sql
facts(id, bank, ts, kind, text, tags, trust, source, sha)
facts_fts(text)                          -- FTS5, unicode61
entities(id, bank, type, name, sha, meta)
edges(id, bank, src, dst, rel, weight, evidence, origin)
observations(id, bank, text, support, signature, updated)
observation_facts(observation_id, fact_id)
pages(id, bank, slug, question, answer, sources, updated)
anchors(bank, goal, done, next_step, open_questions, updated)
embeddings(fact_id, bank, model, dim, scale, vec, ts)   -- int8
meta(key, value)                          -- schema = 2
```

Миграция с v1: таблицы создаются `IF NOT EXISTS`, перед обновлением версии делается
копия `*.v1.bak` (чекпойнт WAL, затем копия).

## Поиск
Гибрид через RRF:
1. лексика — FTS5 bm25;
2. смысл — косинус по int8-векторам (потеря ≤ 0,0005);
3. свежесть — полураспад 30 дней;
4. в ответе поле `why` — видно, какой канал сработал.

Детерминированно: одинаковый запрос при той же базе даёт тот же ответ. LLM не участвует.

## Бюджеты
- `lsre_triage` — факт-шит ≤ 2 КБ;
- `lsre_context` — бюджет в **байтах** (кириллица считается по UTF-8);
- тяжёлые ответы — пагинация `offset/limit`;
- схема всех 28 инструментов — **9,5 КБ** на запрос.

## Безопасность
- секреты вырезаются до записи (`redact`: ключи, токены, приватные ключи, base64-блобы);
- содержимое файлов помечается `untrusted` — текст из малвари не выглядит инструкцией;
- `origin='user'` не принимается от агента: связь, поставленную человеком, агент не изменит;
- политика оболочки: Clean room / Deep, подтверждения опасных действий.
