# Архитектура LSRE

## Слои

```
LSRE.exe (self-extracting, Node SEA)
  └─ stub: распаковка payload (zstd → tar) в LSRE_INSTALL_DIR
       └─ node.exe  (из payload)
            └─ lsre-proxy.mjs   ← фильтр инструментов + память
                 ├─ REA MCP-сервер (rea.mjs mcp)
                 │    ├─ Ghidra 12.1.4 (headless, внешняя)
                 │    └─ Frida (npm-модуль внутри payload)
                 └─ SQLite (FTS5): facts, entities, edges, sessions, pages
```

## Почему один файл

- Node SEA позволяет вшить архив в exe и не требовать установки Node.
- Payload сжат zstd (13 МБ tar → 127 МБ), распаковка при первом запуске ~30 с.
- Дальше exe работает как обычный Node-процесс с реальными файлами на диске — поэтому
  Ghidra и Frida работают без патчей путей.

## Память

| Таблица | Назначение |
|---|---|
| `facts` | факты с дедупликацией по sha256 и полнотекстовым индексом FTS5 |
| `entities` | узлы графа: binary / module / function / service |
| `edges` | связи: calls, contains, imports, duplicates, implements, depends_on, similar_to |
| `sessions` | якорь: goal → done → next_step → open_questions (перезапись) |
| `pages` | страницы знаний: архитектура, соглашения |

Схема версионируется через `PRAGMA user_version`; WAL и `busy_timeout` включены.

## Экономия контекста

| Режим | Инструментов | Вес схем |
|---|---|---|
| REA по умолчанию | 207 | 3084 КБ |
| `compact` + выход `off` | 207 | 214 КБ |
| + фильтр LSRE | 94 | ~75 КБ |

## Сборка

```
LSRE-build/
  build.mjs   — payload (tar + zstd) → esbuild-стаб → SEA → postject
  stub.mjs    — распаковка и запуск
  icon.mjs    — SVG → ICO (16…256) и вставка в PE через resedit
  logo.svg    — логотип
```

Пересборка занимает ~7 минут и требует прав вне песочницы (запуск `tar`, `esbuild`,
`postject`).
