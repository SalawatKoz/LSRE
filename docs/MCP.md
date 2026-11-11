# Подключение как MCP-сервер

Движок `engine/server.mjs` общается по stdio JSON-RPC (MCP). Ему не нужны сеть, ключи и
оболочка: достаточно Node 22+.

## Быстрый способ
В папке сборки:
```
node mcp-print.cjs
```
Скрипт создаст `data\lsre` и напечатает готовый JSON:

```json
{
  "mcpServers": {
    "lsre": {
      "command": "<путь>\\engine\\node.exe",
      "args": ["<путь>\\engine\\server.mjs"],
      "env": {
        "LSRE_LITE_DB": "<путь>\\data\\lsre\\lite.db",
        "LSRE_EMBED_DIR": "<путь>\\model",
        "LSRE_PLAIN_NAMES": "1"
      }
    }
  }
}
```

## Claude Code
```
claude mcp add-json lsre '<JSON из mcp-print.cjs>' --scope user
claude mcp list
```

## Cursor
Settings → MCP → **Add new MCP server** → transport `stdio`:
- Command: путь к `engine\node.exe` (или `node`);
- Args: путь к `engine\server.mjs`;
- Env: три переменные из JSON.

## DeepSeek Harness
В профиле (`~/.dsh/profiles/<профиль>/cordis.patch.yml`) добавить сервер с теми же
`command`, `args`, `env`. После правки — перезапуск DSH.

## Переменные окружения
| Переменная | Зачем |
|---|---|
| `LSRE_LITE_DB` | путь к базе памяти (обязательно вне записи в `%LOCALAPPDATA%`) |
| `LSRE_EMBED_DIR` | папка модели (`model_int8.onnx` + `tokenizer.json`/`vocab.txt` + `meta.json`) |
| `LSRE_PLAIN_NAMES` | `1` — отдавать имена без префикса `lsre_` (оболочка добавит его сама) |
| `GHIDRA_INSTALL_DIR` | папка Ghidra с `support\` (для декомпиляции) |
| `JAVA_HOME` | JDK для Ghidra |
| `LSRE_DEEP` | `0` — отключить эмбеддинги (только FTS5) |

## Проверка
```
node engine/server.mjs
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
```
Ожидаемо: 28 инструментов (full) или 24 (lite), схема ~9,5 КБ.

## Замечания
- consent/подтверждения — политика **оболочки**; при прямом подключении к агенту
  ответственность за опасные вызовы (Frida, Ghidra) лежит на вас;
- базу нельзя держать в защищённой папке: некоторые песочницы запрещают запись в
  `%LOCALAPPDATA%` — поэтому путь задаётся переменной;
- параллельный доступ: SQLite в режиме WAL, несколько читателей допустимы.
