# Установка

## Требования
- Windows 10/11 x64.
- **LSRE-full:** ничего дополнительно (Node.js вложен).
- **LSRE-lite:** Node.js **22 или новее**.
- **Ghidra и Java** — по желанию, для декомпиляции: `GHIDRA_INSTALL_DIR` (папка с `support/`)
  и `JAVA_HOME` (или `java` в PATH). Без них инструменты Ghidra честно сообщают, что не настроены.
- **Frida** уже внутри full-сборки; для lite требуется `frida` в `engine/node_modules`
  (в поставке lite его нет).

## Портативная установка (full)

1. Скачайте `LSRE-full.zip` из Releases.
2. Распакуйте **целиком** в папку без кириллицы в пути, например `C:\LSRE`.
   Не запускайте изнутри zip-архива.
3. Запустите `start.cmd`.

Что произойдёт: `start.cjs` создаст `data\config.toml` с абсолютными путями этой папки,
пропишет плагин `lsre` (команда — вложенный `engine\node.exe`) и откроет `lsre.exe`.

Проверка, что всё на месте:
```
LSRE-full\
  lsre.exe            оболочка
  engine\             28 инструментов + node.exe
  model\              e5-small int8 (112,6 МБ)
  start.cmd .cjs      запуск
  mcp-print.cjs       готовый MCP-конфиг
  data\               создаётся при первом запуске
```

## Установка lite
То же самое, но Node.js 22+ должен быть установлен и доступен в PATH.
`start.cmd` использует системный `node`.

## Перенос на другой компьютер
Скопируйте папку целиком. Конфиг пересоздастся сам: удалите `data\config.toml` и снова
запустите `start.cmd` (пути в нём абсолютные и привязаны к папке).

## Обновление
Распакуйте новую версию в новую папку и перенесите `data\` (память, настройки), если
хотите сохранить историю. Структура `data\` совместима: база памяти — `data\lsre\lite.db`.

## Удаление
Удалите папку. Записей в реестр и системных файлов LSRE не делает.

## Сборка из исходников
Движок:
```
cd engine
node server.mjs            # MCP на stdio
node test.mjs              # 32 теста
node deep-test.mjs         # 8 проверок (нужна модель: LSRE_EMBED_DIR)
node tools-test.mjs        # 7 проверок Kaitai/YAML/YARA/Frida
```
Модель для тестов: `LSRE_EMBED_DIR=<папка с model_int8.onnx и tokenizer.json>`.

Оболочка:
```
cd shell
cargo build --release -p craft-anything
```
Нужны Rust 1.97+ и линкер (MSVC Build Tools либо GNU-тулчейн + mingw-w64).
Готовый бинарник: `shell/target/release/lsre.exe`.

## Частые проблемы
| Симптом | Причина и решение |
|---|---|
| `Node.js 22+ is required` | lite-сборка без Node; установите Node или возьмите full |
| окно не открывается, в `err.log` пусто | проверьте, что папка распакована целиком (есть `model\`) |
| Ghidra: «не настроена» | задайте `GHIDRA_INSTALL_DIR` на папку с `support\` |
| Java не найдена | задайте `JAVA_HOME` или добавьте `java` в PATH |
| антивирус ругается на `yr.exe` | это официальный бинарник YARA-X (BSD-3), добавьте в исключения |
