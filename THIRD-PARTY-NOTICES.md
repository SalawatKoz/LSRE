# Сторонние компоненты и лицензии

LSRE использует следующие компоненты. Каждый распространяется под своей лицензией;
тексты лицензий — в исходных пакетах и по ссылкам.

## Движок и данные

| Компонент | Версия | Лицензия | Где |
|---|---|---|---|
| multilingual-e5-small (int8 ONNX, Xenova) | — | MIT | модель в полной сборке |
| onnxruntime-node | — | MIT | рантайм эмбеддингов (в сборке движка) |
| Kaitai Struct runtime | 0.11 | MIT | `engine/node_modules/kaitai-struct` |
| Kaitai-парсеры (png, sqlite3, gzip, pcap) | — | MIT (сгенерированы из .ksy) | `engine/formats/` |
| yaml (eemeli) | 2.x | ISC | `engine/node_modules/yaml` |
| YARA-X (VirusTotal) | 1.22 | BSD-3-Clause | `engine/tools/yara-x/yr.exe` |
| Frida | 17.x | wxWindows Library Licence (LGPL-подобная) | `engine/node_modules/frida` |
| Node.js | 26.x | MIT | `engine/node.exe` (только full) |
| Ghidra (внешняя, не входит) | 12.x | Apache-2.0 | устанавливается пользователем |
| Java (внешняя, не входит) | 21+ | GPLv2+CE | устанавливается пользователем |

## Оболочка (`shell/`)

| Компонент | Лицензия |
|---|---|
| Craft Anything 0.5.0 (форк) | MIT OR Apache-2.0 |
| egui / eframe / egui_extras | MIT OR Apache-2.0 |
| прочие Rust-крейты | см. `shell/Cargo.lock` и `cargo license` |

## Инструменты, которые LSRE **не** включает

| Инструмент | Лицензия | Почему не включён |
|---|---|---|
| Cutter / rizin | GPL-3.0 | копилефт: встраивание в MIT-продукт невозможно |
| IDA Pro / IDA Free | проприетарная | только адаптер к установленной лицензии пользователя |
| JEB Decompiler | проприетарная | то же |
| capa | Apache-2.0, Python | внешний вызов, не вшивается |
| Detect It Easy | MIT | внешний вызов по желанию |

Если вы подключаете такие инструменты сами, соблюдайте их лицензии.
