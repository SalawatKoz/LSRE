# NOTICE — LSRE

LSRE 3.0.0 включает два слоя:

1. **Движок LSRE** (`engine/`) — собственная разработка SalawatKoz, MIT.
2. **Оболочка** (`shell/`) — изменённый форк [Craft Anything](https://github.com/storytold/craft-anything)
   версии 0.5.0, Copyright (c) 2026 ArtCraft Team and the Craft Anything contributors,
   лицензия MIT OR Apache-2.0. Настоящая поставка использует **вариант MIT**.

Исходный код оболочки доступен в `shell/`, изменения перечислены в `docs/CHANGES.md`
и видны в истории репозитория. Текст лицензии upstream сохраняется в
`shell/LICENSE-MIT` и `shell/LICENSE-APACHE` (как в исходном репозитории).

## Изменения в оболочке (кратко)
- отображаемое имя приложения: LSRE; окно, заголовки, приветствие, About;
- собственные ресурсы: иконка-гарпия (векторный SVG + .ico), ProductName/FileDescription;
- каталог данных: `lsre` вместо `craft-anything`; портативный маркер `LSREData`;
- в `crates/engine/src/clean_room.rs` инструменты с префиксом `lsre_` разрешены в Clean room;
- добавлены экраны: лента «Чат · Код · Архитектура», вкладка кода, карта архитектуры (нодовая);
- сервисные хуки для снимков и проверок (`LSRE_START_SCREEN`, `LSRE_ARCH_DEBUG`);
- в `crates/ui-egui/Cargo.toml` включена поддержка PNG-загрузчика (`image`).

Товарные знаки и фирменные названия Craft Anything / ArtCraft не используются и не
передаются по лицензии; LSRE — самостоятельное название.

## Что не входит в репозиторий
Модель эмбеддингов, `yr.exe`, `node.exe` и готовые архивы поставляются отдельными
файлами в Releases, чтобы не раздувать git. Их лицензии — в `THIRD-PARTY-NOTICES.md`.
