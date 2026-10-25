# Публикация LSRE на GitHub

Exe весит 225,7 МБ — GitHub не принимает файлы больше 100 МБ в репозиторий.
Поэтому: **код и документация — в репозиторий, exe — в Releases** (лимит 2 ГБ на файл).

## Вариант 1 — автоматический (рекомендую)

Нужен токен GitHub с правами `repo` (для своего аккаунта — classic PAT, галочка `repo`).

1. Создайте токен: GitHub → Settings → Developer settings → Personal access tokens →
   Tokens (classic) → Generate new token → scope `repo`.
2. В папке `LSRE-repo` выполните:

```powershell
.\PUBLISH.ps1 -Token "ghp_ВАШ_ТОКЕН"
```

Скрипт сам:
- определит ваш логин,
- создаст репозиторий `LSRE`, если его нет,
- сделает первый коммит и запушит,
- создаст релиз `v2.0.0` с текстом из `release/RELEASE_NOTES-v2.0.0.md`,
- выведет ссылку для загрузки exe.

3. Откройте ссылку релиза и **перетащите `LSRE.exe`** в поле «Attach binaries».
   (Либо передайте `-ExePath "C:\Tools\LSRE.exe"` — скрипт загрузит сам
   через curl; 225 МБ будут грузиться несколько минут.)

## Вариант 2 — вручную

```powershell
cd C:\LSRE-repo
git init
git add .
git commit -m "LSRE v1.0.0: reverse engineering MCP server with local memory"
git branch -M main
git remote add origin https://github.com/ВАШ_ЛОГИН/LSRE.git
git push -u origin main
```

Дальше на GitHub: Releases → Draft a new release → tag `v2.0.0` → вставить текст из
`release/RELEASE_NOTES-v2.0.0.md` → прикрепить `LSRE.exe` → Publish.

## Что попадёт в репозиторий

| Файл | Зачем |
|---|---|
| `README.md` | главная страница: что это, как поставить, хеш |
| `LICENSE` | MIT от REA — обязателен при распространении |
| `NOTICE.md` | происхождение и сторонние компоненты |
| `POLICY.md` | позиция проекта: исследование, без обхода защиты |
| `docs/ARCHITECTURE.md` | как устроено |
| `release/RELEASE_NOTES-v2.0.0.md` | текст релиза |
| `.gitignore` | исключает exe, БД, распаковку |

## После публикации — чек-лист

- [ ] В README указан актуальный SHA-256: `26C37BE9…102D`.
- [ ] В релизе приложен именно тот exe (сверьте хеш).
- [ ] Тег `v1.0.0` стоит на коммите, где README и NOTES согласованы.
- [ ] Лицензия видна на странице репозитория (GitHub определит MIT автоматически).
- [ ] В описании репозитория — одна строка: «Single-exe reverse engineering MCP server with
      persistent local memory».

## Если git ругается на сертификаты

На этой машине уже настроено:

```powershell
git config --global http.sslBackend openssl
```

Без этого git падает с `schannel: SEC_E_NO_CREDENTIALS`.
