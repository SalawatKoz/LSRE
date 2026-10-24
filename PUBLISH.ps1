# Публикация LSRE на GitHub: репозиторий + релиз + (опционально) загрузка exe.
# Запуск:  .\PUBLISH.ps1 -Token "ghp_..." [-Repo "login/LSRE"] [-Tag v1.0.0] [-ExePath "...\LSRE.exe"]
param(
  [Parameter(Mandatory = $true)][string]$Token,
  [string]$Repo = '',
  [string]$Tag = 'v1.0.0',
  [string]$ExePath = ''
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$headers = @{
  Authorization          = "token $Token"
  'User-Agent'           = 'lsre-publish'
  Accept                 = 'application/vnd.github+json'
}
$api = 'https://api.github.com'

function Step($message) { Write-Host "== $message" -ForegroundColor Cyan }

Step '1. Проверяю токен'
$me = Invoke-RestMethod -Uri "$api/user" -Headers $headers -Method Get
$login = $me.login
Write-Host "   вошли как $login"

if ([string]::IsNullOrWhiteSpace($Repo)) { $Repo = "$login/LSRE" }
Write-Host "   репозиторий: $Repo"

Step '2. Создаю репозиторий (если его нет)'
try {
  $null = Invoke-RestMethod -Uri "$api/repos/$Repo" -Headers $headers -Method Get
  Write-Host '   уже существует'
} catch {
  $body = @{
    name        = ($Repo -split '/')[1]
    description = 'Single-exe reverse engineering MCP server with persistent local memory'
    private     = $false
    has_issues  = $true
    auto_init   = $false
  } | ConvertTo-Json
  $null = Invoke-RestMethod -Uri "$api/user/repos" -Headers $headers -Method Post -Body $body -ContentType 'application/json'
  Write-Host '   создан'
}

Step '3. Локальный коммит'
if (-not (Test-Path (Join-Path $root '.git'))) { git init | Out-Null }
git config user.name  | Out-Null
if (-not (git config user.name))  { git config user.name  'LSRE' }
if (-not (git config user.email)) { git config user.email 'lsre@users.noreply.github.com' }
git add -A
$pending = git status --porcelain
if ($pending) {
  git commit -m "LSRE ${Tag}: single-exe reverse engineering MCP server with local memory" | Out-Null
  Write-Host '   коммит создан'
} else {
  Write-Host '   изменений нет'
}
git branch -M main 2>$null | Out-Null

Step '4. Push'
$remote = "https://x-access-token:$Token@github.com/$Repo.git"
if (git remote | Select-String -SimpleMatch 'origin') { git remote set-url origin $remote } else { git remote add origin $remote }
git push -u origin main
Write-Host '   отправлено'

Step '5. Релиз'
$notesPath = Join-Path $root "release/RELEASE_NOTES-$Tag.md"
if (-not (Test-Path $notesPath)) { $notesPath = Join-Path $root 'README.md' }
$notes = Get-Content $notesPath -Raw -Encoding UTF8
$releaseBody = @{
  tag_name         = $Tag
  target_commitish = 'main'
  name             = "LSRE $Tag"
  body             = $notes
  draft            = $false
  prerelease       = $false
} | ConvertTo-Json -Depth 3

$release = $null
try {
  $release = Invoke-RestMethod -Uri "$api/repos/$Repo/releases/tags/$Tag" -Headers $headers -Method Get
  Write-Host '   релиз уже существует'
} catch {
  $release = Invoke-RestMethod -Uri "$api/repos/$Repo/releases" -Headers $headers -Method Post -Body $releaseBody -ContentType 'application/json'
  Write-Host '   релиз создан'
}

$uploadUrl = $release.upload_url -replace '\{\?name,label\}', ''
Write-Host "   загрузка exe: $uploadUrl"

Step '6. Загрузка exe'
if ([string]::IsNullOrWhiteSpace($ExePath)) {
  $defaultExe = 'D:\WORK\SMART BUILDER\LSRE\LSRE.exe'
  if (Test-Path $defaultExe) { $ExePath = $defaultExe }
}

if ($ExePath -and (Test-Path $ExePath)) {
  $sizeMb = [math]::Round((Get-Item $ExePath).Length / 1MB, 1)
  Write-Host "   загружаю $ExePath ($sizeMb МБ) — это может занять несколько минут"
  $asset = & curl.exe -sS -X POST `
    -H "Authorization: token $Token" `
    -H 'Content-Type: application/octet-stream' `
    --data-binary "@$ExePath" `
    "$uploadUrl?name=$(Split-Path -Leaf $ExePath)"
  Write-Host "   ответ: $asset"
} else {
  Write-Host '   exe не найден — прикрепите его вручную на странице релиза:'
  Write-Host "   https://github.com/$Repo/releases/tag/$Tag"
}

Write-Host ''
Write-Host "Готово: https://github.com/$Repo" -ForegroundColor Green
