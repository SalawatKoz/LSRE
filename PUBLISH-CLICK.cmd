@echo off
chcp 65001 >nul
title Публикация LSRE на GitHub

echo.
echo  Публикация LSRE: репозиторий + релиз v1.0.0.
echo.
echo  Нужен токен GitHub с правами "repo":
echo    GitHub - Settings - Developer settings - Personal access tokens - Tokens (classic)
echo    Generate new token - галочка "repo" - скопировать токен.
echo.
echo  Токен вводится скрыто и нигде не сохраняется.
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop';" ^
  "$secure = Read-Host 'Вставьте токен GitHub (ввод скрыт)' -AsSecureString;" ^
  "$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure);" ^
  "$token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr);" ^
  "[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr);" ^
  "& '%~dp0PUBLISH.ps1' -Token $token"

echo.
pause
