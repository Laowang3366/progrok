@echo off
chcp 65001 >nul
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_and_start.ps1"
if errorlevel 1 (
  echo.
  echo 安装或启动失败，请查看上方错误信息。
  pause
)
