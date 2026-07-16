@echo off
setlocal
chcp 65001 >nul
title ProGrok 一键安装并启动
echo 正在检查并安装 ProGrok 运行环境，请勿关闭此窗口...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_and_start.ps1"
set "EXIT_CODE=%ERRORLEVEL%"
echo.
if "%EXIT_CODE%"=="0" (
  echo 安装及启动流程已完成，请访问 http://127.0.0.1:3080
) else (
  echo 安装或启动失败，请查看上方错误信息。
)
echo.
echo 按任意键关闭此窗口...
pause >nul
exit /b %EXIT_CODE%
