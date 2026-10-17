@echo off
cd /d "%~dp0"
title JWT 工具 - 本地服务（关闭此窗口即停止服务）

set "NODE_EXE="
for %%P in ("node.exe") do set "NODE_EXE=%%~$PATH:P"
if not defined NODE_EXE if exist "C:/Program Files/nodejs/node.exe" set "NODE_EXE=C:/Program Files\nodejs\node.exe"
if not defined NODE_EXE if exist "%USERPROFILE%\.workbuddy\binaries\node\versions\22.22.2-6\node.exe" set "NODE_EXE=%USERPROFILE%\.workbuddy\binaries\node\versions\22.22.2-6\node.exe"

if not defined NODE_EXE (
  echo.
  echo   [错误] 未找到 node.exe，请先安装 Node.js 16 以上版本后重试。
  echo.
  pause
  exit /b 1
)

echo.
echo   正在启动 JWT 工具，浏览器会自动打开...
echo   实际地址以本窗口打印的为准（端口被占用会自动顺延）。
echo   停止服务：关闭本窗口或按 Ctrl + C
echo.

rem node 输出为 UTF-8，先切到 65001 代码页，避免中文乱码
chcp 65001 >nul
"%NODE_EXE%" server.js

chcp 936 >nul
echo.
echo   服务已停止。
pause
