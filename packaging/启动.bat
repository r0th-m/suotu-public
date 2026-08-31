@echo off
chcp 936 >nul
rem ============================================================
rem  索图 SuoTu 应急便携包 - 一键启动
rem  双击本文件:启动本地服务并自动打开浏览器
rem  关闭本窗口即停止服务(拔 U 盘前请先关窗口)
rem ============================================================
cd /d %~dp0

rem 数据全部留在 U 盘包内 data\(案件库/金库/账号),不写现场机
set "SUOTU_DATA_DIR=%~dp0data"

echo ============================================================
echo   索图 SuoTu 服务端(应急便携包)
echo   数据目录: %SUOTU_DATA_DIR%
echo   地址:     http://127.0.0.1:8100
echo   首次使用:在网页里创建管理员账号
echo   关闭本黑色窗口 = 停止服务
echo ============================================================

rem 延时 3 秒后自动开浏览器(先确保服务在跑)
start "" cmd /c "timeout /t 3 /nobreak >nul & start http://127.0.0.1:8100"

rem 后端+前端一体化启动(--app-dir 指定到 app 目录)
"%~dp0python\python.exe" -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8100 --app-dir "%~dp0app"

echo.
echo 服务已退出。如有报错请截图反馈。
pause
