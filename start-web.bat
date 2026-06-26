@echo off
:loop
node "%~dp0src\server.js" >> "%~dp0web.log" 2>&1
timeout /t 3 >nul
goto loop
