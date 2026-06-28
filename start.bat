@echo off
echo Starting NCSA Blacklist SOC Dashboard...
set DOCKER_BUILDKIT=0
set COMPOSE_DOCKER_CLI_BUILD=0
docker-compose up -d --build
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Build failed. Try:
    echo   1. Make sure Docker Desktop is running (whale icon in taskbar)
    echo   2. Run: docker pull node:20-alpine
    echo   3. Then run this script again
    pause
    exit /b 1
)
echo.
echo Dashboard ready: http://localhost:3939
echo.
pause
