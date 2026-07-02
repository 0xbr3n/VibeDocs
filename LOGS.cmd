@echo off
REM Tails the live application logs. Press Ctrl+C to stop watching.
setlocal
cd /d "%~dp0"
echo Showing live VibeDocs logs - press Ctrl+C to exit.
echo.
docker compose logs -f app
endlocal
