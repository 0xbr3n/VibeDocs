@echo off
REM Stops VibeDocs. Your data is preserved (only RESET.cmd deletes it).
setlocal
cd /d "%~dp0"
echo Stopping VibeDocs...
docker compose down
echo.
echo Stopped. Your projects and reports are safe. Run START.cmd to start again.
echo.
pause
endlocal
