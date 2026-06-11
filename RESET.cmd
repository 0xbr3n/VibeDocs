@echo off
REM ===========================================================================
REM   DANGER: wipes ALL VibeDocs data (projects, reports, users, uploads) and
REM   starts fresh. Use only if you want a clean slate.
REM ===========================================================================
setlocal
cd /d "%~dp0"
echo.
echo  *** WARNING - this DELETES every project, report and user. ***
echo.
set /p "CONFIRM=Type  YES  to wipe everything: "
if /i not "%CONFIRM%"=="YES" ( echo Cancelled. & pause & exit /b 0 )
echo.
echo Removing containers and data volumes...
docker compose down -v
echo.
echo Done. Run START.cmd to build a fresh installation.
echo.
pause
endlocal
