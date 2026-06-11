@echo off
REM ===========================================================================
REM   VibeDocs — ONE-CLICK LAUNCHER (Windows / Docker Desktop)
REM   Double-click this file. It builds and starts everything, then opens your
REM   browser at http://localhost:8000
REM ===========================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"
set "APPURL=http://localhost:8000"

echo.
echo  ============================================================
echo    VibeDocs  -  a vibecoded report generator by Brendon Teo
echo  ============================================================
echo.

echo  [1/4] Checking Docker Desktop...
docker version >nul 2>&1
if errorlevel 1 (
    echo.
    echo   X  Docker is not running. Install / start Docker Desktop first:
    echo        https://www.docker.com/products/docker-desktop
    echo      Then double-click START.cmd again.
    echo.
    pause
    exit /b 1
)
echo       OK - Docker is running.
echo.

echo  [2/4] Preparing configuration...
if not exist ".env" (
    echo       First run - generating unique local secrets...
    for /f "delims=" %%S in ('powershell -NoProfile -Command "-join ((48..57)+(65..90)+(97..122) ^| Get-Random -Count 64 ^| ForEach-Object {[char]$_})"') do set "GEN_SECRET=%%S"
    for /f "delims=" %%P in ('powershell -NoProfile -Command "-join ((48..57)+(65..90)+(97..122) ^| Get-Random -Count 24 ^| ForEach-Object {[char]$_})"') do set "GEN_DBPW=%%P"
    (
        echo # Auto-generated local secrets. Safe to keep; delete to regenerate.
        echo POSTGRES_USER=vibedocs
        echo POSTGRES_PASSWORD=!GEN_DBPW!
        echo POSTGRES_DB=vibedocs
        echo SECRET_KEY=!GEN_SECRET!
        echo APP_PORT=8000
        echo MAILPIT_UI_PORT=8025
        echo ENV=production
        echo AUTH_PROVIDER=local
    ) > ".env"
    echo       OK - wrote .env
) else (
    echo       OK - using existing .env
)
echo.

echo  [3/4] Building and starting (first build can take 3-6 minutes)...
echo.
docker compose up -d --build
if errorlevel 1 (
    echo.
    echo   X  Build or startup failed. Scroll up for the error.
    pause
    exit /b 1
)
echo.

echo  [4/4] Waiting for first-boot seeding...
set /a TRIES=0
:WAITLOOP
set /a TRIES+=1
powershell -NoProfile -Command "try { $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 '%APPURL%/health'; if ($r.StatusCode -eq 200) { exit 0 } else { exit 1 } } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 goto READY
if !TRIES! geq 60 ( echo   ! Taking longer than usual - check LOGS.cmd. & goto DONE )
<nul set /p "=."
timeout /t 3 >nul
goto WAITLOOP
:READY
echo       OK - the app is up.
start "" "%APPURL%"

:DONE
echo.
echo  ============================================================
echo    READY!   VibeDocs is running.
echo  ============================================================
echo    Web app .........  %APPURL%
echo    Email inbox .....  http://localhost:8025  (Mailpit)
echo.
echo    First login:   admin  /  change_me_now
echo    ^>^> Change this password right after logging in.
echo.
echo    STOP.cmd = stop   LOGS.cmd = logs   RESET.cmd = wipe + restart
echo.
pause
endlocal
