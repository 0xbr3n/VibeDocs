@echo off
REM ===========================================================================
REM   VibeDocs — ONE-CLICK LAUNCHER (Windows / Docker Desktop)
REM   Double-click this file. It builds and starts everything, picks a free
REM   port automatically, then opens your browser.
REM ===========================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo.
echo  ============================================================
echo    VibeDocs  -  a vibecoded report generator by Brendon Teo
echo  ============================================================
echo.

echo  [1/5] Checking Docker Desktop...
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

echo  [2/5] Preparing configuration...
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

echo  [3/5] Choosing free ports...
REM Reuse the port our app is already published on (if it's already running),
REM otherwise find the first free port from the default up.
set "PORT="
for /f "tokens=2 delims=:" %%p in ('docker port vibedocs_app 8000/tcp 2^>nul') do if not defined PORT set "PORT=%%p"
if not defined PORT (
    set /a PORT=8000
    :findapp
    netstat -ano | findstr ":!PORT! " | findstr LISTENING >nul 2>&1
    if not errorlevel 1 ( set /a PORT+=1 & goto findapp )
)
set "MPORT="
for /f "tokens=2 delims=:" %%p in ('docker port vibedocs_mailpit 8025/tcp 2^>nul') do if not defined MPORT set "MPORT=%%p"
if not defined MPORT (
    set /a MPORT=8025
    :findmp
    netstat -ano | findstr ":!MPORT! " | findstr LISTENING >nul 2>&1
    if not errorlevel 1 ( set /a MPORT+=1 & goto findmp )
)
REM These shell vars override the .env values for docker compose.
set "APP_PORT=!PORT!"
set "MAILPIT_UI_PORT=!MPORT!"
set "APPURL=http://localhost:!PORT!"
echo       OK - web app -^> port !PORT!,  mail inbox -^> port !MPORT!
echo.

echo  [4/5] Building and starting (first build can take 3-6 minutes)...
echo.
docker compose up -d --build
if errorlevel 1 (
    echo.
    echo   X  Build or startup failed. Scroll up for the error.
    pause
    exit /b 1
)
echo.

echo  [5/5] Waiting for first-boot seeding...
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
echo    Web app .........  http://localhost:!PORT!
echo    Email inbox .....  http://localhost:!MPORT!  (Mailpit)
echo.
echo    First login:   admin  /  change_me_now
echo    ^>^> Change this password right after logging in.
echo.
echo    STOP.cmd = stop   LOGS.cmd = logs   RESET.cmd = wipe + restart
echo.
pause
endlocal
