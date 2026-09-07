@echo off
setlocal
set "LAUNCHER=%~dp0start.ps1"
set "BACKEND_PORT=8000"
set "FRONTEND_PORT=5173"
set "OPTIONS="

:parse
if "%~1"=="" goto launch
if /i "%~1"=="--backend-port" goto backend
if /i "%~1"=="-b" goto backend
if /i "%~1"=="--frontend-port" goto frontend
if /i "%~1"=="-f" goto frontend
if /i "%~1"=="--check" goto check
if /i "%~1"=="--stop" goto stop
if /i "%~1"=="--install" goto install
if /i "%~1"=="--no-browser" goto no_browser
if /i "%~1"=="--help" goto help
echo ERROR: Unknown option "%~1". Run start.bat --help.
exit /b 2

:backend
if "%~2"=="" goto missing_value
set "BACKEND_PORT=%~2"
shift
shift
goto parse

:frontend
if "%~2"=="" goto missing_value
set "FRONTEND_PORT=%~2"
shift
shift
goto parse

:check
set "OPTIONS=%OPTIONS% -Check"
shift
goto parse

:stop
set "OPTIONS=%OPTIONS% -Stop"
shift
goto parse

:install
set "OPTIONS=%OPTIONS% -InstallDependencies"
shift
goto parse

:no_browser
set "OPTIONS=%OPTIONS% -NoBrowser"
shift
goto parse

:help
powershell.exe -NoProfile -File "%LAUNCHER%" -Help
exit /b %errorlevel%

:missing_value
echo ERROR: A port number is required after "%~1".
exit /b 2

:launch
powershell.exe -NoProfile -File "%LAUNCHER%" -BackendPort "%BACKEND_PORT%" -FrontendPort "%FRONTEND_PORT%" %OPTIONS%
exit /b %errorlevel%
