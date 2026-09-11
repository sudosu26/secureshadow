@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

:: Find Python command
set "PY_CMD="
where py >nul 2>&1 && set "PY_CMD=py"
if "%PY_CMD%"=="" where python >nul 2>&1 && set "PY_CMD=python"
if "%PY_CMD%"=="" where python3 >nul 2>&1 && set "PY_CMD=python3"

if "%PY_CMD%"=="" (
    echo Python not found. Install Python first.
    pause
    exit /b 1
)

echo Installing required packages...
%PY_CMD% -m pip install streamlit plotly networkx colorama
echo.
echo All dependencies installed. You can now run the dashboard.
pause