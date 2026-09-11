@echo off
setlocal enabledelayedexpansion

echo Starting SECURESHADOW Dashboard...
cd /d "%~dp0"

:: Try to find a working Python command
set "PY_CMD="

:: Check py first (official launcher)
where py >nul 2>&1
if %errorlevel% equ 0 (
    set "PY_CMD=py"
) else (
    :: Check python (Microsoft Store or PATH)
    where python >nul 2>&1
    if %errorlevel% equ 0 (
        set "PY_CMD=python"
    ) else (
        :: Check python3 (some custom installs)
        where python3 >nul 2>&1
        if %errorlevel% equ 0 (
            set "PY_CMD=python3"
        )
    )
)

if "%PY_CMD%"=="" (
    echo.
    echo ERROR: Python not found.
    echo Please install Python from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo Using Python command: %PY_CMD%
echo.

:: Run Streamlit
%PY_CMD% -m streamlit run streamlit_app.py

pause