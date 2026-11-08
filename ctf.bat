@echo off
REM CTF-Toolkit v3.0 Apex - Windows Command Prompt Launcher
chcp 65001 >nul 2>&1
set PYTHONIOENCODING=utf-8
set SCRIPT_DIR=%~dp0

if exist "%SCRIPT_DIR%.venv\Scripts\python.exe" (
    "%SCRIPT_DIR%.venv\Scripts\python.exe" "%SCRIPT_DIR%main.py" %*
    exit /b %ERRORLEVEL%
)

where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    python "%SCRIPT_DIR%main.py" %*
    exit /b %ERRORLEVEL%
)

where py >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    py -3 "%SCRIPT_DIR%main.py" %*
    exit /b %ERRORLEVEL%
)

echo [-] Error: Python 3.10+ tidak ditemukan di PATH.
exit /b 1
