#!/usr/bin/env pwsh
# CTF-Toolkit v4.0 Apex - Windows PowerShell Launcher
$ErrorActionPreference = "Stop"

# Ensure UTF-8 console encoding for Unicode borders & sparklines
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$VenvPythonWin = Join-Path $ScriptDir ".venv\Scripts\python.exe"
$VenvPythonPosix = Join-Path $ScriptDir ".venv/bin/python"
$MainPy = Join-Path $ScriptDir "main.py"

if (Test-Path $VenvPythonWin) {
    & $VenvPythonWin $MainPy @args
} elseif (Test-Path $VenvPythonPosix) {
    & $VenvPythonPosix $MainPy @args
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    & python $MainPy @args
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    & python3 $MainPy @args
} else {
    Write-Error "Python 3.10+ tidak ditemukan di PATH."
    exit 1
}
exit $LASTEXITCODE
