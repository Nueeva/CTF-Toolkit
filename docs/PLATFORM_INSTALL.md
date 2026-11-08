# Cross-Platform Installation & Deployment Guide

`CTF-Toolkit v4.0 Apex` is engineered to run seamlessly across **Windows 10/11**, **Linux (Kali, Parrot, Ubuntu, Debian, Arch, WSL2)**, **macOS (Apple Silicon & Intel)**, **Docker containers**, and **air-gapped CTF jumpboxes**.

---

## 1. Windows (PowerShell & Command Prompt)

### Option A: Zero-Friction PowerShell / CMD Launcher
The repository includes native launchers (`ctf.ps1` and `ctf.bat`) that automatically configure Windows console UTF-8 encoding (`chcp 65001` / `PYTHONIOENCODING=utf-8`) so Unicode borders (`╭─╮`) and entropy sparklines (`▁▂▃▄▅▆▇█`) render cleanly without `UnicodeEncodeError`.

```powershell
# 1. Create and activate virtual environment (optional but recommended)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 2. Launch Interactive TUI v4 Apex Command Center
.\ctf.ps1

# 3. Run Headless CLI commands
.\ctf.ps1 --version
.\ctf.ps1 triage artifact.bin
.\ctf.ps1 recipe "b64d | xor:0x5a | flag_scan" -d "cVoxcVFFWlxXWlx="
.\ctf.ps1 magic -s "RkxBR3t3aW5kb3dzX3Bvd2Vyc2hlbGxfb2t9"
```

In classic **Command Prompt (`cmd.exe`)**:
```cmd
ctf.bat
ctf.bat recipe "b64d" -d "RkxBR3tjbWRfb2t9"
```

---

## 2. Linux (Kali / Ubuntu / Arch / WSL2) & macOS

```bash
# 1. Clone and set up virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Make launcher executable and run
chmod +x ctf.sh
./ctf.sh

# 3. Headless CLI usage
./ctf.sh triage suspicious.pcap
./ctf.sh recipe "hex_d | zlib_d" -i dump.hex
./ctf.sh magic @cipher.txt
```

---

## 3. Global CLI Installation (`pipx` / `uv` / `pip`)

To call `ctf-toolkit` or its short alias `ctft` from any directory on your system:

```bash
# Using pipx (recommended for Kali/Ubuntu/macOS/Windows)
pipx install .

# Or using uv
uv tool install .

# Or editable install inside an active environment
pip install -e .

# Now available globally:
ctf-toolkit
ctft --version
ctft magic -s "RkxBR3tnbG9iYWxfY2xpX3JlYWR5fQ=="
```

---

## 4. Portable Single-File `.pyz` Bundle (For Air-Gapped VMs & Remote SSH Boxes)

During on-site competitions (such as LKS, Gemastik, or restricted SSH jumpboxes) where `pip install` or internet access is unavailable, you can build a single self-contained Python ZIP application (`dist/ctf-toolkit.pyz`, ~130 KB):

```bash
# 1. Build the portable bundle on your host machine
python scripts/build_portable.py

# Output: dist/ctf-toolkit.pyz
```

Copy `dist/ctf-toolkit.pyz` to any target machine with Python 3.10+ installed and execute it directly:

```bash
# Run interactive TUI (automatically falls back to pure ANSI if 'rich' is not installed on target)
python3 ctf-toolkit.pyz

# Run headless pipelines & magic solver on the remote box
python3 ctf-toolkit.pyz triage ./mystery_binary
python3 ctf-toolkit.pyz recipe "b64d | rot13" -d "U0xOUnthdnJfcG9ydGFibGV9"
python3 ctf-toolkit.pyz magic -s "RkxBR3twb3J0YWJsZV9weXpfd29ya3N9"
```

---

## 5. Docker Container Mode

Run `CTF-Toolkit` inside an isolated `python:3.12-slim` container with your current challenge directory mounted to `/work`:

```bash
# Build the image
docker build -t ctf-toolkit:v4 .

# Launch interactive TUI with current folder mounted
docker run -it --rm -v "$(pwd):/work" ctf-toolkit:v4

# Run headless triage on a file in the current directory
docker run --rm -v "$(pwd):/work" ctf-toolkit:v4 triage /work/challenge.bin
```

On **Windows PowerShell**:
```powershell
docker run -it --rm -v "${PWD}:/work" ctf-toolkit:v4
```

---

## 6. Running the Test Suite Across Platforms

The repository includes a zero-dependency test runner (`run_tests.py`) that discovers and runs all **118+ test files (1,238+ tests)** across Windows, Linux, and macOS without requiring external test frameworks:

```bash
python run_tests.py
```

Install the development dependencies first (`pip install -r requirements-dev.txt`, or `pip install -e ".[dev]"`). One test — the portable-bundle builder — needs `shiv`; without it that single test is reported as skipped and the rest of the suite still runs to completion.
