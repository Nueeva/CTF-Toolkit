# Copilot Guide

## Repository Context
This repository contains **CTF Toolkit v5.0**, a modular multi-domain TUI/CLI workbench, persistent **Evidence Workbench** (`ctf_toolkit/cases/`), optional private team collaboration host (`ctf_toolkit_team/`), and **560+ callable solver library** for CTF challenges and authorized security labs.
Penjelasan singkat: repo ini untuk penyelesaian soal CTF, manajemen bukti & analisis artefak offline/tim, serta pembelajaran keamanan siber.

## Scope & Boundaries
- Use this project for challenge solving, offline evidence analysis, and defensive learning.
- Keep core solver primitives in `ctf_toolkit/<domain>/` pure and decoupled from interactive `input()` prompts so they remain scriptable, callable via `ctf-toolkit call`, and testable.
- Keep optional Django/Uvicorn team host dependencies isolated in `ctf_toolkit_team/` and `ctf_toolkit/cases/team_host.py` so default installs and `python run_tests.py` remain lightweight.
- Keep changes minimal, well-typed, and covered by deterministic tests in `tests/` (and `qa/cases/` for Workbench/team features).

## Preferred Workflow
1. Explore related files first (`ctf_toolkit/`, `ctf_toolkit_team/`, `docs/`, `tests/`, `qa/`).
2. Apply clean, surgical changes.
3. Validate using `python run_tests.py` (and `pytest qa/cases` when modifying `ctf_toolkit/cases/` or `ctf_toolkit_team/`).
4. Keep output concise, actionable, and cross-platform compatible (Windows PowerShell/CMD, Linux, macOS).

## Do / Don't
### Do
- Maintain bilingual clarity when editing docs (English structure, Indonesian notes allowed).
- Preserve menu/domain naming from `ctf_toolkit/registry.py` and catalog indexing in `ctf_toolkit/ui/palette.py`.
- Use local assets under `docs/assets/` for CLI screenshots.

### Don't
- Don’t break backward compatibility with numeric menu navigation (`1`–`9`, `0`) or headless CLI subcommands (`case`, `team`, `doctor`, `triage`, `recipe`, `magic`, `call`, `trace`, `identify`, `flags`, `cheatsheet`, `server`, `writeup`, `train`).
- Don’t break relative links in `README.md` or `docs/*.md`.

## Validation Commands (Cross-Platform)
```bash
# Run all unit & synthetic twin tests (Windows, Linux, macOS)
python run_tests.py

# Check runtime parser detection & v5 case workbench
python -m ctf_toolkit doctor

# Quick smoke check (Linux/macOS Bash)
printf '0\n' | python3 main.py

# Quick smoke check (Windows PowerShell)
"0" | .\ctf.ps1
```

## Related Docs
- Main project readme: [`README.md`](README.md)
- v5 Evidence Workbench & private host guide: [`docs/CASE_WORKBENCH.md`](docs/CASE_WORKBENCH.md)
- TUI & CLI guide: [`docs/TUI_AND_CLI_GUIDE.md`](docs/TUI_AND_CLI_GUIDE.md)
- Solver catalog: [`docs/SOLVER_CATALOG.md`](docs/SOLVER_CATALOG.md)
- Platform install guide: [`docs/PLATFORM_INSTALL.md`](docs/PLATFORM_INSTALL.md)
- Architecture guide: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Complementary Claude guidance: [`claude.md`](claude.md)
