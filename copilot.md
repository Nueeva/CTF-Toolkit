# Copilot Guide

## Repository Context
This repository contains **CTF Toolkit v3.0 Apex**, a modular multi-domain TUI/CLI workbench and 106+ solver library for CTF challenges and authorized security labs.
Penjelasan singkat: repo ini untuk penyelesaian soal CTF, analisis offline, dan pembelajaran keamanan siber.

## Scope & Boundaries
- Use this project for challenge solving, offline analysis, and defensive learning.
- Keep core solver primitives in `ctf_toolkit/<domain>/` pure and decoupled from interactive `input()` prompts so they remain scriptable and testable.
- Keep changes minimal, well-typed, and covered by deterministic tests in `tests/`.

## Preferred Workflow
1. Explore related files first (`ctf_toolkit/`, `docs/`, `tests/`).
2. Apply clean, surgical changes.
3. Validate using `python run_tests.py`.
4. Keep output concise, actionable, and cross-platform compatible (Windows PowerShell/CMD, Linux, macOS).

## Do / Don't
### Do
- Maintain bilingual clarity when editing docs (English structure, Indonesian notes allowed).
- Preserve menu/domain naming from `ctf_toolkit/registry.py` and catalog indexing in `ctf_toolkit/ui/palette.py`.
- Use local assets under `docs/assets/` for CLI screenshots.

### Don't
- Don’t break backward compatibility with numeric menu navigation (`1`–`9`, `0`) or headless CLI subcommands (`triage`, `recipe`, `magic`).
- Don’t break relative links in `README.md` or `docs/*.md`.

## Validation Commands (Cross-Platform)
```bash
# Run all unit & synthetic twin tests (Windows, Linux, macOS)
python run_tests.py

# Quick smoke check (Linux/macOS Bash)
printf '0\n' | python3 main.py

# Quick smoke check (Windows PowerShell)
"0" | .\ctf.ps1
```

## Related Docs
- Main project readme: [`README.md`](README.md)
- TUI & CLI guide: [`docs/TUI_AND_CLI_GUIDE.md`](docs/TUI_AND_CLI_GUIDE.md)
- Solver catalog: [`docs/SOLVER_CATALOG.md`](docs/SOLVER_CATALOG.md)
- Complementary Claude guidance: [`claude.md`](claude.md)
