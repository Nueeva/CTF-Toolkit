# Copilot Guide

## Repository Context
This repository contains a modular CLI toolkit for CTF learning and legal lab usage only.
Penjelasan singkat: repo ini untuk pembelajaran, bukan untuk serangan sistem nyata.

## Scope & Boundaries
- Use this project for challenge solving, offline analysis, and defensive learning.
- Do not add auto-exploit workflows or unsafe automation assumptions.
- Keep changes minimal and focused on the requested task.

## Preferred Workflow
1. Explore related files first.
2. Apply small, surgical changes.
3. Validate quickly using project commands.
4. Keep output concise, actionable, and safe.

## Output Style
- Professional and direct.
- Jelaskan langkah inti tanpa bertele-tele.
- Prioritize practical guidance over ornamental wording.

## Do / Don't
### Do
- Maintain bilingual clarity when editing docs (English structure, Indonesian notes allowed).
- Preserve menu/domain naming from the CLI registry.
- Use local assets under `docs/assets/` for CLI screenshots.

### Don't
- Don’t introduce legal-risk instructions for real targets.
- Don’t replace real CLI evidence with purely decorative mockups.
- Don’t break stable links in README.

## Validation Commands
Use these after Python or CLI-related changes:

```bash
python3 -m py_compile $(find . -name '*.py' -not -path './.venv/*')
printf '0\n' | python3 main.py
```

## Related Docs
- Main project readme: [`README.md`](README.md)
- Complementary Claude guidance: [`claude.md`](claude.md)
