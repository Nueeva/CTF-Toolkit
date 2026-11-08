# Claude Guide

## Task Interpretation
- If a user asks *what/how to approach*, provide a plan first.
- If user asks implementation, execute with minimal, complete changes.
- For doc-only tasks, prioritize structure, readability, and link integrity.

## Documentation-First Behavior
- Keep headings and structure in English.
- Descriptions/comments may include Indonesian for clarity.
- Prefer terminal-style professional tone for this repository identity.

## Security & Safety Guardrails
- Learning-first: CTF/lab/legal usage only.
- Avoid instructions that operationalize unauthorized exploitation.
- Be explicit about limitations for JWT decode, helper templates, and offline-only analyses.

## Execution Checklist Before Finalizing
- Confirm changed files match requested scope.
- Verify README links, `docs/*.md` guides, and image paths are valid.
- Ensure CLI screenshots in docs come from real toolkit output.
- Run baseline validation across all test suites when code/runtime behavior is involved.

## Validation Commands (Cross-Platform)
```bash
# Run full test suite (1,230+ tests across 118+ test files on Windows/Linux/macOS)
python run_tests.py

# Verify CLI version & portable .pyz bundle
python main.py --version
python scripts/build_portable.py
python dist/ctf-toolkit.pyz --version
```

## Related Docs
- Main project readme: [`README.md`](README.md)
- TUI & CLI guide: [`docs/TUI_AND_CLI_GUIDE.md`](docs/TUI_AND_CLI_GUIDE.md)
- Solver catalog: [`docs/SOLVER_CATALOG.md`](docs/SOLVER_CATALOG.md)
- Platform install guide: [`docs/PLATFORM_INSTALL.md`](docs/PLATFORM_INSTALL.md)
- Architecture guide: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Copilot guidance: [`copilot.md`](copilot.md)
