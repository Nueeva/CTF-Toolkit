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
- Verify README links and image paths are valid.
- Ensure CLI screenshots in docs come from real toolkit output.
- Run baseline validation when code/runtime behavior is involved.

## Validation Commands
```bash
python3 -m py_compile $(find . -name '*.py' -not -path './.venv/*')
printf '0\n' | python3 main.py
```

## Related Docs
- Main project readme: [`README.md`](README.md)
- Copilot guidance: [`copilot.md`](copilot.md)
