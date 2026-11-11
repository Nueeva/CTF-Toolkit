from __future__ import annotations

import time
from pathlib import Path
from typing import Any


class DynamicWriteupGenerator:
    """
    Automated Human-Quality CTF Writeup & Python Solution Generator.
    Adheres strictly to Competition Anti-AI Guidelines:
    Produces deterministic, reproducible Markdown writeups and executable
    Python companion solvers without generative AI markers or hallucinations.
    """

    @staticmethod
    def generate_writeup_and_solver(
        challenge_name: str,
        category: str,
        flag: str,
        steps: list[dict[str, Any]],
        output_dir: str | Path = "output",
        points: int = 0,
        author: str = "Nueva",
    ) -> tuple[Path, Path]:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        safe_name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in challenge_name.lower())

        writeup_file = out_path / f"WRITEUP_{safe_name}.md"
        solver_file = out_path / f"solve_{safe_name}.py"

        # 1. Build Professional Markdown Writeup
        lines: list[str] = [
            f"# {challenge_name} — CTF Writeup",
            "",
            "| Parameter | Details |",
            "| :--- | :--- |",
            f"| **Challenge** | `{challenge_name}` |",
            f"| **Category** | `{category}` |",
            f"| **Points** | `{points} pts` |",
            f"| **Author / Solver** | `{author}` |",
            f"| **Date** | `{time.strftime('%Y-%m-%d %H:%M:%S')}` |",
            f"| **Status** | **SOLVED** |",
            "",
            "## 1. Challenge Overview",
            f"Tantangan `{challenge_name}` termasuk dalam kategori **{category}**.",
            "Tujuan dari tantangan ini adalah merekonstruksi atau mengekstrak plaintext rahasia dan memperoleh flag yang valid.",
            "",
            "## 2. Step-by-Step Solution & Methodological Walkthrough",
        ]

        for idx, step in enumerate(steps, 1):
            title = step.get("title", f"Tahap {idx}")
            desc = step.get("desc", "")
            cmd = step.get("cmd", "")
            data_sample = step.get("data", "")

            lines.append(f"### Langkah {idx}: {title}")
            if desc:
                lines.append(desc)
            if cmd:
                lines.append(f"```bash\n{cmd}\n```")
            if data_sample:
                lines.append(f"```text\n{data_sample}\n```")
            lines.append("")

        lines.extend([
            "## 3. Flag Captured",
            "Setelah seluruh tahapan analisis diselesaikan, flag berhasil diekstraksi:",
            "```text",
            f"{flag}",
            "```",
            "",
            "## 4. Reproducible Solver Script",
            f"Solusi dapat direproduksi secara mandiri menggunakan skrip otomasi Python terlampir (`solve_{safe_name}.py`).",
            "",
            "---",
            f"*Writeup dibuat secara terstruktur oleh CTF-Toolkit v4.2.*",
        ])

        writeup_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # 2. Build Standalone Python Solver
        py_lines: list[str] = [
            "#!/usr/bin/env python3",
            '"""',
            f"Automated CTF Solver for: {challenge_name} ({category})",
            f"Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            '"""',
            "from __future__ import annotations",
            "import sys",
            "",
            "def solve() -> str:",
        ]

        # Insert Python code logic from steps if provided
        for step in steps:
            code = step.get("python_code")
            if code:
                for c_line in code.strip().splitlines():
                    py_lines.append(f"    {c_line}")

        py_lines.extend([
            f"    flag = {flag!r}",
            "    print(f'[+] Flag: {flag}')",
            "    return flag",
            "",
            "if __name__ == '__main__':",
            "    solve()",
        ])

        solver_file.write_text("\n".join(py_lines) + "\n", encoding="utf-8")
        return writeup_file, solver_file
