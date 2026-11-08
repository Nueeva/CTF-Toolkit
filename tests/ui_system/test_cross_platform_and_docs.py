from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from ctf_toolkit import __version__
from ctf_toolkit.main_cli import build_parser, configure_utf8_console
from scripts.build_portable import build_pyz

ROOT_DIR = Path(__file__).resolve().parents[2]


def test_version_and_utf8_console():
    assert __version__ == "4.0.2"
    configure_utf8_console()
    assert os.environ.get("PYTHONIOENCODING", "").lower() == "utf-8"

    parser = build_parser()
    args = parser.parse_args(["magic", "-s", "RkxBR3t0ZXN0fQ==", "--depth", "2"])
    assert args.subcommand == "magic"
    assert args.depth == 2


def test_portable_pyz_builder_and_execution():
    with tempfile.TemporaryDirectory() as tmpdir:
        pyz_path = Path(tmpdir) / "ctf-toolkit-test.pyz"
        built = build_pyz(pyz_path)
        assert built.exists()
        assert built.stat().st_size > 10000

        # 1. Test --version on the portable .pyz archive
        proc_ver = subprocess.run(
            [sys.executable, str(built), "--version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert proc_ver.returncode == 0
        assert "4.0.2" in proc_ver.stdout

        # 2. Test headless recipe execution inside the portable .pyz archive
        proc_rec = subprocess.run(
            [sys.executable, str(built), "recipe", "b64d", "-d", "RkxBR3twb3J0YWJsZV9weXpfb2t9"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert proc_rec.returncode == 0
        assert "FLAG{portable_pyz_ok}" in proc_rec.stdout


def test_documentation_and_cross_platform_files_exist():
    required_files = [
        ROOT_DIR / "README.md",
        ROOT_DIR / "claude.md",
        ROOT_DIR / "copilot.md",
        ROOT_DIR / "pyproject.toml",
        ROOT_DIR / "requirements.txt",
        ROOT_DIR / "Dockerfile",
        ROOT_DIR / ".dockerignore",
        ROOT_DIR / "ctf.ps1",
        ROOT_DIR / "ctf.bat",
        ROOT_DIR / "ctf.sh",
        ROOT_DIR / "scripts" / "build_portable.py",
        ROOT_DIR / ".github" / "workflows" / "ci.yml",
        ROOT_DIR / "docs" / "TUI_AND_CLI_GUIDE.md",
        ROOT_DIR / "docs" / "SOLVER_CATALOG.md",
        ROOT_DIR / "docs" / "PLATFORM_INSTALL.md",
        ROOT_DIR / "docs" / "ARCHITECTURE.md",
    ]
    for fpath in required_files:
        assert fpath.exists(), f"Missing required file: {fpath}"


def test_markdown_local_links_integrity():
    md_files = [
        ROOT_DIR / "README.md",
        ROOT_DIR / "claude.md",
        ROOT_DIR / "copilot.md",
        ROOT_DIR / "docs" / "TUI_AND_CLI_GUIDE.md",
        ROOT_DIR / "docs" / "SOLVER_CATALOG.md",
        ROOT_DIR / "docs" / "PLATFORM_INSTALL.md",
        ROOT_DIR / "docs" / "ARCHITECTURE.md",
    ]
    link_pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")

    for md_file in md_files:
        content = md_file.read_text(encoding="utf-8")
        for match in link_pattern.finditer(content):
            target = match.group(1).strip()
            if (
                target.startswith("http://")
                or target.startswith("https://")
                or target.startswith("#")
                or target.startswith("file://")
                or target.startswith("mailto:")
            ):
                continue
            clean_target = target.split("#")[0]
            if not clean_target:
                continue
            resolved = (md_file.parent / clean_target).resolve()
            assert resolved.exists(), f"Broken relative link '{target}' in {md_file.name}"
