from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from collections.abc import Iterable


def _resolve_pager_cmd() -> list[str] | None:
    pager = os.environ.get("PAGER", "").strip()
    if pager:
        return shlex.split(pager)
    if shutil.which("less"):
        return ["less", "-R"]
    if shutil.which("more"):
        return ["more"]
    return None


def page_text(text: str) -> None:
    pager_cmd = _resolve_pager_cmd()
    if not pager_cmd or not sys.stdout.isatty():
        print(text)
        return
    try:
        proc = subprocess.Popen(pager_cmd, stdin=subprocess.PIPE, text=True)
    except OSError:
        print(text)
        return
    try:
        if proc.stdin:
            proc.stdin.write(text)
            proc.stdin.close()
        proc.wait()
    except BrokenPipeError:
        return


def page_stream(chunks: Iterable[str]) -> None:
    pager_cmd = _resolve_pager_cmd()
    if not pager_cmd or not sys.stdout.isatty():
        for chunk in chunks:
            print(chunk, end="")
        return
    try:
        proc = subprocess.Popen(pager_cmd, stdin=subprocess.PIPE, text=True)
    except OSError:
        for chunk in chunks:
            print(chunk, end="")
        return
    try:
        if proc.stdin:
            for chunk in chunks:
                proc.stdin.write(chunk)
            proc.stdin.close()
        proc.wait()
    except BrokenPipeError:
        return
