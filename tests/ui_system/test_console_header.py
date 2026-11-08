"""Regression test: the interactive TUI header must render under rich.

Field report 2026-11-08 (first external tester): launching the TUI
crashed with rich.errors.MarkupError, "Closing tag '[/dim]' ... doesn't
match any open tag". The hotkey hint cell in render_header contained the
literal text [/] (the Search hotkey), which rich parsed as a closing
markup tag. The literals are now escaped; this test renders the real
header through a real rich Console so the suite catches a regression.

NOTE: run_tests.py only discovers module-level test_* functions.
"""
import io

from rich.console import Console

from ctf_toolkit.ui import console as ui_console


def test_render_header_rich_no_markup_error():
    buf = io.StringIO()
    old = ui_console._CONSOLE
    ui_console._CONSOLE = Console(file=buf, width=110, force_terminal=False)
    try:
        ui_console.render_header("Main Hub")
    finally:
        ui_console._CONSOLE = old
    out = buf.getvalue()
    assert "APEX CTF WORKBENCH" in out
    assert "Search Tools" in out
    assert "[/]" in out
