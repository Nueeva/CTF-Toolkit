"""Import guard: every module in the package must import cleanly.

Field find 2026-11-08 (cue feature sweep): ctf_toolkit.ui.osint_misc.menu
imported a helper (read_text_file) that did not exist in
ctf_toolkit.utils.io, so choosing "OSINT & Misc" in the interactive TUI
crashed with ImportError. No test imported that menu module, so the
suite stayed green. This guard walks the whole package so a broken
import anywhere fails the suite.

NOTE: run_tests.py only discovers module-level test_* functions.
"""
import importlib
import pkgutil

import ctf_toolkit


def test_all_modules_import_cleanly():
    failures = []
    for mod in pkgutil.walk_packages(ctf_toolkit.__path__, "ctf_toolkit."):
        try:
            importlib.import_module(mod.name)
        except Exception as exc:  # noqa: BLE001 - report every failure
            failures.append(f"{mod.name}: {type(exc).__name__}: {exc}")
    assert not failures, "Broken module imports:\n" + "\n".join(failures)
