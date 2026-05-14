from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import Callable


@dataclass(frozen=True)
class MenuModule:
    key: str
    label: str
    loader: Callable[[], None]


def _lazy_loader(module_path: str) -> Callable[[], None]:
    def _run() -> None:
        menu_module = import_module(module_path)
        menu_module.menu()

    return _run


def get_menu_registry() -> list[MenuModule]:
    return [
        MenuModule("1", "Crypto", _lazy_loader("ctf_toolkit.ui.crypto.menu")),
        MenuModule("2", "BinEx", _lazy_loader("ctf_toolkit.ui.binex.menu")),
        MenuModule("3", "Web", _lazy_loader("ctf_toolkit.ui.web.menu")),
        MenuModule("4", "Forensics / RE", _lazy_loader("ctf_toolkit.ui.forensics.menu")),
        MenuModule("5", "Utilities", _lazy_loader("ctf_toolkit.ui.utilities.menu")),
        MenuModule("6", "Defensive / Blue Team", _lazy_loader("ctf_toolkit.ui.defensive.menu")),
    ]
