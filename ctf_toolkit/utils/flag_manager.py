from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

# Default built-in formats verified across major global CTFs & national editions
DEFAULT_FLAG_TEMPLATES: list[dict[str, Any]] = [
    {"name": "GETSFLAG", "pattern": r"GETSFLAG\{[^}\n]+\}", "priority": 100, "builtin": True},
    {"name": "picoCTF", "pattern": r"picoCTF\{[^}\n]+\}", "priority": 95, "builtin": True},
    {"name": "HTB Academy", "pattern": r"academy\{[^}\n]+\}", "priority": 92, "builtin": True},
    {"name": "HTB / CHTB", "pattern": r"(?:HTB|CHTB)\{[^}\n]+\}", "priority": 90, "builtin": True},
    {"name": "LKS Jakarta Timur", "pattern": r"LKSJAKTIM\{[^}\n]+\}", "priority": 88, "builtin": True},
    {"name": "LKS Nasional / Wilayah", "pattern": r"LKS\{[^}\n]+\}", "priority": 87, "builtin": True},
    {"name": "THM", "pattern": r"THM\{[^}\n]+\}", "priority": 85, "builtin": True},
    {"name": "Standard FLAG", "pattern": r"FLAG\{[^}\n]+\}", "priority": 80, "builtin": True},
    {"name": "Standard CTF", "pattern": r"CTF\{[^}\n]+\}", "priority": 75, "builtin": True},
    {"name": "Short CT", "pattern": r"CT\{[^}\n]+\}", "priority": 70, "builtin": True},
    {"name": "CTFlearn", "pattern": r"CTFlearn\{[^}\n]+\}", "priority": 65, "builtin": True},
    {"name": "Major Recurring (DICE, ASIS, SEKAI, etc.)", "pattern": r"(?:DICE|HOPE|ASIS|SEKAI|OOO|ARKAV|LACTF|ACTF)\{[^}\n]+\}", "priority": 60, "builtin": True},
    {"name": "Indonesian Editions (COMPFEST, GEMASTIK, etc.)", "pattern": r"(?:TECHCOMFEST\d*|COMPFEST\d*|GEMASTIK\d*|WRECKIT\d*|HOLOGY\d*|SLASHROOT\d*|HIDC\d*|ARA\d*)\{[^}\n]+\}", "priority": 55, "builtin": True},
]

CONFIG_FILE_PATH = Path.home() / ".ctf_toolkit_flags.json"


class IntelligentFlagManager:
    """
    Commercial-grade, dynamic flag format management system.
    Supports user custom templates, priority ordering, compiled regex caches,
    safe loading/saving, and low false-positive heuristics.
    """

    def __init__(self, config_path: Path | str | None = None) -> None:
        self.config_path = Path(config_path) if config_path else CONFIG_FILE_PATH
        self.templates: list[dict[str, Any]] = []
        self._compiled_regexes: list[tuple[str, int, re.Pattern[str]]] = []
        self.load_templates()

    def load_templates(self) -> None:
        """Load templates from persistent JSON config or default to built-ins."""
        if self.config_path.exists():
            try:
                data = json.loads(self.config_path.read_text(encoding="utf-8"))
                if isinstance(data, list) and data:
                    self.templates = data
                else:
                    self.templates = [dict(t) for t in DEFAULT_FLAG_TEMPLATES]
            except Exception:
                self.templates = [dict(t) for t in DEFAULT_FLAG_TEMPLATES]
        else:
            self.templates = [dict(t) for t in DEFAULT_FLAG_TEMPLATES]
        self._recompile()

    def save_templates(self) -> None:
        """Save templates to persistent JSON file."""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            self.config_path.write_text(json.dumps(self.templates, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _recompile(self) -> None:
        """Sort by priority descending and precompile regex objects."""
        self.templates.sort(key=lambda t: t.get("priority", 0), reverse=True)
        self._compiled_regexes = []
        for t in self.templates:
            name = t.get("name", "Custom")
            prio = t.get("priority", 0)
            patt = t.get("pattern", "")
            try:
                compiled = re.compile(patt, re.IGNORECASE)
                self._compiled_regexes.append((name, prio, compiled))
            except re.error:
                continue

    def add_template(self, name: str, pattern: str, priority: int = 50) -> bool:
        """Add a custom flag template with syntax validation."""
        try:
            re.compile(pattern)
        except re.error as err:
            raise ValueError(f"Invalid regex pattern: {err}") from err

        # Remove existing with same name if any
        self.templates = [t for t in self.templates if t.get("name") != name]
        self.templates.append({
            "name": name,
            "pattern": pattern,
            "priority": priority,
            "builtin": False,
        })
        self._recompile()
        self.save_templates()
        return True

    def remove_template(self, name: str) -> bool:
        """Remove a template by name (prevent removing all templates)."""
        new_list = [t for t in self.templates if t.get("name") != name]
        if not new_list:
            return False
        self.templates = new_list
        self._recompile()
        self.save_templates()
        return True

    def reset_to_defaults(self) -> None:
        """Reset template configuration back to built-in presets."""
        self.templates = [dict(t) for t in DEFAULT_FLAG_TEMPLATES]
        self._recompile()
        self.save_templates()

    def extract_flags(self, text: str | bytes) -> list[dict[str, Any]]:
        """
        Extract all flags matching configured templates in priority order.
        Returns ordered list of matches: [{"name", "priority", "flag", "start", "end"}]
        """
        if isinstance(text, bytes):
            text = text.decode("utf-8", errors="ignore")

        discovered: list[dict[str, Any]] = []
        seen_spans: set[tuple[int, int]] = set()

        for name, prio, regex in self._compiled_regexes:
            for m in regex.finditer(text):
                span = m.span()
                # Check overlapping spans to prevent duplicate captures with lower priority
                if any(s[0] <= span[0] and span[1] <= s[1] for s in seen_spans):
                    continue
                seen_spans.add(span)
                discovered.append({
                    "template": name,
                    "priority": prio,
                    "flag": m.group(0),
                    "start": span[0],
                    "end": span[1],
                })

        return discovered

    def find_first_flag(self, text: str | bytes) -> str | None:
        """Quickly retrieve highest-priority matching flag, or None."""
        matches = self.extract_flags(text)
        return matches[0]["flag"] if matches else None


# Global singleton instance
_GLOBAL_FLAG_MANAGER: IntelligentFlagManager | None = None


def get_flag_manager() -> IntelligentFlagManager:
    global _GLOBAL_FLAG_MANAGER
    if _GLOBAL_FLAG_MANAGER is None:
        _GLOBAL_FLAG_MANAGER = IntelligentFlagManager()
    return _GLOBAL_FLAG_MANAGER
