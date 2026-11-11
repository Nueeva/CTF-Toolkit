#!/usr/bin/env python3
"""Build the full-featured Apexsions workbench prototype.

Reads workbench_template.html, injects live catalog/flag/cheatsheet JSON,
writes output/ctf-toolkit-prototype.html. No f-strings for the HTML body --
placeholder tokens keep CSS/JS braces literal.
"""
import inspect
import json
import sys
from pathlib import Path

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))

from ctf_toolkit.ui.palette import build_tool_catalog
from ctf_toolkit.utils.flag_manager import get_flag_manager
from ctf_toolkit.web.cheatsheets import get_web_cheatsheet

HERE = Path(__file__).resolve().parent
TEMPLATE = str(HERE / "workbench_template.html")
OUTPUT = str(HERE / "prototype.html")


def safe_json(obj):
    """Escape < > so a payload string can never close the parent <script>."""
    return (
        json.dumps(obj, ensure_ascii=False)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


def main():
    catalog = build_tool_catalog()
    signatures = {}
    for item in catalog:
        try:
            sig = inspect.signature(item["func"])
            signatures[item["name"]] = [
                {
                    "n": p.name,
                    "d": "" if p.default is inspect.Parameter.empty else repr(p.default)[:40],
                    "req": p.default is inspect.Parameter.empty,
                }
                for p in sig.parameters.values()
                if p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)
            ]
        except (ValueError, TypeError):
            signatures[item["name"]] = []
    tools = [
        {
            "n": item["name"],
            "c": item["category"],
            "m": item["module"],
            "d": (item.get("doc") or "").strip()[:220],
            "s": signatures.get(item["name"], []),
        }
        for item in catalog
    ]

    flags = get_flag_manager().templates
    cheats = get_web_cheatsheet()

    with open(TEMPLATE, encoding="utf-8") as fh:
        html = fh.read()

    html = html.replace("__TOOLS_JSON__", safe_json(tools))
    html = html.replace("__FLAGS_JSON__", safe_json(flags))
    html = html.replace("__CHEATS_JSON__", safe_json(cheats))
    html = html.replace("__TOOL_COUNT__", str(len(tools)))

    with open(OUTPUT, "w", encoding="utf-8") as fh:
        fh.write(html)

    print(f"tools={len(tools)} flags={len(flags)} cheat_sets={len(cheats)}")
    print(f"bytes={len(html)}")
    print(f"script_tags={html.count('</script>')}")


if __name__ == "__main__":
    main()