from __future__ import annotations

import importlib
import inspect
import pkgutil
from pathlib import Path
from typing import Any

from ctf_toolkit.ui.console import (
    HAS_RICH,
    get_rich_console,
    console_info,
    console_success,
    console_warn,
    console_error,
)
from ctf_toolkit.ui.inspector import inspect_output
from ctf_toolkit.ui.session import resolve_smart_input

try:
    from rich.table import Table
    from rich import box
except ImportError:
    pass


ENGINE_PACKAGES: tuple[str, ...] = (
    "ctf_toolkit.crypto",
    "ctf_toolkit.forensics",
    "ctf_toolkit.reversing",
    "ctf_toolkit.web",
    "ctf_toolkit.pwn",
    "ctf_toolkit.binex",
    "ctf_toolkit.blockchain",
    "ctf_toolkit.osint_misc",
    "ctf_toolkit.defensive",
    "ctf_toolkit.utils",
)

STANDALONE_MODULES: tuple[str, ...] = (
    "ctf_toolkit.triage",
    "ctf_toolkit.pipeline",
)

EXCLUDED_MODULE_SUFFIXES: tuple[str, ...] = (
    ".menu",
    ".io",
)

_CACHED_CATALOG: list[dict[str, Any]] | None = None


def _discover_engine_modules() -> list[str]:
    """Discover all non-UI engine modules across ctf_toolkit."""
    modules: list[str] = list(STANDALONE_MODULES)
    root_dir = Path(__file__).resolve().parent.parent

    for pkg_name in ENGINE_PACKAGES:
        rel_pkg = pkg_name.split(".", 1)[1]
        pkg_path = root_dir / rel_pkg
        if not pkg_path.exists():
            continue
        modules.append(pkg_name)
        for mod_info in pkgutil.walk_packages([str(pkg_path)], prefix=f"{pkg_name}."):
            if any(mod_info.name.endswith(sfx) for sfx in EXCLUDED_MODULE_SUFFIXES):
                continue
            modules.append(mod_info.name)
    return modules


def build_tool_catalog(force_refresh: bool = False) -> list[dict[str, Any]]:
    """Dynamically index all public CTF solver functions across all engine domains."""
    global _CACHED_CATALOG
    if _CACHED_CATALOG is not None and not force_refresh:
        return _CACHED_CATALOG

    catalog: list[dict[str, Any]] = []
    seen_funcs: set[str] = set()

    for mod_name in _discover_engine_modules():
        try:
            mod = importlib.import_module(mod_name)
        except Exception:
            continue

        parts = mod_name.split(".")
        domain = parts[1] if len(parts) > 1 else parts[0]
        submod = parts[-1]
        category = f"{domain}.{submod}" if domain != submod else domain

        for attr_name, obj in inspect.getmembers(mod, inspect.isfunction):
            if attr_name.startswith("_"):
                continue
            # Only index functions defined inside ctf_toolkit
            obj_mod = getattr(obj, "__module__", "") or ""
            if not obj_mod.startswith("ctf_toolkit."):
                continue
            if any(obj_mod.endswith(sfx) for sfx in EXCLUDED_MODULE_SUFFIXES):
                continue
            if ".ui." in obj_mod:
                continue
            if attr_name in seen_funcs:
                continue

            seen_funcs.add(attr_name)
            doc_lines = [line.strip() for line in (obj.__doc__ or "").strip().splitlines() if line.strip()]
            doc = doc_lines[0] if doc_lines else f"Solver {attr_name} ({obj_mod})"
            catalog.append({
                "name": attr_name,
                "module": obj_mod,
                "category": category,
                "func": obj,
                "doc": doc,
            })

    catalog.sort(key=lambda item: (item["category"], item["name"]))
    _CACHED_CATALOG = catalog
    return catalog


def fuzzy_search_tools(query: str, catalog: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Match query against function name, module/category, and docstring."""
    if catalog is None:
        catalog = build_tool_catalog()
    q = query.lower().strip()
    if not q:
        return catalog[:25]

    matches = []
    tokens = q.split()
    for tool in catalog:
        name_lower = tool["name"].lower()
        cat_lower = tool["category"].lower()
        mod_lower = tool["module"].lower()
        doc_lower = tool["doc"].lower()
        haystack = f"{name_lower} {cat_lower} {mod_lower} {doc_lower}"

        score = 0
        if q == name_lower:
            score += 120
        elif name_lower.startswith(q):
            score += 70
        elif q in name_lower:
            score += 45
        elif q in cat_lower or q in mod_lower:
            score += 30
        elif q in doc_lower:
            score += 15
        elif len(tokens) > 1 and all(tok in haystack for tok in tokens):
            score += 25

        if score > 0:
            matches.append((score, tool["name"], tool))

    matches.sort(key=lambda x: (-x[0], x[1]))
    return [m[2] for m in matches]


def coerce_arg_value(raw: str, param: inspect.Parameter) -> Any:
    """Resolve smart input and coerce to parameter type annotation."""
    ann = param.annotation
    ann_str = str(ann)
    as_bytes = ann is bytes or ("bytes" in ann_str and "str" not in ann_str)
    val: Any = resolve_smart_input(raw, as_bytes=as_bytes)

    if (ann is int or ann_str == "int") and isinstance(val, str):
        try:
            return int(val, 0)
        except Exception:
            return val
    if (ann is float or ann_str == "float") and isinstance(val, str):
        try:
            return float(val)
        except Exception:
            return val
    if (ann is bool or ann_str == "bool") and isinstance(val, str):
        return val.lower() in ("1", "true", "yes", "y", "on")
    return val


def run_tool_interactive(tool: dict[str, Any]) -> None:
    """Prompt for function arguments dynamically using inspect.signature and run tool."""
    fn = tool["func"]
    sig = inspect.signature(fn)
    console_info(f"Running: [bold cyan]{tool['name']}[/bold cyan] ({tool['module']})")
    if tool["doc"]:
        print(f"  Description: {tool['doc']}")

    kwargs: dict[str, Any] = {}
    for param_name, param in sig.parameters.items():
        if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue

        default_str = f" [default: {param.default}]" if param.default != inspect.Parameter.empty else ""
        prompt = f"  Parameter '{param_name}'{default_str} ($last, @file, hex:, etc.): "
        raw = input(prompt).strip()

        if not raw and param.default != inspect.Parameter.empty:
            kwargs[param_name] = param.default
            continue

        kwargs[param_name] = coerce_arg_value(raw, param)

    try:
        console_info(f"Executing {tool['name']}...")
        result = fn(**kwargs)
        inspect_output(result, title=f"{tool['name']} Output", op_name=tool['name'])
    except Exception as e:
        console_error(f"Error executing {tool['name']}: {e}")


def palette_interactive(initial_query: str = "") -> None:
    """Command Palette interactive loop: search and run any CTF abstraction."""
    catalog = build_tool_catalog()
    query = initial_query.strip().lstrip("/")

    while True:
        if not query:
            query = input(f"\n[Command Palette - {len(catalog)} tools] Kata kunci pencarian ('q' keluar): ").strip().lstrip("/")
            if query.lower() in ("q", "quit", "exit", "0"):
                return

        results = fuzzy_search_tools(query, catalog)
        if not results:
            console_warn(f"Tidak ada tool yang cocok dengan '{query}'. Coba kata kunci lain.")
            query = ""
            continue

        console = get_rich_console()
        if HAS_RICH and console:
            table = Table(
                title=f"Command Palette: {len(results)} match(es) for '{query}' (Total indexed: {len(catalog)})",
                box=box.ROUNDED,
                border_style="bright_blue",
            )
            table.add_column("#", style="bold yellow", width=4, justify="right")
            table.add_column("Tool / Function Name", style="bold cyan", width=30)
            table.add_column("Domain / Module", style="magenta", width=22)
            table.add_column("Description", style="white")

            for i, r in enumerate(results[:20], 1):
                table.add_row(str(i), r["name"], r["category"], r["doc"][:60])
            console.print(table)
        else:
            print(f"\n--- Found {len(results)} tool(s) for '{query}' ---")
            for i, r in enumerate(results[:20], 1):
                print(f"  [{i}] {r['name']} ({r['category']}): {r['doc'][:55]}")

        choice = input("\nPilih nomor tool untuk dieksekusi (atau '/' cari lagi, '0' kembali): ").strip()
        if choice in ("0", "q", "exit"):
            return
        if choice.startswith("/"):
            query = choice.lstrip("/")
            continue

        try:
            idx = int(choice)
            if 1 <= idx <= len(results[:20]):
                run_tool_interactive(results[idx - 1])
                return
            else:
                console_warn("Nomor tidak valid.")
        except ValueError:
            query = choice
