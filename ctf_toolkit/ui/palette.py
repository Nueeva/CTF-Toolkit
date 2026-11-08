from __future__ import annotations

import importlib
import inspect
from typing import Any, Callable

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
    from rich.panel import Panel
    from rich import box
except ImportError:
    pass


CATALOG_SOURCES: list[tuple[str, list[str]]] = [
    (
        "ctf_toolkit.crypto.classical",
        [
            "caesar_decrypt", "caesar_bruteforce", "atbash", "vigenere_decrypt",
            "affine_decrypt", "bacon_decode", "polybius_decode", "hill_decrypt_2x2",
            "rail_fence_decrypt", "columnar_transposition_decrypt", "playfair_decrypt",
            "bifid_decrypt", "four_square_decrypt", "adfgvx_decrypt", "beaufort_decrypt",
            "scytale_decrypt", "rot_n", "xor_bytes", "morse_decode", "tap_code_decode",
        ],
    ),
    (
        "ctf_toolkit.crypto.rsa",
        [
            "rsa_solve_pqec", "rsa_solve_phi_e_c", "rsa_fermat", "rsa_wiener",
            "hastad_unpadded", "pollard_p_minus_1", "common_modulus_attack",
        ],
    ),
    (
        "ctf_toolkit.pwn",
        [
            "build_ret2win_payload", "build_variable_overwrite", "build_rop_chain",
            "leak_stack_offsets", "calculate_oob_offset", "cyclic", "cyclic_find",
        ],
    ),
    (
        "ctf_toolkit.web.helpers",
        [
            "build_sqli_payload", "build_ssti_payload", "build_ssrf_url",
            "build_lfi_path", "build_multipart_payload", "build_cors_request",
            "build_custom_verb_request", "build_json_post", "build_get_request",
            "base64_encode", "base64_decode",
        ],
    ),
    (
        "ctf_toolkit.forensics.office",
        ["extract_docx_metadata"],
    ),
    (
        "ctf_toolkit.forensics.artifact_discovery",
        ["extract_strings_from_object"],
    ),
    (
        "ctf_toolkit.osint_misc.parsers",
        ["ct_parser", "whois_parser", "html_comment_parser", "json_secrets", "landmark_matcher"],
    ),
    (
        "ctf_toolkit.osint_misc.config_hunter",
        [
            "extract_cron_secrets", "extract_sqlite_secrets", "extract_json_secrets",
            "extract_yaml_secrets", "extract_ini_secrets", "extract_csv_secrets",
        ],
    ),
    (
        "ctf_toolkit.blockchain.calldata",
        ["parse_calldata", "decode_revert_reason", "decode_calldata_charcodes"],
    ),
    (
        "ctf_toolkit.triage",
        ["triage_data", "triage_file"],
    ),
    (
        "ctf_toolkit.pipeline",
        ["run_recipe"],
    ),
]


def build_tool_catalog() -> list[dict[str, Any]]:
    """Index all curated CTF solver functions across domains."""
    catalog = []
    for mod_name, funcs in CATALOG_SOURCES:
        try:
            mod = importlib.import_module(mod_name)
            for fname in funcs:
                if hasattr(mod, fname):
                    fn = getattr(mod, fname)
                    doc = (fn.__doc__ or "").strip().split("\n")[0]
                    category = mod_name.split(".")[-1]
                    catalog.append({
                        "name": fname,
                        "module": mod_name,
                        "category": category,
                        "func": fn,
                        "doc": doc or f"Function {fname} from {category}",
                    })
        except Exception:
            continue
    return catalog


def fuzzy_search_tools(query: str, catalog: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Match query against function name, category, and docstring."""
    if catalog is None:
        catalog = build_tool_catalog()
    q = query.lower().strip()
    if not q:
        return catalog[:20]

    matches = []
    for tool in catalog:
        name_lower = tool["name"].lower()
        cat_lower = tool["category"].lower()
        doc_lower = tool["doc"].lower()

        score = 0
        if q == name_lower:
            score += 100
        elif name_lower.startswith(q):
            score += 50
        elif q in name_lower:
            score += 30
        elif q in cat_lower:
            score += 20
        elif q in doc_lower:
            score += 10

        if score > 0:
            matches.append((score, tool))

    matches.sort(key=lambda x: x[0], reverse=True)
    return [m[1] for m in matches]


def run_tool_interactive(tool: dict[str, Any]) -> None:
    """Prompt for function arguments dynamically using inspect.signature and run tool."""
    fn = tool["func"]
    sig = inspect.signature(fn)
    console_info(f"Running: [bold cyan]{tool['name']}[/bold cyan] ({tool['category']})")
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

        # Determine type
        ann = param.annotation
        as_bytes = ann in (bytes, "bytes", "bytes | None", "str | bytes", "bytes | str")
        val = resolve_smart_input(raw, as_bytes=as_bytes)

        # Type conversion
        if ann in (int, "int") and isinstance(val, str):
            try:
                val = int(val, 0)
            except Exception:
                pass
        elif ann in (float, "float") and isinstance(val, str):
            try:
                val = float(val)
            except Exception:
                pass

        kwargs[param_name] = val

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
            query = input("\n[🔍 Command Palette] Masukkan kata kunci pencarian (atau 'q' keluar): ").strip().lstrip("/")
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
                title=f"🔍 Command Palette: {len(results)} match(es) for '{query}'",
                box=box.ROUNDED,
                border_style="bright_blue",
            )
            table.add_column("#", style="bold yellow", width=4, justify="right")
            table.add_column("Tool / Function Name", style="bold cyan", width=28)
            table.add_column("Category", style="magenta", width=12)
            table.add_column("Docstring / Description", style="white")

            for i, r in enumerate(results[:15], 1):
                table.add_row(str(i), r["name"], r["category"], r["doc"][:55])
            console.print(table)
        else:
            print(f"\n--- Found {len(results)} tool(s) for '{query}' ---")
            for i, r in enumerate(results[:15], 1):
                print(f"  [{i}] {r['name']} ({r['category']}): {r['doc'][:50]}")

        choice = input("\nPilih nomor tool untuk dieksekusi (atau '/' cari lagi, '0' kembali): ").strip()
        if choice in ("0", "q", "exit"):
            return
        if choice.startswith("/"):
            query = choice.lstrip("/")
            continue

        try:
            idx = int(choice)
            if 1 <= idx <= len(results[:15]):
                run_tool_interactive(results[idx - 1])
                return
            else:
                console_warn("Nomor tidak valid.")
        except ValueError:
            query = choice
