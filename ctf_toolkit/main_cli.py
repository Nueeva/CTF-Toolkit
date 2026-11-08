from __future__ import annotations

import argparse
import inspect
import json
import os
import sys

from ctf_toolkit import __version__
from ctf_toolkit.pipeline import run_recipe
from ctf_toolkit.registry import get_menu_registry
from ctf_toolkit.triage import triage_data, triage_file
from ctf_toolkit.ui.console import (
    render_header,
    render_menu_panel,
    console_info,
    console_success,
    console_warn,
    show_flag_vault_interactive,
    show_buffer_history_interactive,
)
from ctf_toolkit.ui.inspector import inspect_output
from ctf_toolkit.ui.magic_solver import magic_interactive, solve_magic, render_magic_tree
from ctf_toolkit.ui.palette import build_tool_catalog, coerce_arg_value, fuzzy_search_tools, palette_interactive
from ctf_toolkit.ui.session import (
    copy_to_clipboard,
    export_case_script,
    export_case_writeup,
    get_session,
    resolve_smart_input,
)
from ctf_toolkit.ui.workbench.menu import recipe_studio_interactive
from ctf_toolkit.utils.io import safe_input, success, warn


def configure_utf8_console() -> None:
    """Ensure stdout and stderr use UTF-8 encoding across Windows/Linux/macOS consoles."""
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def handle_global_hotkey(choice: str) -> bool:
    """Handle global TUI hotkeys (/, :m, :s, :f, :b, :c, :case, :export). Return True if handled."""
    if choice.startswith("/"):
        palette_interactive(choice)
        return True
    if choice in (":m", ":magic"):
        magic_interactive()
        return True
    if choice in (":s", ":studio"):
        recipe_studio_interactive()
        return True
    if choice in (":f", ":flags", ":vault"):
        show_flag_vault_interactive()
        return True
    if choice in (":b", ":buf", ":history"):
        show_buffer_history_interactive()
        return True
    if choice in (":c", ":copy"):
        last_val = get_session().registers.get("$last", "")
        if copy_to_clipboard(last_val):
            console_success("Buffer $last berhasil disalin ke clipboard OS!")
        else:
            console_warn("Gagal menyalin ke clipboard (clipboard tool tidak tersedia).")
        return True
    if choice.startswith(":case"):
        parts = choice.split(maxsplit=1)
        if len(parts) > 1:
            get_session().active_case = parts[1].strip()
            console_success(f"Active case diubah menjadi: [bold yellow]{get_session().active_case}[/bold yellow]")
        else:
            console_info(f"Active case saat ini: {get_session().active_case}")
        return True
    if choice in (":export", ":writeup"):
        f_sc = export_case_script()
        f_wr = export_case_writeup()
        console_success(f"Artefak berhasil diekspor:\n  - Script : {f_sc}\n  - Writeup: {f_wr}")
        return True
    return False


def show_main_menu() -> None:
    render_header("Apex Command Center")
    items = [(entry.key, entry.label) for entry in get_menu_registry()]
    items.append(("0", "Exit Toolkit"))
    render_menu_panel("Category Modules & Workbenches", items, subtitle="Tip: Ketik '/' untuk Command Palette, ':m' untuk Magic Solver")


def interactive_menu() -> None:
    while True:
        show_main_menu()
        choice = safe_input("Pilih opsi menu: ").strip()

        if choice == "0":
            success("Keluar dari toolkit. Bye!")
            return

        if handle_global_hotkey(choice):
            continue

        selected = next((entry for entry in get_menu_registry() if entry.key == choice), None)
        if selected is None:
            warn("Pilihan tidak valid, coba lagi.")
            continue

        selected.loader()


def handle_triage(args: argparse.Namespace) -> int:
    target = args.target or args.file
    if args.string is not None:
        report = triage_data(args.string.encode(), target_label="cli_arg")
    elif target:
        if os.path.exists(target):
            report = triage_file(target)
        else:
            report = triage_data(target.encode(), target_label="cli_raw")
    else:
        warn("Error: Harap berikan target file (-f / target) atau string (-s).")
        return 1

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.summary())
    return 0


def handle_recipe(args: argparse.Namespace) -> int:
    pipeline_str = args.pipeline
    data: bytes | str

    if args.input:
        if not os.path.exists(args.input):
            warn(f"Error: File input tidak ditemukan: {args.input}")
            return 1
        with open(args.input, "rb") as f:
            data = f.read()
    elif args.data is not None:
        data = args.data
    else:
        if not sys.stdin.isatty():
            data = sys.stdin.read()
        else:
            warn("Error: Harap berikan data melalui -d/--data, -i/--input, atau pipe stdin.")
            return 1

    try:
        result = run_recipe(pipeline_str, data)
    except Exception as e:
        warn(f"Error eksekusi resep: {e}")
        return 1

    if args.output:
        mode = "wb" if isinstance(result, bytes) else "w"
        encoding = None if isinstance(result, bytes) else "utf-8"
        with open(args.output, mode, encoding=encoding) as f:
            f.write(result)
        success(f"[+] Output tersimpan di: {args.output}")
    else:
        if isinstance(result, bytes):
            if args.raw:
                sys.stdout.buffer.write(result)
            else:
                try:
                    print(result.decode("utf-8"))
                except UnicodeDecodeError:
                    print(result.decode("latin-1", errors="replace"))
        else:
            print(str(result))
    return 0


def handle_magic(args: argparse.Namespace) -> int:
    target = args.target
    data: bytes

    if args.string is not None:
        data = resolve_smart_input(args.string, as_bytes=True)
    elif target:
        if os.path.exists(target):
            with open(target, "rb") as f:
                data = f.read()
        else:
            data = resolve_smart_input(target, as_bytes=True)
    else:
        if not sys.stdin.isatty():
            data = sys.stdin.buffer.read()
        else:
            warn("Error: Harap berikan target melalui argumen atau pipe stdin.")
            return 1

    console_info(f"Running Autonomous Magic Solver on {len(data)} bytes...")
    best_data, best_path, best_score, history = solve_magic(data, max_depth=args.depth)
    render_magic_tree(data, best_path, history)

    if best_path and best_path != ["(direct)"]:
        console_success(f"Solusi ditemukan via: {' -> '.join(best_path)} (Score: {best_score:.1f})")
    inspect_output(best_data, title=f"Magic Result ({' -> '.join(best_path)})", op_name="magic_cli")
    return 0


def handle_call(args: argparse.Namespace) -> int:
    """Invoke any indexed solver function directly from the CLI."""
    catalog = build_tool_catalog()
    if getattr(args, "list", False) or not (args.function_name or "").strip():
        filter_query = (args.function_name or "").strip().lower()
        if filter_query:
            matched = [
                t for t in catalog
                if filter_query in t["name"].lower()
                or filter_query in t.get("category", "").lower()
                or (t.get("doc") and filter_query in t["doc"].lower())
            ]
        else:
            matched = catalog

        for tool in matched:
            doc_first = (tool.get("doc") or "").strip().splitlines()[0] if tool.get("doc") else ""
            print(f"{tool['name']:<35} [{tool['category']}] {doc_first}")

        if filter_query:
            print(f"\nTotal: {len(matched)} matching functions found (filter: '{filter_query}').")
        else:
            print(f"\nTotal: {len(catalog)} functions indexed.")
        return 0
    func_name = args.function_name.strip()
    exact = next((t for t in catalog if t["name"] == func_name), None)
    if exact is None:
        matches = fuzzy_search_tools(func_name, catalog)
        if not matches:
            warn(f"Fungsi '{func_name}' tidak ditemukan di katalog ({len(catalog)} fungsi terindeks).")
            return 1
        exact = matches[0]

    fn = exact["func"]
    sig = inspect.signature(fn)
    params = [
        p for p in sig.parameters.values()
        if p.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
    ]

    pos_args = list(args.args or [])
    kwargs = {}
    pos_idx = 0
    for param in params:
        if pos_idx < len(pos_args):
            kwargs[param.name] = coerce_arg_value(pos_args[pos_idx], param)
            pos_idx += 1
        elif param.default != inspect.Parameter.empty:
            kwargs[param.name] = param.default
        else:
            warn(f"Missing required argument '{param.name}' for {exact['name']}.")
            return 1

    try:
        res = fn(**kwargs)
    except Exception as exc:
        warn(f"Error calling {exact['name']}: {exc}")
        return 1

    if args.json:
        if isinstance(res, bytes):
            print(json.dumps({"function": exact["name"], "hex": res.hex(), "utf8": res.decode("utf-8", errors="replace")}))
        else:
            print(json.dumps({"function": exact["name"], "result": res}, default=str, indent=2))
    else:
        inspect_output(res, title=f"{exact['name']} Result", op_name=exact["name"])
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctf-toolkit",
        description="CTF Toolkit v4.0 Apex - Headless Workbench & Multi-Domain Exploitation Suite",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"ctf-toolkit {__version__}",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Mode operasi")

    # Subcommand: interactive
    subparsers.add_parser("interactive", help="Buka TUI interactive menu (default jika tanpa argumen)")

    # Subcommand: triage
    triage_parser = subparsers.add_parser("triage", help="Auto-triage & heuristic fingerprinter")
    triage_parser.add_argument("target", nargs="?", default=None, help="File path atau string target untuk ditriage")
    triage_parser.add_argument("-f", "--file", dest="file", help="Path ke file target")
    triage_parser.add_argument("-s", "--string", dest="string", help="Raw string target")
    triage_parser.add_argument("--json", action="store_true", help="Output dalam format JSON")

    # Subcommand: recipe
    recipe_parser = subparsers.add_parser("recipe", help="CyberChef-style recipe chaining pipeline")
    recipe_parser.add_argument("pipeline", help="Rantai operasi, e.g. 'b64d | xor:0x5a | flag_scan'")
    recipe_parser.add_argument("-d", "--data", dest="data", help="Input string data")
    recipe_parser.add_argument("-i", "--input", dest="input", help="Input file path")
    recipe_parser.add_argument("-o", "--output", dest="output", help="Output file path")
    recipe_parser.add_argument("--raw", action="store_true", help="Output raw bytes tanpa decoding")

    # Subcommand: magic
    magic_parser = subparsers.add_parser("magic", help="Autonomous A* multi-hop solver (Ciphey-style)")
    magic_parser.add_argument("target", nargs="?", default=None, help="Target string, @file, hex:, or b64:")
    magic_parser.add_argument("-s", "--string", dest="string", help="Raw string target")
    magic_parser.add_argument("--depth", type=int, default=4, help="Max search tree depth (default 4)")

    # Subcommand: call
    call_parser = subparsers.add_parser("call", help="Panggil fungsi solver apa pun secara langsung via CLI")
    call_parser.add_argument("function_name", nargs="?", default="", help="Nama fungsi solver (mis. caesar_decrypt, solve_rsa_auto)")
    call_parser.add_argument("args", nargs="*", help="Argumen posisi fungsi (mendukung @file, hex:, b64:, $last)")
    call_parser.add_argument("-l", "--list", action="store_true", help="Daftar semua fungsi solver yang tersedia di katalog")
    call_parser.add_argument("--json", action="store_true", help="Output hasil dalam format JSON")

    return parser


def main() -> None:
    configure_utf8_console()

    if len(sys.argv) <= 1:
        interactive_menu()
        return

    parser = build_parser()
    args = parser.parse_args()

    if args.subcommand is None or args.subcommand == "interactive":
        interactive_menu()
    elif args.subcommand == "triage":
        sys.exit(handle_triage(args))
    elif args.subcommand == "recipe":
        sys.exit(handle_recipe(args))
    elif args.subcommand == "magic":
        sys.exit(handle_magic(args))
    elif args.subcommand == "call":
        sys.exit(handle_call(args))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
