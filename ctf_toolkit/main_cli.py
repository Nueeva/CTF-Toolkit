from __future__ import annotations

import argparse
import json
import os
import sys

from ctf_toolkit.pipeline import run_recipe
from ctf_toolkit.registry import get_menu_registry
from ctf_toolkit.triage import triage_data, triage_file
from ctf_toolkit.utils.io import safe_input, success, warn


def show_main_menu() -> None:
    print("\n=== CTF Toolkit CLI ===")
    for entry in get_menu_registry():
        print(f"[{entry.key}] {entry.label}")
    print("[0] Exit")


def interactive_menu() -> None:
    while True:
        show_main_menu()
        choice = safe_input("Pilih opsi menu: ").strip()

        if choice == "0":
            success("Keluar dari toolkit. Bye!")
            return

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
            # Treat as raw string
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
        # Check if stdin has data piped
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctf-toolkit",
        description="CTF Toolkit - Headless Workbench & Multi-Domain Exploitation Suite",
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

    return parser


def main() -> None:
    # If no args provided, default to interactive
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
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
