from __future__ import annotations

import os
from typing import Any

from ctf_toolkit.pipeline import run_recipe, RECIPE_REGISTRY
from ctf_toolkit.triage import triage_data, triage_file
from ctf_toolkit.ui.console import (
    HAS_RICH,
    get_rich_console,
    render_header,
    render_menu_panel,
    console_info,
    console_success,
    console_warn,
    console_error,
)
from ctf_toolkit.ui.inspector import inspect_output, calculate_shannon_entropy
from ctf_toolkit.ui.magic_solver import magic_interactive
from ctf_toolkit.ui.session import (
    resolve_smart_input,
    set_last_output,
    export_case_script,
    export_case_writeup,
    get_session,
)

try:
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
except ImportError:
    pass


def triage_interactive() -> None:
    render_header("Auto-Triage & Fingerprint")
    print("\n--- Auto-Triage & Fingerprinter ---")
    print("[1] Triage File")
    print("[2] Triage Raw Text / Hex / Base64 / Register ($last)")
    choice = input("Pilih sumber input: ").strip()

    if choice == "1":
        fpath = input("Masukkan path file (@path atau path): ").strip().strip('"').strip("@")
        if not os.path.exists(fpath):
            console_warn(f"File tidak ditemukan: {fpath}")
            return
        report = triage_file(fpath)
        print("\n" + report.summary())
        set_last_output(report.to_dict(), op_name=f"triage_file:{fpath}")
    elif choice == "2":
        raw = input("Masukkan string / data mentah ($last, @file, hex:, b64:): ").strip()
        if not raw:
            console_warn("Input kosong.")
            return
        data = resolve_smart_input(raw, as_bytes=True)
        report = triage_data(data, target_label="user_input")
        print("\n" + report.summary())
        set_last_output(report.to_dict(), op_name="triage_data")
    else:
        console_warn("Pilihan tidak valid.")


def execute_recipe_trace(recipe_steps: list[str], initial_data: bytes | str) -> list[dict[str, Any]]:
    """Execute pipeline step-by-step and collect intermediate traces."""
    current = initial_data
    trace = []

    for idx, op in enumerate(recipe_steps, 1):
        in_size = len(current) if isinstance(current, (bytes, str)) else 0
        try:
            current = run_recipe(op, current)
            out_size = len(current) if isinstance(current, (bytes, str)) else 0
            ent = calculate_shannon_entropy(current if isinstance(current, bytes) else str(current).encode())
            trace.append({
                "step": idx,
                "op": op,
                "in_size": in_size,
                "out_size": out_size,
                "entropy": ent,
                "output": current,
                "error": None,
            })
        except Exception as e:
            trace.append({
                "step": idx,
                "op": op,
                "in_size": in_size,
                "out_size": 0,
                "entropy": 0.0,
                "output": None,
                "error": str(e),
            })
            break

    return trace


def render_trace_table(trace: list[dict[str, Any]]) -> None:
    """Render intermediate trace table for CyberChef Recipe Studio."""
    console = get_rich_console()
    if HAS_RICH and console:
        table = Table(
            title="⚡ Recipe Pipeline Execution Trace",
            box=box.ROUNDED,
            border_style="cyan",
            show_header=True,
            header_style="bold yellow",
        )
        table.add_column("Step", justify="right", width=6)
        table.add_column("Operation", style="bold white", width=16)
        table.add_column("In Size", justify="right", width=10)
        table.add_column("Out Size", justify="right", width=10)
        table.add_column("Entropy", justify="right", width=10)
        table.add_column("Preview (Hex / ASCII)", style="cyan")

        for t in trace:
            if t["error"]:
                table.add_row(
                    str(t["step"]),
                    t["op"],
                    f"{t['in_size']} B",
                    "[bold red]FAIL[/bold red]",
                    "-",
                    f"[red]{t['error']}[/red]",
                )
            else:
                out = t["output"]
                if isinstance(out, bytes):
                    prev = out[:20].hex() + " | " + out[:20].decode("latin1", errors="replace")
                else:
                    prev = str(out)[:40].replace("\n", "\\n")
                table.add_row(
                    str(t["step"]),
                    t["op"],
                    f"{t['in_size']} B",
                    f"{t['out_size']} B",
                    f"{t['entropy']:.2f}",
                    prev,
                )
        console.print(table)
    else:
        print("\n--- Pipeline Execution Trace ---")
        for t in trace:
            if t["error"]:
                print(f"  Step {t['step']} [{t['op']}]: ERROR: {t['error']}")
            else:
                print(f"  Step {t['step']} [{t['op']}]: {t['out_size']} B (H={t['entropy']:.2f})")


def recipe_studio_interactive() -> None:
    """Interactive CyberChef Recipe Studio with dynamic step editing & trace inspection."""
    render_header("Interactive Recipe Studio")
    console_info("CyberChef-Style Interactive Studio. Rangkai resep step-by-step dengan preview langsung.")

    raw_in = input("Masukkan data awal ($last, @file, hex:, b64:, atau string): ").strip()
    if not raw_in:
        console_warn("Data awal kosong.")
        return

    data = resolve_smart_input(raw_in, as_bytes=True)
    steps: list[str] = []

    while True:
        print(f"\n[Active Recipe Pipeline: {' | '.join(steps) if steps else '<empty>'}]")
        trace = execute_recipe_trace(steps, data) if steps else []
        if trace:
            render_trace_table(trace)

        print("\nPerintah Studio:")
        print("  + <op>     : Tambah operasi (misal '+ b64d', '+ xor:0x5a', '+ zlib_d', '+ flag_scan')")
        print("  pop        : Hapus operasi terakhir")
        print("  clear      : Bersihkan seluruh operasi")
        print("  export     : Ekspor resep ke script Python (solve_<case>.py)")
        print("  inspect    : Tampilkan output akhir secara detail di Smart Inspector")
        print("  done       : Simpan hasil akhir ke $last dan keluar")
        print("  0          : Batal dan kembali")

        cmd = input("Studio CMD > ").strip()
        if not cmd:
            continue
        if cmd == "0":
            return
        if cmd.lower() == "done":
            if trace and not trace[-1]["error"]:
                inspect_output(trace[-1]["output"], title="Recipe Studio Output", op_name=f"recipe:{' | '.join(steps)}")
                console_success("Hasil disimpan di $last!")
            return
        if cmd.lower() == "inspect":
            if trace and not trace[-1]["error"]:
                inspect_output(trace[-1]["output"], title="Recipe Studio Intermediate Output", op_name=f"recipe:{' | '.join(steps)}")
            else:
                console_warn("Tidak ada output valid untuk diinspeksi.")
            continue
        if cmd.lower() == "pop":
            if steps:
                removed = steps.pop()
                console_info(f"Dihapus: {removed}")
            else:
                console_warn("Pipeline kosong.")
            continue
        if cmd.lower() == "clear":
            steps.clear()
            console_info("Pipeline dibersihkan.")
            continue
        if cmd.lower() == "export":
            f_script = export_case_script()
            f_write = export_case_writeup()
            console_success(f"Berhasil diekspor: {f_script} dan {f_write}")
            continue

        if cmd.startswith("+"):
            op = cmd[1:].strip()
            if not op:
                console_warn("Operasi tidak boleh kosong.")
                continue
            steps.append(op)
            console_success(f"Operasi ditambahkan: {op}")
        else:
            # Maybe user typed one or multiple pipe ops directly
            if "|" in cmd:
                new_ops = [p.strip() for p in cmd.split("|") if p.strip()]
                steps.extend(new_ops)
                console_success(f"Menambahkan {len(new_ops)} operasi.")
            elif cmd in RECIPE_REGISTRY:
                steps.append(cmd)
                console_success(f"Operasi ditambahkan: {cmd}")
            else:
                console_warn(f"Perintah atau operasi '{cmd}' tidak dikenal. Gunakan '+ <op>' atau 'clear'.")


def fast_recipe_interactive() -> None:
    """Fast One-Liner Recipe Pipeline."""
    render_header("Fast Recipe Pipeline")
    console_info(f"Operasi tersedia: {', '.join(sorted(RECIPE_REGISTRY.keys())[:15])} ...")
    recipe_str = input("Masukkan rantai resep (contoh: 'b64d | xor:0x5a | flag_scan'): ").strip()
    if not recipe_str:
        console_warn("Resep kosong.")
        return

    raw = input("Masukkan data ($last, @file, hex:, b64:, teks): ").strip()
    if not raw:
        console_warn("Data kosong.")
        return

    data = resolve_smart_input(raw, as_bytes=True)
    try:
        result = run_recipe(recipe_str, data)
        inspect_output(result, title=f"Recipe Result ({recipe_str})", op_name=f"recipe:{recipe_str}")
    except Exception as e:
        console_error(f"Gagal menjalankan resep: {e}")


def menu() -> None:
    while True:
        render_header("CTF Workbench & Pipelines")
        items = [
            ("1", "Auto-Triage & Fingerprint (Entropy / Magic / Encodings)"),
            ("2", "Interactive CyberChef Recipe Studio (Live Step Trace)"),
            ("3", "Fast Recipe Pipeline (One-liner string)"),
            ("4", "Autonomous Magic Solver (Ciphey / A* Multi-Hop)"),
            ("5", "Export Session Script & Writeup (solve.py / WRITEUP.md)"),
            ("6", "Daftar Operasi Resep Tersedia"),
            ("0", "Kembali ke Menu Utama"),
        ]
        render_menu_panel("Workbench Navigation", items)

        choice = input("Pilih opsi menu: ").strip()
        if choice == "0":
            return
        elif choice == "1":
            triage_interactive()
        elif choice == "2":
            recipe_studio_interactive()
        elif choice == "3":
            fast_recipe_interactive()
        elif choice == "4":
            magic_interactive()
        elif choice == "5":
            f_sc = export_case_script()
            f_wr = export_case_writeup()
            console_success(f"Sesi diekspor ke:\n  - Script : {f_sc}\n  - Writeup: {f_wr}")
        elif choice == "6":
            print("\nOperasi Terdaftar:")
            for op in sorted(RECIPE_REGISTRY.keys()):
                print(f"  - {op}")
        elif choice.startswith("/"):
            from ctf_toolkit.ui.palette import palette_interactive
            palette_interactive(choice)
        elif choice == ":m":
            magic_interactive()
        elif choice == ":s":
            recipe_studio_interactive()
        else:
            console_warn("Pilihan tidak valid, coba lagi.")
