from __future__ import annotations

from pathlib import Path


def info(message: str) -> None:
    print(f"[i] {message}")


def success(message: str) -> None:
    print(f"[+] {message}")


def warn(message: str) -> None:
    print(f"[!] {message}")


def error(message: str) -> None:
    print(f"[-] {message}")


def safe_input(prompt: str) -> str:
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        warn("Input dibatalkan.")
        return ""


def read_text_or_file() -> str:
    print("\n[1] Input teks langsung")
    print("[2] Input dari file")
    choice = safe_input("Pilih sumber input: ").strip()

    if choice == "1":
        return safe_input("Masukkan teks: ")

    if choice == "2":
        path = safe_input("Masukkan path file: ").strip()
        if not path:
            warn("Path file kosong.")
            return ""
        try:
            return Path(path).read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            warn(f"Gagal membaca file: {exc}")
            return ""

    warn("Pilihan tidak valid.")
    return ""


def read_bytes_file(path: str) -> bytes:
    if not path:
        return b""
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        warn(f"Gagal membaca file: {exc}")
        return b""
