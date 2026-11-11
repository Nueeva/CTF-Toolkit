from __future__ import annotations

from ctf_toolkit.ui.console import console_info, console_success, console_warn, render_header, render_menu_panel
from ctf_toolkit.utils.flag_manager import get_flag_manager
from ctf_toolkit.utils.io import safe_input


def flag_manager_menu() -> None:
    """Interactive TUI for Intelligent Flag Format Management."""
    fm = get_flag_manager()
    while True:
        render_header("Intelligent Flag Format Manager")
        items = [
            ("1", "Daftar Template Format Flag Aktif & Prioritas"),
            ("2", "Tambah Custom Flag Template (Nama, Regex & Prioritas)"),
            ("3", "Hapus Template Custom"),
            ("4", "Reset Konfigurasi ke Default Preset (PicoCTF, GetsFlag, dll)"),
            ("5", "Test Deteksi Flag pada Teks / File Sample"),
            ("0", "Kembali ke Menu Utama"),
        ]
        render_menu_panel("Flag Template Governance", items)
        choice = safe_input("Pilih opsi [0-5]: ").strip()

        if choice == "0":
            return
        elif choice == "1":
            console_info("Format Flag Terdaftar:")
            for idx, t in enumerate(fm.templates, 1):
                prio = t.get("priority", 0)
                name = t.get("name", "Unknown")
                patt = t.get("pattern", "")
                is_b = " [builtin]" if t.get("builtin") else " [custom]"
                print(f"  {idx:2d}. [{prio:3d}] {name:<35}{is_b} -> {patt}")
            safe_input("\nTekan Enter untuk lanjut...")
        elif choice == "2":
            name = safe_input("Nama Template (mis. SECURE_CTF): ").strip()
            if not name:
                console_warn("Nama template tidak boleh kosong.")
                continue
            pattern = safe_input(r"Pola Regex (mis. SECURE\{[^\}\n]+\}): ").strip()
            if not pattern:
                console_warn("Pola regex tidak boleh kosong.")
                continue
            prio_raw = safe_input("Tingkat Prioritas [1-100, default 50]: ").strip() or "50"
            try:
                prio = int(prio_raw)
                fm.add_template(name, pattern, priority=prio)
                console_success(f"Template '{name}' berhasil didaftarkan dengan prioritas {prio}!")
            except Exception as e:
                console_warn(f"Gagal menambahkan template: {e}")
            safe_input("\nTekan Enter untuk lanjut...")
        elif choice == "3":
            name = safe_input("Nama template yang ingin dihapus: ").strip()
            if fm.remove_template(name):
                console_success(f"Template '{name}' berhasil dihapus.")
            else:
                console_warn(f"Template '{name}' tidak ditemukan atau gagal dihapus.")
            safe_input("\nTekan Enter untuk lanjut...")
        elif choice == "4":
            fm.reset_to_defaults()
            console_success("Seluruh template berhasil di-reset ke preset bawaan kompetisi global.")
            safe_input("\nTekan Enter untuk lanjut...")
        elif choice == "5":
            sample = safe_input("Masukkan teks/string sample untuk diuji: ").strip()
            flags = fm.extract_flags(sample)
            if flags:
                console_success(f"Ditemukan {len(flags)} pola flag:")
                for f in flags:
                    print(f"  • [{f['template']} | prio {f['priority']}] : {f['flag']}")
            else:
                console_warn("Tidak ada flag yang cocok dengan template aktif.")
            safe_input("\nTekan Enter untuk lanjut...")
        else:
            console_warn("Pilihan tidak valid.")
