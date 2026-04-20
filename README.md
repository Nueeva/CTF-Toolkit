# CTF Toolkit (Modular)

Toolkit Python modular untuk latihan CTF/lab, disusun agar selaras dengan fokus LKS 2026 Cyber Security.

> Gunakan hanya untuk pembelajaran, lab, dan challenge legal. Jangan gunakan untuk penyalahgunaan pada sistem nyata tanpa izin.

## Fitur Utama

### 1) Cryptography
- Classical ciphers: Caesar/ROT-n (+ bruteforce), Atbash, Vigenere, Affine, substitution helper + frequency
- RSA tools: encrypt/decrypt, common modulus attack, Hastad broadcast attack, Fermat factorization, hitung `d` dari faktor
- AES helpers: ECB/CBC/CTR encrypt/decrypt, PKCS#7 pad/unpad, ECB detection
- Note: ECB support is included for CTF learning and legacy challenge analysis only (insecure for production)
- PRNG starter: LCG generate + recover parameter saat modulus diketahui
- Hashes: MD5/SHA1/SHA256

### 2) Binary Exploitation
- Cyclic pattern create + offset finder
- Packing helpers: p32/p64/u32/u64 (little-endian)
- ELF triage/checksec-lite (PIE/NX/RELRO/Canary heuristic)
- Gadget scan dasar (`ret`, `pop rdi; ret`)

### 3) Web Helpers (Safe)
- URL encode/decode
- Base64URL encode/decode
- JWT decode tanpa verifikasi signature
- Request template generator (SQLi/SSRF/SSTI payload examples, tanpa auto-scan)

### 4) Forensics/RE Helpers
- File magic detection
- Hexdump
- Entropy calculator
- Strings extractor (min length configurable)
- PCAP analysis notes (offline-safe guidance)

## Struktur

```text
ctf_toolkit/
  __init__.py
  __main__.py
  cli.py
  utils/
  crypto/
  binex/
  web/
  forensics/
main.py
requirements.txt
```

## Instalasi

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Menjalankan

```bash
python3 main.py
```

atau:

```bash
python3 -m ctf_toolkit
```

## Menu Utama

1. Decode/Encode
2. XOR Brute Force
3. Regex Flag Finder
4. File Scanner / Strings
5. HTTP Request Tester
6. Simple Wordlist Brute
7. Crypto Tools
8. BinEx Tools
9. Web Helpers (safe)
10. Forensics/RE Helpers
0. Exit

## Catatan
- Kompatibel Python 3.10+.
- Tidak ada eksekusi command eksternal dari toolkit.
- Modul aman untuk di-import tanpa menjalankan CLI otomatis.
- `Simple Wordlist Brute` menggunakan password dummy default `ctf123` (khusus simulasi CTF/lab, bukan autentikasi nyata).
- `Regex Flag Finder` mengenali pola flag umum termasuk `LKS{...}`, `LKSJAKTIM{...}`, dan variasi `LKS[_-\\s]?JAKTIM{...}` (case-insensitive).
