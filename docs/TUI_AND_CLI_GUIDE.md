# TUI v3 Apex & Headless CLI Operator Guide

This guide covers interactive navigation in the **TUI v3 Apex Command Center**, global hotkeys, Smart Input syntax, the **Interactive CyberChef Recipe Studio**, the **Autonomous A\* Magic Solver**, and headless CLI piping across Windows PowerShell, CMD, Linux Bash, and macOS Zsh.

---

## 1. Global Hotkeys (Available from Any Menu)

When running in interactive mode (`python main.py` or `ctf-toolkit`), you can enter either a numeric menu choice (`1`–`9`, `0`) or any of the following global command shortcuts at the prompt:

| Shortcut / Command | Function | Example |
| :--- | :--- | :--- |
| `/<query>` | **Global Command Palette**: Fuzzy-search across all 106+ solver abstractions and run any function via an auto-generated parameter prompt. | `/wiener`, `/rop`, `/sqli`, `/docx`, `/whois`, `/revert` |
| `:m` or `:magic` | **Autonomous Magic Solver**: Launch the A\* heuristic multi-hop decoder/decryptor tree on any ciphertext or file. | `:m` |
| `:s` or `:studio` | **Interactive Recipe Studio**: Open the step-by-step CyberChef pipeline builder with live intermediate trace tables. | `:s` |
| `:f` or `:flags` | **Session Flag Vault**: Display all flags automatically captured during the active session (`FLAG{...}`, `GETSFLAG{...}`, `LKS{...}`, etc.). | `:f` |
| `:b` or `:buf` | **Buffer Register History**: Inspect all stored session registers (`$last`, `$1`, `$2`, ...) along with data type, byte size, and preview. | `:b` |
| `:c` or `:copy` | **Copy to Clipboard**: Copy the current `$last` register contents directly to the OS clipboard (`clip.exe` / `pbcopy` / `xclip`). | `:c` |
| `:case <name>` | **Switch Challenge Case**: Set the active challenge workspace name used for tracking history and exporting writeups. | `:case crypto_rsa_01` |
| `:export` | **1-Click Solver & Writeup Exporter**: Generate both `solve_<case>.py` and `WRITEUP_<case>.md` in the current working directory. | `:export` |
| `0` | **Back / Exit**: Return to the parent menu or exit the toolkit from the main hub. | `0` |

---

## 2. Smart Input Resolver Syntax

Every prompt in the Command Palette, Magic Solver, Recipe Studio, and Workbench supports **Smart Input prefixes** so you never have to manually copy-paste intermediate bytes between tools:

| Prefix / Token | Resolution Behavior | Example Input |
| :--- | :--- | :--- |
| `$last` | Uses the output of the most recently executed tool or recipe. | `$last` |
| `$1`, `$2`, `$N` | Uses the output stored at step `#N` in the session register history (`:b`). | `$2` |
| `@<filepath>` | Reads the raw bytes or text directly from the specified file path on disk. | `@challenges/dump.bin` |
| `hex:<hex_str>` | Decodes the hexadecimal string into raw bytes before passing to the function. | `hex:89504e470d0a1a0a` |
| `b64:<b64_str>` | Decodes the Base64 string into raw bytes before passing to the function. | `b64:RkxBR3t0ZXN0fQ==` |
| *(plain text)* | Passed directly as a UTF-8 string or bytes depending on the target function signature. | `admin' OR 1=1 --` |

---

## 3. Headless CLI Subcommands

`ctf-toolkit` provides three headless subcommands for terminal scripting, automation, and shell piping:

### A. `triage` — Heuristic Fingerprinter & Entropy Analyzer
Scans a file or raw string for magic signatures, Shannon entropy, Index of Coincidence (IC), candidate encodings, and embedded flags.

```bash
# Linux / macOS / WSL2
python3 main.py triage suspicious.bin
python3 main.py triage -s "RkxBR3toZWFkbGVzc190cmlhZ2V9" --json

# Windows PowerShell
.\ctf.ps1 triage suspicious.bin
.\ctf.ps1 triage -s "RkxBR3toZWFkbGVzc190cmlhZ2V9" --json
```

### B. `recipe` — CyberChef-Style Chained Pipeline
Executes a pipe-delimited (`|`) chain of operations from `RECIPE_REGISTRY` on input strings, files, or `stdin`.

```bash
# Linux / macOS Bash
python3 main.py recipe "b64d | xor:0x33 | flag_scan" -d "cVoxcVFFWlxXWlx="
cat payload.enc | python3 main.py recipe "hex_d | zlib_d | rot13" -o decrypted.txt

# Windows PowerShell
.\ctf.ps1 recipe "b64d | xor:0x33 | flag_scan" -d "cVoxcVFFWlxXWlx="
Get-Content payload.enc -Raw | .\ctf.ps1 recipe "hex_d | zlib_d | rot13"
```

### C. `magic` — Autonomous A* Multi-Hop Solver
Automatically discovers multi-layer encoding and classical cipher chains (up to depth $D=4$ by default) and prints the search tree.

```bash
# Solve a multi-layered string directly
python main.py magic -s "71597a7151455a51..."

# Solve from a file with custom search depth
python main.py magic @artifact.enc --depth 4
```

---

## 4. Built-In Recipe Operations (`RECIPE_REGISTRY`)

The following operations can be chained inside `ctf-toolkit recipe "..."` or added interactively inside `:studio`:

| Category | Operation Token | Arguments | Description |
| :--- | :--- | :--- | :--- |
| **Base Encodings** | `b64d` / `b64e` | None | Base64 decode / encode |
| | `b64url_d` / `b64url_e` | None | URL-safe Base64 decode / encode |
| | `b32d` / `b32e` | None | Base32 decode / encode |
| | `b32hex_d` / `b32hex_e` | None | Extended Hex Base32 (RFC 4648) decode / encode |
| | `b58d` / `b58e` | None | Bitcoin Base58 decode / encode |
| | `b58_ripple_d` | None | Ripple alphabet Base58 decode |
| | `b62d` / `b62e` | None | Base62 decode / encode |
| | `b85d` / `b85e` | None | ASCII85 / Base85 decode / encode |
| | `b91d` / `b91e` | None | basE91 decode / encode |
| | `b45d` / `b45e` | None | Base45 decode / encode |
| | `b36d` / `b36e` | None | Base36 decode / encode |
| **Hex & Web** | `hex_d` / `hex_e` | None | Hexadecimal decode / encode |
| | `url_d` / `url_e` | None | URL percent-encoding decode / encode |
| | `qp_d` / `qp_e` | None | Quoted-Printable decode / encode |
| | `html_d` / `html_e` | None | HTML entity unescape / escape |
| | `uu_d` / `xx_d` | None | UUDecode / XXDecode |
| **Classical & Stream** | `rot13` / `rot47` / `rot18` | None | Standard ROT13, ROT47 (ASCII 33–126), ROT18 (alpha+digits) |
| | `caesar:<shift>` | `shift` (int) | Caesar shift decryption (e.g. `caesar:7`) |
| | `atbash` | None | Atbash mirror substitution |
| | `vigenere_d:<key>` | `key` (str) | Vigenère decryption with key (e.g. `vigenere_d:SECRET`) |
| | `xor:<key>` | `key` (hex/str) | Single-byte or repeating-key XOR (e.g. `xor:0x5a` or `xor:KEY`) |
| | `rc4:<key>` | `key` (str/hex) | RC4 stream cipher decryption |
| | `rail_fence_d:<rails>` | `rails` (int) | Rail Fence transposition decryption |
| | `columnar_d:<key>` | `key` (str) | Columnar transposition decryption |
| | `porta_d:<key>` | `key` (str) | Porta polyalphabetic cipher decryption |
| **Bit & Byte Transforms** | `reverse` | None | Reverse byte or character order |
| | `swap_nibbles` | None | Swap high and low 4-bit nibbles in every byte |
| | `byte_shift:<n>` | `n` (int) | Add/subtract `n` (mod 256) to each byte |
| | `rle_d` | None | Run-Length Encoding (RLE) decompression |
| **Compression & Scan** | `zlib_d` / `gzip_d` / `bz2_d` / `lzma_d` | None | Decompress raw zlib, gzip, bzip2, or lzma streams |
| | `flag_scan` | None | Extract all matching CTF flag patterns from the stream |
