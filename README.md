# CTF Toolkit v4.0 Apex

> **Multi-Domain CTF Exploitation Workbench, Autonomous A\* Magic Solver, CyberChef Pipeline Studio, and 560+ Callable Solver Functions.**  
> Engineered for rapid exploitation and analysis across **Windows (PowerShell/CMD)**, **Linux (Kali/Ubuntu/WSL2)**, **macOS**, **Docker**, and **Single-File `.pyz` Jumpboxes**.

![Version](https://img.shields.io/badge/Version-4.1.0%20Apex-0ea5e9)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB?logo=python&logoColor=white)
![Platforms](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20Docker-22c55e)
![Tests](https://img.shields.io/badge/Tests-1%2C238%2B%20Passing-brightgreen)
![Solvers](https://img.shields.io/badge/Solvers-560%2B%20Functions-8b5cf6)
![License](https://img.shields.io/badge/License-MIT-green)

---

```text
╭──────────────────────────────────────────────────────────────────────────────╮
│ ⚡ APEX CTF WORKBENCH v4.0 │ Main Hub      Case: default_case │ Vault: 0 Flags │
│ Buffer $last: <empty>   [/] Search  [:m] Magic  [:s] Studio  [:f] Flags  [0] │
╰──────────────────────────────────────────────────────────────────────────────╯
```

## Table of Contents
- [Overview & What's New in v4.0 Apex](#overview--whats-new-in-v40-apex)
- [9-Domain Feature Matrix](#9-domain-feature-matrix)
- [Cross-Platform Quickstart](#cross-platform-quickstart)
- [Headless CLI & Universal Dispatcher](#headless-cli--universal-dispatcher)
- [TUI v4 Apex Hotkeys & Smart Input](#tui-v4-apex-hotkeys--smart-input)
- [Python Scripting API Usage](#python-scripting-api-usage)
- [Documentation Hub (`docs/`)](#documentation-hub-docs)
- [CLI Preview (Real Output)](#cli-preview-real-output)
- [Project Layout](#project-layout)
- [Validation & Test Suite](#validation--test-suite)
- [License](#license)

---

## Overview & What's New in v4.0 Apex

**CTF Toolkit v4.0 Apex** expands the workbench into a comprehensive **560+ function CTF Command Center** that operates both as an interactive Terminal UI (TUI) and a scriptable headless library:

1. **Dynamic 560+ Function Command Palette (`/search`) & Universal CLI Dispatcher (`ctf-toolkit call`):** Dynamically indexes every public solver across all domain packages (`crypto`, `pwn`, `binex`, `web`, `forensics`, `reversing`, `blockchain`, `osint_misc`, `triage`, `pipeline`). Search and run any function interactively with `/<query>` or headlessly via `ctf-toolkit call <func> [args...] [--json]`.
2. **Automated RSA, Lattice (LLL) & Elliptic Curve Suite (`rsa_auto`, `lattice_lll`, `ecc`, `block_attacks`):**
   - **Auto-RSA Dispatcher (`solve_rsa_auto` & `parse_pem_key`):** Parses PEM/DER public keys and cascades across 9 mathematical attacks (Small-$e$ root, Fermat, Trial/Small factor, Pollard $p-1$, Pollard $\rho$, Wiener, Boneh-Durfee lattice roots, Common Modulus, and Håstad CRT).
   - **Pure-Python LLL Lattice Reduction (`lll_reduce`):** Solves subset-sum/Merkle-Hellman knapsacks (`solve_knapsack_lll`), HNP, and univariate modular small roots (`coppersmith_small_root_univariate`).
   - **Elliptic Curve Cryptography (`ecc.py`):** Weierstrass curve arithmetic, Baby-Step Giant-Step (`ecc_small_subgroup_dlog`), **Smart's $p$-adic lift attack** on anomalous curves (`ecc_smarts_attack`), and invalid-curve CRT recovery (`ecc_invalid_curve_recovery`).
   - **Active Block & Stream Attacks (`block_attacks.py`):** CBC bit-flipping (`cbc_bitflip_craft`), PKCS#7 padding oracle block recovery (`padding_oracle_decrypt_block`), and ECB byte-at-a-time oracle recovery (`ecb_byte_at_a_time_recover`).
3. **Active Web JWT & Deserialization Exploitation (`jwt_attacks`, `deserialization`):**
   - Forges `alg: none` tokens (`jwt_forge_none`), cracks HS256 secrets (`jwt_crack_hs256`), executes RS256→HS256 key confusion (`jwt_forge_key_confusion`), and injects `jwk`/`kid` SQLi headers.
   - Disassembles Python `pickle` VM opcodes (`pickle_inspect_opcodes`) and crafts PHP serialized payloads (`build_php_serialized_object` with CVE-2016-7124 `__wakeup` bypass).
4. **Forensics Binary Carver, Wasm Dissector & Wire Formats (`carver`, `wasm_analyzer`, `binary_formats`):**
   - **Multi-Stream File Carver (`carve_embedded_files`):** Binwalk-lite signature scanner & automatic `zlib`/`gzip` stream decompressor.
   - **WebAssembly Dissector (`analyze_wasm_binary`):** Parses `.wasm` LEB128 sections, imports, exports, and data-segment strings.
   - **Binary Wire Formats (`binary_formats.py`):** Decodes schema-less Protobuf wire tags, MessagePack, CBOR, ASN.1 DER, Apple `bplist00`, Git loose objects, and timestamp delta covert channels.
5. **Autonomous "Magic" Solver (`:m`), CyberChef Recipe Studio (`:s`) & 1-Click Writeup Exporter (`:export`):** Crack multi-hop encodings via A\* search, chain 35+ transformations with intermediate trace tables, and export standalone `solve_<case>.py` + `WRITEUP_<case>.md` artifacts.

---

## 9-Domain Feature Matrix

| Key | Domain Module | Highlights & Capabilities |
| :---: | :--- | :--- |
| **`1`** | **Crypto** | **Auto-RSA Dispatcher (`solve_rsa_auto`)**, **LLL Lattice Reduction (`lll_reduce`)**, **ECC (`ecc_smarts_attack`, BSGS)**, **CBC Bit-Flip / Padding Oracle / ECB Oracle**, 30+ classical ciphers (Caesar, Vigenère, Beaufort, Autokey, Playfair, Bifid, Trifid, Hill, Rail Fence, Columnar, Myszkowski, ADFGVX, Bacon, Polybius), AES/DES/3DES/RC4/Fernet, CRC32 4-byte algebraic inverter, LCG & Shamir Secret Sharing. |
| **`2`** | **BinEx / Pwn** | De Bruijn `cyclic` generator & offset finder, Visual Stack Frame diagram (`MOVAPS` 16-byte alignment check), `ret2win` & `ROP` chain crafters, Format String `%k$p` stack leak crawler, OOB array index math, ELF triage & `pwntools` boilerplate generator. |
| **`3`** | **Web** | **Active JWT Attacks (`alg:none`, HS256 cracker, RS256→HS256 key confusion, `jwk`/`kid` injection)**, **Python Pickle VM disassembler & PHP Object Injection crafter**, **Payload Diff Matrix**, SQLi auth bypass & UNION crafter, SSTI, Cloud SSRF metadata prober, LFI traversal generator, CORS/X-Forwarded-For bypass & IDOR matrix. |
| **`4`** | **Forensics / RE** | **Signature File Carver (`carve_embedded_files`)**, **WebAssembly `.wasm` Dissector (`analyze_wasm_binary`)**, **x86/x64 `MOV` Stack-String Deobfuscator**, OOXML (`DOCX`/`XLSX`) hidden text extractor, PDF stream decompressor & raw object scanner, PNG trailing bytes & chunk repair, LSB image & WAV audio stego, DTMF/FSK audio decoder, PCAP DNS/HTTP/USB extractor, `.pyc` bytecode extractor & crackme byte transforms. |
| **`5`** | **Blockchain / EVM** | Ethereum ABI calldata parser, `uint256` charcode array decoder, EVM `Error(string)` & `Panic(uint256)` revert decoder, Keccak mapping/dynamic array storage slot calculator, event receipt log parser, **Keccak256 Merkle root calculator**, **4-byte selector resolver**, and **Keccak256 wordlist cracker**. |
| **`6`** | **OSINT & Misc** | **Wire Format Decoders (Protobuf, MessagePack, CBOR, ASN.1 DER, Apple `bplist00`, Git loose objects)**, **OSINT Handle/Email/Commit Miner (`mine_profile_handles`)**, Certificate Transparency (`crt.sh`) & WHOIS parsers, SQLite/Crontab/TOML/JSONC/MIME/XML secret hunters, Stego (Unicode Tag Plane `U+E0000`, 7-Segment, Case Bitstream, Acrostic), and Esolangs (Brainfuck, Befunge-93, Ook!, Deadfish, Spoon, Whitespace, Collatz). |
| **`7`** | **Utilities** | Multi-radix encodings (Base32/36/45/58/62/64/85/91, Z85, Braille, Baudot, EBCDIC, UUDecode, XXDecode), Multi-Hop Auto-Decoder (`auto_decode_layers`), XOR brute-forcer, regex flag scanner, and HTTP request tester. |
| **`8`** | **Defensive / Blue Team** | Multi-log fragment correlation, Suricata alert reassembly, EDR beacon sequence analyzer, `/etc/passwd` & `sshd_config` security auditors, and Linux/Windows forensic artifact discovery. |
| **`9`** | **Workbench & Pipelines** | Auto-Triage & heuristic fingerprinter, Interactive CyberChef Recipe Studio, Autonomous A\* Magic Solver, and 1-Click Python Solver + Markdown Writeup exporter. |

---

## Cross-Platform Quickstart

### 1. Windows (PowerShell & Command Prompt)
Native launchers (`ctf.ps1` and `ctf.bat`) automatically enable UTF-8 console output (`chcp 65001` / `PYTHONIOENCODING=utf-8`):

```powershell
# PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Launch TUI v4 Apex Command Center
.\ctf.ps1
```

```cmd
:: Windows Command Prompt (CMD)
ctf.bat
```

### 2. Linux (Kali / Parrot / Ubuntu / WSL2) & macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

chmod +x ctf.sh
./ctf.sh
```

### 3. Global CLI Installation (`pipx` / `uv` / `pip`)
Install globally to invoke `ctf-toolkit` or its short alias `ctft` from any folder:
```bash
pipx install .
# or: uv tool install .
# or: pip install -e .

ctft --version
ctft
```

### 4. Portable Single-File `.pyz` Bundle (For Air-Gapped VMs & SSH Jumpboxes)
Build a single self-contained executable (`dist/ctf-toolkit.pyz`) that runs on any machine with Python 3.10+:
```bash
python scripts/build_portable.py
python dist/ctf-toolkit.pyz --version
python dist/ctf-toolkit.pyz
```

### 5. Docker Container
```bash
docker build -t ctf-toolkit:v4 .
docker run -it --rm -v "$(pwd):/work" ctf-toolkit:v4
```

---

## Headless CLI & Universal Dispatcher

Run triage, chained recipes, the autonomous A\* Magic Solver, or **call any of the 560+ solver functions directly** from your shell:

```bash
# 1. Universal Function Dispatcher (call any of the 560+ toolkit functions directly)
python main.py call --list rsa
python main.py call crack_crc32_4byte 0x1c291ca3
python main.py call jwt_forge_none '{"user":"admin","admin":true}' --json

# 2. Auto-Triage a file or string (with optional --json output)
python main.py triage challenge.bin
python main.py triage -s "RkxBR3toZWFkbGVzc190cmlhZ2V9" --json

# 3. CyberChef-style Recipe Pipeline
python main.py recipe "b64d | xor:0x33 | flag_scan" -d "cVoxcVFFWlxXWlx="

# 4. Autonomous A* Magic Solver (cracks multi-hop encodings automatically)
python main.py magic -s "RkxBR3t0ZXN0X21hZ2ljX3NvbHZlcn0="
python main.py magic @mystery_payload.enc --depth 4
```

---

## TUI v4 Apex Hotkeys & Smart Input

At **any menu prompt** in interactive mode, you can use these global commands and input tokens:

| Token / Hotkey | Action |
| :--- | :--- |
| `/<query>` | Search & run any of the **560+ solver functions** (e.g., `/solve_rsa_auto`, `/lll`, `/jwt_forge`, `/wasm`). |
| `:m` / `:s` | Open **Autonomous Magic Solver** (`:m`) or **Interactive Recipe Studio** (`:s`). |
| `:f` / `:b` | View **Captured Flag Vault** (`:f`) or **Session Register History** (`:b`). |
| `:c` | Copy current `$last` register output to the OS clipboard. |
| `:case <name>` | Set active challenge case name (e.g., `:case crypto_ecc_01`). |
| `:export` | Export `solve_<case>.py` and `WRITEUP_<case>.md`. |
| `$last`, `$1`, `$2` | Pass previous tool output directly into the current prompt. |
| `@path/to/file` | Load raw bytes or text from a file into any prompt. |
| `hex:...` / `b64:...` | Inline decode hex or Base64 input at any prompt. |

---

## Python Scripting API Usage

Import `ctf_toolkit` directly inside your custom exploit or solver scripts:

```python
from ctf_toolkit.crypto.rsa_auto import solve_rsa_auto
from ctf_toolkit.crypto.ecc import ecc_smarts_attack
from ctf_toolkit.crypto.lattice_lll import lll_reduce
from ctf_toolkit.web.jwt_attacks import jwt_forge_none, jwt_crack_hs256
from ctf_toolkit.forensics.carver import carve_embedded_files
from ctf_toolkit.pwn import build_ret2win_payload, build_rop_chain
from ctf_toolkit.pipeline import run_recipe

# 1. Automatically attack RSA (tries Small-e, Fermat, Pollard p-1/rho, Wiener, Boneh-Durfee, CRT)
res = solve_rsa_auto(n=N, e=e, c=c)
print(res["attack"], res["plaintext"])

# 2. Recover discrete log on anomalous elliptic curve (#E(Fp) == p) via Smart's p-adic attack
priv_key = ecc_smarts_attack(G=(gx, gy), Q=(qx, qy), a=a, b=b, p=p)

# 3. Carve & auto-decompress hidden zlib/gzip/PNG/ZIP streams from a binary blob
artifacts = carve_embedded_files(open("firmware.bin", "rb").read())
```

---

## Documentation Hub (`docs/`)

- **[TUI v4 & Headless CLI Guide](docs/TUI_AND_CLI_GUIDE.md):** Full reference for hotkeys, `ctf-toolkit call`, Smart Input prefixes, Recipe Studio commands, and `RECIPE_REGISTRY` tokens.
- **[Solver Abstractions Catalog (560+ Functions)](docs/SOLVER_CATALOG.md):** Complete API reference across Crypto, Pwn, Web, Forensics, Reversing, Blockchain, and OSINT/Misc.
- **[Cross-Platform Installation & `.pyz` Deployment](docs/PLATFORM_INSTALL.md):** Detailed instructions for Windows PowerShell/CMD, Linux/Kali, macOS, Docker, and air-gapped `.pyz` bundles.
- **[Architecture & Extension Guide](docs/ARCHITECTURE.md):** Internal design of the engine/UI separation, dynamic Command Palette introspection, A\* Magic Solver scoring, and how to add new primitives.
- **AI Assistant Guides:** [`copilot.md`](copilot.md) and [`claude.md`](claude.md).

---

## CLI Preview (Real Output)

> Real toolkit screenshots stored locally in `docs/assets/`:

### Main Menu
![Screenshot showing CTF Toolkit main menu](docs/assets/cli-main-menu.png)

### Crypto Menu
![Screenshot of Crypto submenu](docs/assets/cli-crypto-menu.png)

### Forensics / RE Menu
![Screenshot of Forensics / RE submenu](docs/assets/cli-forensics-menu.png)

---

## Project Layout

```text
ctf_toolkit/
  __init__.py          # Package version (__version__ = "4.1.0") & exports
  __main__.py          # Module execution entrypoint (python -m ctf_toolkit)
  main_cli.py          # CLI router (triage / recipe / magic / call / interactive) & UTF-8 setup
  registry.py          # 9-Domain lazy-loaded menu registry
  triage/              # Heuristic fingerprinter, magic bytes & entropy analyzer
  pipeline/            # CyberChef-style RECIPE_REGISTRY & chained executor
  crypto/              # Auto-RSA, LLL Lattice, ECC, Block/Stream attacks, 30+ classical ciphers
  pwn/ & binex/        # Unified BinEx/Pwn API (ROP, ret2win, format string, OOB, cyclic, ELF)
  web/                 # Active JWT attacks, Pickle/PHP deserialization, SQLi, SSTI, SSRF, LFI, IDOR
  forensics/           # Binary carver, Wasm dissector, Office (DOCX/XLSX), PDF, PNG/GIF, Audio, PCAP, PYC
  reversing/           # Stack-string deobfuscator, crackme byte transforms & charcode decoders
  blockchain/          # EVM calldata, revert decoder, storage slots, Merkle roots & 4-byte selectors
  osint_misc/          # Protobuf/MsgPack/CBOR/ASN.1/bplist decoders, Profile miner, Config hunters, Esolangs
  utils/               # I/O helpers, menu primitives, mathematical & encoding utilities
  ui/                  # TUI v4 Apex (console, inspector, session, dynamic 560+ palette, magic_solver, menus)
scripts/
  build_portable.py    # Single-file dist/ctf-toolkit.pyz bundler
docs/                  # Technical guides & CLI screenshot assets
tests/                 # Domain-organized test suites (1,238+ passing tests)
  crypto/              # Classical, RSA, DES, Fernet, encoding & cipher unit tests
  forensics/           # Audio, image, Office, PDF, PCAP, QR & bytecode unit tests
  pwn_reversing/       # BinEx, Pwn, ELF, stack-strings & reversing transform tests
  web/                 # Web exploitation, traversal & robots tests
  osint_misc/          # Config hunters, binary formats, compression & esolang tests
  blockchain/          # EVM calldata, events, revert & storage slot tests
  ui_system/           # TUI v4 Apex, Command Palette, CLI & cross-platform verification tests
  integration/         # End-to-end multi-domain solver suites
  benchmarks/          # Synthetic twin challenge benchmark suites
ctf.ps1 / ctf.bat      # Windows PowerShell & CMD launchers
ctf.sh                 # Linux / macOS POSIX launcher
Dockerfile             # Containerized execution environment
run_tests.py           # Zero-dependency cross-platform test runner
```

---

## Validation & Test Suite

Run the complete test suite (**1,238+ unit & synthetic twin tests**) on Windows, Linux, or macOS:

```bash
# Cross-platform test runner (works on Windows PowerShell, CMD, Linux, and macOS)
python run_tests.py

# Build and verify portable .pyz bundle
python scripts/build_portable.py
python dist/ctf-toolkit.pyz --version
```

---

## License
See [LICENSE](LICENSE).
