# CTF-Toolkit Solver Abstractions Catalog (106+ Primitives)

All solver modules in `ctf_toolkit` are designed to be used both interactively via the **Command Palette (`/search`)** and programmatically inside standalone Python solve scripts.

---

## 1. Cryptography & Encodings (`ctf_toolkit.crypto`)

### 1.1 Classical & Polyalphabetic Ciphers (`ctf_toolkit.crypto.classical`)
| Function | Signature | Purpose |
| :--- | :--- | :--- |
| `rot_n` | `(text: str, shift: int) -> str` | Rotate alphabetic characters by `shift` positions. |
| `caesar_encrypt` / `caesar_decrypt` | `(text: str, shift: int) -> str` | Standard Caesar shift encryption and decryption. |
| `caesar_bruteforce` | `(text: str) -> list[tuple[int, str]]` | Generate all 26 Caesar shift candidates. |
| `atbash` | `(text: str) -> str` | Mirror substitution (`A <-> Z`, `a <-> z`). |
| `vigenere_encrypt` / `vigenere_decrypt` | `(text: str, key: str) -> str` | Standard Vigenère polyalphabetic cipher. |
| `beaufort_decrypt` | `(text: str, key: str) -> str` | Reciprocal Beaufort cipher (`C = K - P mod 26`). |
| `autokey_decrypt` | `(text: str, key: str) -> str` | Autokey cipher where plaintext extends the keystream. |
| `gronsfeld_decrypt` | `(text: str, digits_key: str) -> str` | Numeric-key Vigenère variant. |
| `porta_decrypt` | `(text: str, key: str) -> str` | 13-tableau reciprocal Porta cipher. |
| `trithemius_decrypt` | `(text: str, start: int = 0, step: int = 1) -> str` | Progressive shift cipher. |
| `affine_encrypt` / `affine_decrypt` | `(text: str, a: int, b: int) -> str` | Affine linear congruence cipher ($E(x) = ax + b \pmod{26}$). |
| `multiplicative_decrypt` | `(text: str, a: int) -> str` | Multiplicative cipher ($b = 0$ special case of Affine). |
| `bacon_decode` | `(text: str) -> str` | 5-bit A/B binary steganographic cipher decoder (26-letter & 24-letter). |
| `polybius_decode` / `polybius_6x6_decode` | `(text: str, key: str = "") -> str` | 5x5 and 6x6 coordinate grid decoders. |
| `playfair_decrypt` | `(text: str, key: str) -> str` | Digraph substitution on a 5x5 key square. |
| `bifid_decrypt` / `trifid_decrypt` | `(text: str, key: str, period: int) -> str` | Fractionated Polybius ciphers. |
| `four_square_decrypt` / `two_square_decrypt` | `(text: str, key1: str, key2: str) -> str` | Multi-grid digraph substitution ciphers. |
| `adfgx_decrypt` / `adfgvx_decrypt` | `(text: str, polybius_key: str, trans_key: str) -> str` | Fractionation + columnar transposition ciphers. |
| `nihilist_decrypt` | `(cipher_nums: list[int], poly_key: str, add_key: str) -> str` | Russian Nihilist numeric Polybius addition cipher. |
| `hill_decrypt_2x2` / `hill_decrypt_3x3` | `(text: str, matrix: list[list[int]]) -> str` | Linear algebra matrix modulo 26 decryption. |
| `rail_fence_decrypt` | `(text: str, rails: int) -> str` | Zig-zag transposition decryption. |
| `scytale_decrypt` | `(text: str, diameter: int) -> str` | Spartan cylinder transposition decryption. |
| `columnar_transposition_decrypt` | `(text: str, key: str) -> str` | Single and double keyed columnar transposition. |
| `myszkowski_decrypt` | `(text: str, key: str) -> str` | Transposition supporting repeated key letters. |
| `tap_code_decode` | `(text: str) -> str` | Knock/dot prison tap code decoder. |
| `a1z26_decode` | `(text: str) -> str` | Numeric position (`1=A .. 26=Z`) decoder. |
| `nato_phonetic_decode` | `(text: str) -> str` | `Alfa Bravo Charlie` phonetic word decoder. |
| `rot47` / `rot18` | `(text: str) -> str` | Printable ASCII 33–126 rotation and alphanumeric rotation. |
| `repeating_key_xor` / `xor_bytes` | `(data: bytes, key: bytes \| int) -> bytes` | Single-byte and multi-byte repeating XOR. |

### 1.2 RSA, Asymmetric & Mathematical Attacks (`ctf_toolkit.crypto.rsa`)
| Function | Signature | Purpose |
| :--- | :--- | :--- |
| `rsa_solve_pqec` | `(p: int, q: int, e: int, c: int) -> bytes` | Decrypt RSA given prime factors $p, q$. |
| `rsa_solve_phi_e_c` | `(phi: int, e: int, c: int) -> bytes` | Decrypt RSA given Euler's totient $\phi(N)$. |
| `rsa_fermat` | `(n: int, max_steps: int = 100000) -> tuple[int, int]` | Factor $N = p \cdot q$ when $|p - q|$ is small. |
| `rsa_wiener` | `(e: int, n: int) -> int \| None` | Recover private key $d$ via continued fractions when $d < \frac{1}{3}N^{1/4}$. |
| `hastad_unpadded` | `(ciphertexts: list[int], moduli: list[int], e: int) -> int` | Chinese Remainder Theorem (CRT) broadcast attack + $e$-th root. |
| `common_modulus_attack` | `(n: int, e1: int, e2: int, c1: int, c2: int) -> bytes` | Extended GCD recovery when two messages share modulus $N$. |
| `pollard_p_minus_1` | `(n: int, B: int = 10000) -> int \| None` | Factor $N$ when $p - 1$ is $B$-smooth. |
| `dp_leak_recover` | `(n: int, e: int, dp: int, c: int) -> bytes` | Recover $p, q$ and plaintext from CRT exponent $d_p = d \bmod (p-1)$. |
| `rabin_decrypt` | `(p: int, q: int, c: int) -> list[bytes]` | Compute all 4 modular square roots for Rabin cryptosystem ($e=2$). |

### 1.3 Symmetric, Stream, PRNG & Hashes (`ctf_toolkit.crypto.*`)
- `ctf_toolkit.crypto.aes`: `aes_ecb_decrypt`, `aes_cbc_decrypt`, `aes_ctr_decrypt`, `pkcs7_unpad`
- `ctf_toolkit.crypto.des`: `des_ecb_decrypt`, `des3_cbc_decrypt`
- `ctf_toolkit.crypto.rc4`: `rc4_crypt`
- `ctf_toolkit.crypto.fernet`: `fernet_decrypt_token`
- `ctf_toolkit.crypto.stream_attacks`: `crib_drag_xor`, `recover_lcg_modulus`, `shamir_reconstruct_secret`
- `ctf_toolkit.crypto.encoding`: Base32/45/58/62/64/85/91, Braille, Baudot, Z85, EBCDIC, Morse (`ctf_toolkit.crypto.morse`)

---

## 2. Binary Exploitation / Pwn (`ctf_toolkit.pwn` & `ctf_toolkit.binex`)

| Function | Module | Purpose |
| :--- | :--- | :--- |
| `build_ret2win_payload` | `ctf_toolkit.pwn.overflow` | Construct buffer padding + packed 32/64-bit return address override. |
| `build_variable_overwrite` | `ctf_toolkit.pwn.overflow` | Construct stack local variable corruption payload. |
| `build_rop_chain` | `ctf_toolkit.pwn.rop` | Assemble padding + sequence of little-endian ROP gadget addresses and arguments. |
| `leak_stack_offsets` | `ctf_toolkit.pwn.format_string` | Generate `%k$p` format string probes and parse leaked hex words into ASCII. |
| `calculate_oob_offset` | `ctf_toolkit.pwn.arrays` | Compute negative/positive array index offset `(target_addr - base_addr) // stride`. |
| `cyclic_create` / `cyclic_find` | `ctf_toolkit.binex.pwncalc` | De Bruijn non-repeating pattern generator and crash offset calculator. |
| `describe_integer_bounds` | `ctf_toolkit.binex.pwncalc` | Analyze signed/unsigned 32/64-bit integer overflow/underflow boundaries. |
| `parse_elf` / `scan_gadgets` | `ctf_toolkit.binex.elf` / `gadgets` | Inspect ELF headers/protections and locate `ret` / `pop rdi; ret` gadgets. |

---

## 3. Web Exploitation (`ctf_toolkit.web`)

| Function | Module | Purpose |
| :--- | :--- | :--- |
| `build_sqli_payload` / `build_sqli_auth_bypass` | `ctf_toolkit.web.helpers` | Generate UNION, boolean, and comment-truncated SQL injection payloads. |
| `build_ssti_payload` | `ctf_toolkit.web.helpers` | Craft Jinja2/Twig/Mako Server-Side Template Injection payloads. |
| `build_ssrf_url` / `build_ssrf_metadata_url` | `ctf_toolkit.web.helpers` | Generate cloud metadata (`169.254.169.254`) and localhost bypass URLs. |
| `build_lfi_path` / `generate_traversal_payloads` | `ctf_toolkit.web.helpers` / `traversal` | Generate dot-dot-slash, double-encoded, and PHP filter LFI payloads. |
| `build_json_post` / `build_post_request` / `build_get_request` | `ctf_toolkit.web.helpers` | Construct raw HTTP request envelopes with custom headers/cookies. |
| `build_multipart_payload` | `ctf_toolkit.web.helpers` | Build multipart/form-data file upload bypass bodies. |
| `build_cors_request` / `add_forwarded_headers` | `ctf_toolkit.web.helpers` | Inject `Origin`, `X-Forwarded-For`, `X-Real-IP`, and `Client-IP` bypass headers. |
| `jwt_decode_no_verify` | `ctf_toolkit.web.helpers` | Inspect JWT header, claims, and signature without secret verification. |
| `build_idor_payloads` | `ctf_toolkit.web.idor` | Generate padded, Base64, MD5, and hex IDOR enumeration matrices. |

---

## 4. Forensics, Steganography & Reversing (`ctf_toolkit.forensics` & `reversing`)

| Function | Module | Purpose |
| :--- | :--- | :--- |
| `extract_docx_metadata` | `ctf_toolkit.forensics.office` | Parse OOXML `docProps/core.xml`, `app.xml`, and `custom.xml` properties. |
| `extract_docx_hidden_vanish` / `comments` / `revisions` | `ctf_toolkit.forensics.docx_tools` | Extract `<w:vanish>` hidden runs, author comments, and tracked changes. |
| `extract_xlsx_metadata` | `ctf_toolkit.forensics.xlsx_tools` | Extract `veryHidden` worksheets, sharedStrings, and cell comments. |
| `extract_pdf_metadata` / `extract_pdf_decompressed_streams` | `ctf_toolkit.forensics.pdf_tools` | Decompress PDF `/FlateDecode` streams, off-page text, and attachments. |
| `extract_png_trailing_bytes` / `extract_png_text_chunks` | `ctf_toolkit.forensics.png_tools` | Carve payloads after `IEND` and extract `tEXt`/`zTXt`/`iTXt` metadata. |
| `repair_png_header` / `repair_jpeg_header` / `repair_zip_header` | `ctf_toolkit.forensics.*` | Automatically fix corrupted magic bytes and CRC headers. |
| `extract_channel_lsb` / `extract_sequential_rgb_bytes` | `ctf_toolkit.forensics.image_channels` | Extract R/G/B/A bitplanes and LSB steganography payloads. |
| `extract_audio_pcm_lsb` / `decode_dtmf_tones` / `demodulate_audio_fsk` | `ctf_toolkit.forensics.audio_tools` | Recover WAV LSB bits, DTMF keypad digits, and FSK/MFSK audio modems. |
| `extract_pcap_artifacts` / `extract_dns_subdomain_exfiltration` | `ctf_toolkit.forensics.pcap_extract` | Reassemble HTTP auth, DNS exfiltration chunks, and USB HID/serial captures. |
| `extract_strings_from_object` | `ctf_toolkit.forensics.artifact_discovery` | Extract printable strings from zlib-compressed Git loose objects and blobs. |
| `extract_pyc_constants_raw` / `decompile_pyc` | `ctf_toolkit.forensics.pyc_decompile` | Extract marshaled code constants and disassemble Python `.pyc` bytecode. |
| `xor_bruteforce_single` / `byte_shift_bruteforce` / `endian_swap` | `ctf_toolkit.reversing.transforms` | Reverse common binary string obfuscation loops and 32/64-bit endianness swaps. |

---

## 5. Blockchain / EVM & Smart Contracts (`ctf_toolkit.blockchain`)

| Function | Module | Purpose |
| :--- | :--- | :--- |
| `parse_calldata` / `decode_calldata_charcodes` | `ctf_toolkit.blockchain.calldata` | Split Ethereum ABI calldata into 4-byte selector, 32-byte words, and ASCII strings. |
| `decode_revert_reason` | `ctf_toolkit.blockchain.calldata` / `revert` | Decode EVM `Error(string)` (`0x08c379a0`) and `Panic(uint256)` (`0x4e487b71`) payloads. |
| `compute_mapping_slot` / `compute_dynamic_array_slot` | `ctf_toolkit.blockchain.storage` | Calculate Keccak-aligned EVM storage slot indices for private mappings/arrays. |
| `decode_event_logs` | `ctf_toolkit.blockchain.events` | Extract indexed topics and non-indexed ABI data from transaction receipt logs. |

---

## 6. OSINT, Config Hunting & Esoteric Languages (`ctf_toolkit.osint_misc`)

| Function | Module | Purpose |
| :--- | :--- | :--- |
| `ct_parser` | `ctf_toolkit.osint_misc.parsers` | Extract subdomains and flags from Certificate Transparency (`crt.sh`) JSON logs. |
| `whois_parser` | `ctf_toolkit.osint_misc.parsers` | Parse ASN/domain WHOIS records into normalized dictionaries (`org`, `aut-num`, `country`). |
| `html_comment_parser` | `ctf_toolkit.osint_misc.parsers` | Extract HTML comments (`<!-- ... -->`) and embedded tokens from Wayback snapshots. |
| `landmark_matcher` / `lookup_city_by_coordinates` | `ctf_toolkit.osint_misc.parsers` | Resolve geographic coordinates and plaque clues to landmark/city names. |
| `extract_sqlite_secrets` / `extract_cron_secrets` | `ctf_toolkit.osint_misc.config_hunter` | Scan SQLite databases and crontab files for embedded credentials, Base64, and flags. |
| `extract_json_secrets` / `extract_yaml_secrets` / `extract_ini_secrets` | `ctf_toolkit.osint_misc.config_hunter` | Traverse nested JSON, JSONL, YAML, INI, CSV, TSV, VCF, and ICS files for secrets. |
| `brainfuck_eval` / `ook_eval` / `deadfish_eval` / `spoon_eval` / `whitespace_eval` | `ctf_toolkit.osint_misc.esolang` | Execute esoteric programming languages and return captured standard output. |
