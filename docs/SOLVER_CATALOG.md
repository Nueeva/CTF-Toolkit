# CTF-Toolkit v4.0 Apex — Solver Abstractions Catalog (560+ Functions)

All solver modules in `ctf_toolkit` are dynamically indexed in the **Command Palette (`/search`)**, directly callable from the terminal via **`ctf-toolkit call <function_name> [args...]`**, and importable inside standalone Python solve scripts.

---

## 1. Cryptography & Mathematical Attacks (`ctf_toolkit.crypto`)

### 1.1 Automated RSA, Lattice (LLL) & Elliptic Curve (`rsa_auto`, `lattice_lll`, `ecc`, `rsa`)
| Function | Module | Signature & Purpose |
| :--- | :--- | :--- |
| `solve_rsa_auto` | `ctf_toolkit.crypto.rsa_auto` | `(n, e, c=None, dp=None, dq=None, phi=None, ...) -> dict`: Cascades across Small-$e$ root, Fermat, Small factor, Pollard $p-1$, Pollard $\rho$, Wiener, Boneh-Durfee lattice roots, Common Modulus, and Håstad CRT. |
| `parse_pem_key` | `ctf_toolkit.crypto.rsa_auto` | `(pem_or_der: str \| bytes) -> dict`: Extracts `(n, e, d, p, q)` from PEM/DER public or private keys. |
| `rsa_factor_small` | `ctf_toolkit.crypto.rsa` | `(n: int, e: int = 65537, c: int \| None = None) -> tuple[int, int] \| bytes`: Factors composite $N$ via trial division + Pollard $\rho$ and optionally decrypts $c$. |
| `rsa_solve_pqec` / `rsa_solve_phi_e_c` | `ctf_toolkit.crypto.rsa` | Decrypt RSA given prime factors $(p, q)$ or Euler's totient $\phi(N)$. |
| `rsa_fermat` / `rsa_wiener` | `ctf_toolkit.crypto.rsa` | Fermat close-prime factorization and Wiener continued-fraction small-$d$ recovery. |
| `hastad_unpadded` / `common_modulus_attack` | `ctf_toolkit.crypto.rsa` | Chinese Remainder Theorem (CRT) broadcast attack and Extended GCD common modulus recovery. |
| `pollard_p_minus_1` / `dp_leak_recover` / `rabin_decrypt` | `ctf_toolkit.crypto.rsa` | Pollard $p-1$ smooth factorizer, CRT $d_p$ leak recovery, and 4-root Rabin decryption ($e=2$). |
| `lll_reduce` / `gauss_reduce_2d` | `ctf_toolkit.crypto.lattice_lll` | `(basis: list[list[int]], delta: float = 0.75) -> list[list[int]]`: Pure-Python Lenstra–Lenstra–Lovász (LLL) and 2D Gauss lattice basis reduction. |
| `solve_knapsack_lll` | `ctf_toolkit.crypto.lattice_lll` | `(weights: list[int], target_sum: int) -> list[int] \| None`: Solves subset-sum / Merkle-Hellman knapsack via LLL embedding. |
| `coppersmith_small_root_univariate` | `ctf_toolkit.crypto.lattice_lll` | `(coeffs: list[int], N: int, X: int) -> list[int]`: Finds small modular roots $|x_0| \le X$ of $f(x) \equiv 0 \pmod N$. |
| `ecc_point_add` / `ecc_scalar_mul` | `ctf_toolkit.crypto.ecc` | Weierstrass elliptic curve point addition and double-and-add scalar multiplication over $\mathbb{F}_p$. |
| `ecc_small_subgroup_dlog` | `ctf_toolkit.crypto.ecc` | Baby-Step Giant-Step (BSGS) discrete logarithm solver on elliptic curves. |
| `ecc_smarts_attack` | `ctf_toolkit.crypto.ecc` | `(G, Q, a, b, p) -> int`: Smart's $p$-adic lift attack for anomalous curves where $\#E(\mathbb{F}_p) = p$. |
| `ecc_invalid_curve_recovery` | `ctf_toolkit.crypto.ecc` | Combines partial discrete log residues `(d mod m_i)` via CRT for invalid-curve / Pohlig-Hellman attacks. |

### 1.2 Active Block, Stream & Hash Attacks (`block_attacks`, `aes`, `des`, `hashes`, `auto_decode`)
| Function | Module | Purpose |
| :--- | :--- | :--- |
| `cbc_bitflip_craft` | `ctf_toolkit.crypto.block_attacks` | XOR-crafts an IV or previous ciphertext block to mutate target plaintext bytes in AES/DES-CBC. |
| `padding_oracle_decrypt_block` | `ctf_toolkit.crypto.block_attacks` | Recovers plaintext block byte-by-byte against a boolean PKCS#7 padding oracle callback. |
| `ecb_byte_at_a_time_recover` | `ctf_toolkit.crypto.block_attacks` | Automated chosen-prefix block alignment and byte-by-byte suffix recovery against an ECB encryption oracle. |
| `many_time_pad_crib_drag` | `ctf_toolkit.crypto.block_attacks` | Slides known cribs across multi-ciphertext XOR streams and ranks printable plaintext segments. |
| `aes_ecb_decrypt` / `aes_cbc_decrypt` / `aes_ctr_decrypt` | `ctf_toolkit.crypto.aes` | Standard AES decryption primitives and `pkcs7_unpad`. |
| `des_ecb_decrypt` / `triple_des_ecb_decrypt` | `ctf_toolkit.crypto.des` | PyCryptodome-backed DES and 3DES ECB/CBC encryption and decryption. |
| `crack_crc32_4byte` | `ctf_toolkit.crypto.hashes` | Algebraically inverts the IEEE 802.3 CRC32 state machine to recover 4-byte ASCII preimages. |
| `solve_lfsr` | `ctf_toolkit.crypto.solvers.stream` | Recovers linear feedback shift register taps via Berlekamp-Massey from observed bits and decrypts ciphertext. |
| `coppersmith_stereotyped` | `ctf_toolkit.crypto.coppersmith` | Recovers small roots of $(known + x)^e - c \equiv 0 \pmod n$ using Howgrave-Graham LLL reduction. |
| `auto_decode_layers` | `ctf_toolkit.crypto.auto_decode` | Greedy iterative multi-hop decoder across Hex, Base64/32/58/85, URL, zlib/gzip, and ROT13. |

### 1.3 Classical & Polyalphabetic Ciphers (`ctf_toolkit.crypto.classical`)
Includes 30+ ciphers: `rot_n`, `caesar_decrypt`, `caesar_bruteforce`, `atbash`, `vigenere_decrypt`, `beaufort_decrypt`, `autokey_decrypt`, `gronsfeld_decrypt`, `porta_decrypt`, `trithemius_decrypt`, `affine_decrypt`, `multiplicative_decrypt`, `bacon_decode`, `polybius_decode`, `playfair_decrypt`, `bifid_decrypt`, `trifid_decrypt`, `four_square_decrypt`, `two_square_decrypt`, `adfgx_decrypt`, `adfgvx_decrypt`, `nihilist_decrypt`, `hill_decrypt_2x2`, `hill_decrypt_3x3`, `rail_fence_decrypt`, `scytale_decrypt`, `columnar_transposition_decrypt`, `myszkowski_decrypt`, `tap_code_decode`, `a1z26_decode`, `nato_phonetic_decode`, `rot47`, `rot18`, `repeating_key_xor`, `xor_bytes`.

---

### 1.4 Deep Primitive Solvers (`length_extension`, `crc_forge`, `lfsr`, `galois`, `dlog_engine`, `padic`)

Added 2026-11-14. Pure stdlib — no PyCryptodome, no gmpy2, no Sage.

| Function | Module | Signature & Purpose |
| :--- | :--- | :--- |
| `length_extension` | `ctf_toolkit.crypto.length_extension` | `(algorithm, secret_len, message, append, digest) -> LengthExtensionResult`: resumes the Merkle–Damgård compression function from a leaked digest and returns the forged digest plus the exact wire payload plus the glue padding. Supports `md5`, `sha1`, `sha256`. |
| `length_extension_candidates` | `ctf_toolkit.crypto.length_extension` | `(algorithm, digest, message, append, secret_lens=range(1,33)) -> list[...]`: brute the unknown secret length; each candidate carries its own glue padding. |
| `md5_pad` / `reference_digest` | `ctf_toolkit.crypto.length_extension` | Glue padding for a given message length, and a `hashlib` ground truth used by the tests. |
| `forge_crc32` | `ctf_toolkit.crypto.crc_forge` | `(data, target, offset=None) -> CRCForgeResult`: solves the 32×32 GF(2) system over a four-byte window so `crc32(data') == target`. Raises on an unreachable target. |
| `forge_crc32_hex` / `crc32_value` | `ctf_toolkit.crypto.crc_forge` | Hex-target convenience wrapper and raw IEEE 802.3 checksum. |
| `berlekamp_massey` | `ctf_toolkit.crypto.lfsr` | `(bits) -> (taps, complexity)`: shortest linear recurrence over GF(2); `lfsr_predict` then extends the stream. |
| `lfsr_generate` / `recover_from_bytes` | `ctf_toolkit.crypto.lfsr` | Forward generation from an explicit seed, and bytes-in → `LFSRModel` recovery. |
| `bits_from_bytes` / `bits_to_bytes` / `bits_from_int` | `ctf_toolkit.crypto.lfsr` | Bit-packing helpers with MSB-first and LSB-first order. |
| `gf256_mul` / `gf256_inv` / `gf256_pow` / `gf_find_generator` | `ctf_toolkit.crypto.galois` | GF(2^8) arithmetic under the AES reduction polynomial `0x11B`; verified against the `0x57·0x83 = 0xC1` vector. |
| `rs_syndrome` / `rs_berlekamp_massey` / `rs_chien_search` / `rs_forney_roots` | `ctf_toolkit.crypto.galois` | Reed-Solomon decode chain over GF(2^8). |
| `crt` / `crt_combine` | `ctf_toolkit.crypto.galois` | Integer CRT with inconsistency detection (returns `(x, lcm)`). |
| `poly2_gcd` / `poly2_mul` / `poly2_divmod` / `poly2_mod` | `ctf_toolkit.crypto.galois` | GF(2) polynomial arithmetic on integer bitmasks — used by CRC/linear-algebra paths. |
| `bsgs` | `ctf_toolkit.crypto.dlog_engine` | `(g, h, p, order=None) -> x`: baby-step giant-step in O(√order) with a monotonic deadline. |
| `pohlig_hellman_dlog` | `ctf_toolkit.crypto.dlog_engine` | `(g, h, p) -> (x, factors)`: digit-by-digit recovery per prime power, CRT recombination, self-verifying. |
| `EllipticCurve` / `ECPoint` | `ctf_toolkit.crypto.dlog_engine` | Affine group law over F_p with `add`, `mul`, `neg`, `on_curve`, and a correct `order_naive` (two points per quadratic residue). |
| `smart_attack_coords` | `ctf_toolkit.crypto.dlog_engine` | `(a, b, p, px, py, qx, qy) -> k`: flat-argument twin for the web API / CLI, where JSON cannot carry an `EllipticCurve`. |
| `ec_bsgs` / `ec_bsgs_coords` | `ctf_toolkit.crypto.dlog_engine` | `(a, b, p, px, py, qx, qy, order=None) -> k`: Baby-Step Giant-Step discrete logarithm solver on general elliptic curves over $\mathbb{F}_p$. |
| `ec_add` / `ec_mul` / `curve_order_naive` / `ec_validate_point` | `ctf_toolkit.crypto.dlog_engine` | Scalar-only curve helpers for the same dispatcher path. |
| `smart_attack` | `ctf_toolkit.crypto.dlog_engine` | `(curve, P, Q) -> k`: anomalous-curve ECDLP via Q_p lift, elliptic logarithm `-x/y`, with random-lift retries and a verification gate on `k·P == Q`. |
| `QpContext` / `Qp` | `ctf_toolkit.crypto.padic` | Fixed-precision p-adics with explicit valuation, exact division of non-units, and Hensel square roots. |
| `paillier_keygen` / `paillier_encrypt` / `paillier_decrypt` | `ctf_toolkit.crypto.paillier` | Key generation, encryption ($c = g^m \cdot r^n \pmod{n^2}$), and decryption ($m = L(c^\lambda) \cdot \mu \pmod n$) for Paillier cryptosystem. |
| `paillier_homomorphic_add` / `paillier_homomorphic_mul` | `ctf_toolkit.crypto.paillier` | Additive homomorphism ($c_1 \cdot c_2 \pmod{n^2}$) and scalar multiplication ($c^k \pmod{n^2}$). |
| `paillier_auto_solve` | `ctf_toolkit.crypto.paillier` | `(c, n, p=None, q=None) -> int`: Automated Paillier challenge solver with factor recovery. |
| `bleichenbacher_forge_signature` | `ctf_toolkit.crypto.rsa` | `(message, key_size_bits=1024, hash_algo='sha256', e=3) -> int`: Forges PKCS#1 v1.5 RSA signature under low exponent $e=3$ exploiting trailing garbage parser flaws. |
| `shamir_reconstruct_secret` | `ctf_toolkit.crypto.rsa` | `(shares: list[tuple[int, int]], p: int) -> int`: Lagrange polynomial interpolation to reconstruct secret at $x=0$ over $\mathbb{F}_p$. |
| `franklin_reiter_related_message` | `ctf_toolkit.crypto.lks_national_suite` | `(n, e, c1, c2, a=1, b=0) -> bytes`: Recovers message $m_1$ from related ciphertexts $c_1 = m_1^3, c_2 = (a \cdot m_1 + b)^3 \pmod n$. |

## 2. Binary Exploitation / Pwn (`ctf_toolkit.pwn` & `ctf_toolkit.binex`)

| Function | Module | Purpose |
| :--- | :--- | :--- |
| `build_ret2win_payload` | `ctf_toolkit.pwn` | Construct buffer padding + packed 32/64-bit return address override. |
| `build_variable_overwrite` | `ctf_toolkit.pwn` | Construct stack local variable corruption payload. |
| `build_rop_chain` | `ctf_toolkit.pwn` | Assemble padding + sequence of little-endian ROP gadget addresses and arguments. |
| `leak_stack_offsets` / `build_format_string_probe` | `ctf_toolkit.pwn` | Generate `%k$p` format string probes and parse leaked hex words into ASCII. |
| `calculate_oob_offset` | `ctf_toolkit.pwn` | Compute negative/positive array index offset `(target_addr - base_addr) // stride`. |
| `cyclic_create` / `cyclic_find` | `ctf_toolkit.pwn` | De Bruijn non-repeating pattern generator and crash offset calculator. |
| `describe_integer_bounds` | `ctf_toolkit.pwn` | Analyze signed/unsigned 32/64-bit integer overflow/underflow boundaries. |
| `parse_elf` / `scan_gadgets` | `ctf_toolkit.binex.elf` / `gadgets` | Inspect ELF headers/protections and locate `ret` / `pop rdi; ret` gadgets. |

---

## 3. Web Exploitation & Deserialization (`ctf_toolkit.web`)

| Function | Module | Purpose |
| :--- | :--- | :--- |
| `jwt_forge_none` | `ctf_toolkit.web.jwt_attacks` | Craft unsigned `alg: "none"` JWT tokens with modified payload claims. |
| `jwt_crack_hs256` / `jwt_sign_hs256` | `ctf_toolkit.web.jwt_attacks` | Offline dictionary cracker and signer for HMAC-SHA256 JWT tokens. |
| `jwt_forge_key_confusion` | `ctf_toolkit.web.jwt_attacks` | Forge RS256→HS256 key-confusion tokens signed using the server's RSA public key bytes. |
| `jwt_inject_jwk_header` / `jwt_inject_kid_sqli` | `ctf_toolkit.web.jwt_attacks` | Inject custom `jwk` headers or `kid` path-traversal / SQLi payloads into JWT headers. |
| `pickle_inspect_opcodes` / `generate_pickle_test_payload` | `ctf_toolkit.web.deserialization` | Disassemble Python `pickle` VM opcodes safely via `pickletools` and craft `__reduce__` payloads. |
| `parse_php_serialized` / `build_php_serialized_object` | `ctf_toolkit.web.deserialization` | Parse PHP `O:...` strings and craft PHP Object Injection payloads (with CVE-2016-7124 `__wakeup` bypass). |
| `build_sqli_payload` / `build_sqli_auth_bypass` | `ctf_toolkit.web.helpers` | Generate UNION, boolean, and comment-truncated SQL injection payloads. |
| `build_ssti_payload` | `ctf_toolkit.web.helpers` | Craft Jinja2/Twig/Mako Server-Side Template Injection payloads. |
| `build_ssrf_url` / `build_ssrf_metadata_url` | `ctf_toolkit.web.helpers` | Generate cloud metadata (`169.254.169.254`) and localhost bypass URLs. |
| `build_lfi_path` / `generate_traversal_payloads` | `ctf_toolkit.web.helpers` / `traversal` | Generate dot-dot-slash, double-encoded, and PHP filter LFI payloads. |
| `build_idor_payloads` | `ctf_toolkit.web.idor` | Generate padded, Base64, MD5, and hex IDOR enumeration matrices. |

---

## 4. Forensics, Steganography, Wasm & Reversing (`ctf_toolkit.forensics` & `reversing`)

| Function | Module | Purpose |
| :--- | :--- | :--- |
| `carve_embedded_files` | `ctf_toolkit.forensics.carver` | Signature-based multi-stream binary carver (PNG, ZIP, PDF, ELF, GZIP, ZLIB, BZ2, XZ, RAR, 7z, SQLite) with automatic decompression. |
| `analyze_wasm_binary` | `ctf_toolkit.forensics.wasm_analyzer` | Pure-Python WebAssembly (`.wasm`) binary dissector extracting imports, exports, and data-segment strings. |
| `extract_mov_stack_strings` | `ctf_toolkit.reversing.stack_strings` | Reconstructs obfuscated stack strings from x86/x64 disassembly (`mov BYTE/WORD/DWORD/QWORD PTR [rbp-...], 0x...`). |
| `solve_crackme_byte_transform` | `ctf_toolkit.reversing.transforms` | Brute-forces single-byte XOR, additive/subtractive shifts, and ROL/ROR bit rotations for crackme targets. |
| `extract_docx_metadata` / `extract_docx_hidden_vanish` | `ctf_toolkit.forensics.docx_tools` | Parse OOXML properties, `<w:vanish>` hidden runs, author comments, and tracked changes. |
| `extract_xlsx_metadata` | `ctf_toolkit.forensics.xlsx_tools` | Extract `veryHidden` worksheets, sharedStrings, and cell comments. |
| `extract_pdf_metadata` / `scan_pdf_raw_objects` | `ctf_toolkit.forensics.pdf_tools` | Decompress PDF `/FlateDecode` streams, off-page text, attachments, and raw object tokens. |
| `extract_png_trailing_bytes` / `repair_png_header` | `ctf_toolkit.forensics.png_tools` | Carve payloads after `IEND`, extract text chunks, and repair corrupted magic/CRC headers. |
| `extract_channel_lsb` / `decode_qr_image` | `ctf_toolkit.forensics.image_channels` | Extract R/G/B/A bitplanes, LSB steganography payloads, and rotated QR codes. |
| `extract_audio_pcm_lsb` / `decode_dtmf_tones` / `demodulate_audio_fsk` | `ctf_toolkit.forensics.audio_tools` | Recover WAV LSB bits, DTMF keypad digits, and FSK/MFSK audio modems. |
| `extract_pcap_artifacts` / `extract_dns_subdomain_exfiltration` | `ctf_toolkit.forensics.pcap_extract` | Reassemble HTTP auth, DNS exfiltration chunks, and USB HID/serial captures. |
| `extract_pyc_constants_raw` / `decompile_pyc` | `ctf_toolkit.forensics.pyc_decompile` | Extract marshaled code constants and disassemble Python `.pyc` bytecode. |
| `audit_etc_passwd` / `audit_sshd_config` | `ctf_toolkit.forensics.linux_forensics` | Detect rogue UID 0 accounts, login shells, and insecure SSH daemon directives. |

---

## 5. Blockchain / EVM & Smart Contracts (`ctf_toolkit.blockchain`)

| Function | Module | Purpose |
| :--- | :--- | :--- |
| `parse_calldata` / `decode_calldata_charcodes` | `ctf_toolkit.blockchain.calldata` | Split Ethereum ABI calldata into 4-byte selector, 32-byte words, and ASCII strings. |
| `decode_revert_reason` | `ctf_toolkit.blockchain.revert` | Decode EVM `Error(string)` (`0x08c379a0`) and `Panic(uint256)` (`0x4e487b71`) payloads. |
| `compute_mapping_slot` / `compute_dynamic_array_slot` | `ctf_toolkit.blockchain.storage` | Calculate Keccak-aligned EVM storage slot indices for private mappings/arrays. |
| `decode_event_logs` | `ctf_toolkit.blockchain.events` | Extract indexed topics and non-indexed ABI data from transaction receipt logs. |
| `compute_merkle_root` / `resolve_4byte_selector` / `crack_keccak256_wordlist` | `ctf_toolkit.blockchain.protocols` | Compute Keccak256 Merkle tree roots, match 4-byte function selectors, and crack Keccak256 hashes. |

---

## 6. OSINT, Wire Formats, Config Hunting & Esolangs (`ctf_toolkit.osint_misc`)

| Function | Module | Purpose |
| :--- | :--- | :--- |
| `decode_protobuf_raw` / `decode_msgpack_raw` / `decode_cbor_raw` | `ctf_toolkit.osint_misc.binary_formats` | Schema-less decoders for Protobuf wire tags, MessagePack, and CBOR binary objects. |
| `parse_asn1_der_strings` / `parse_bplist_strings` | `ctf_toolkit.osint_misc.binary_formats` | Extract printable strings from ASN.1 DER structures and Apple `bplist00` binary property lists. |
| `decompress_git_loose_object` / `reassemble_seq_chunks` / `decode_timestamp_delta_channel` | `ctf_toolkit.osint_misc.binary_formats` | Decompress Git objects, reassemble out-of-order `SEQ:N:` packets, and decode covert timing channels. |
| `mine_profile_handles` | `ctf_toolkit.osint_misc.profile_miner` | Extract `@handles`, emails, URLs, commit SHAs, and flags from OSINT profile dumps. |
| `parse_toml_secrets` / `parse_jsonc` / `resolve_json_pointer` / `parse_mime_email_parts` / `extract_xml_namespaced_values` | `ctf_toolkit.osint_misc.config_hunter` | Parse TOML, JSONC, RFC 6901 JSON Pointers, `.eml` MIME attachments, and namespaced XML documents. |
| `decode_unicode_tag_plane` / `decode_seven_segment` / `extract_acrostic` / `extract_periodic_step` / `decode_case_bitstream` / `reconstruct_from_regex_pattern` | `ctf_toolkit.osint_misc.stego` | Decode Unicode Plane 14 tag stego (`U+E0000`), 7-segment displays, acrostics, case bitstreams, and regex patterns. |
| `befunge_extract_strings` / `decode_collatz_ascii` / `brainfuck_eval` / `ook_eval` / `deadfish_eval` / `spoon_eval` / `whitespace_eval` | `ctf_toolkit.osint_misc.esolang` | Execute or extract flags from Befunge-93, Collatz sequences, Brainfuck, Ook!, Deadfish, Spoon, and Whitespace. |
