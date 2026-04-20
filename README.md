# CTF Toolkit (Modular)

Toolkit Python modular untuk latihan CTF/lab, dirancang agar alurnya cepat dipakai saat practice dan tetap aman untuk lingkungan belajar.

> Gunakan hanya untuk pembelajaran, lab, dan challenge legal. Jangan gunakan pada sistem nyata tanpa izin.

---

## Kenapa toolkit ini?

Toolkit ini menggabungkan helper yang paling sering dipakai di challenge:
- decoding cepat,
- eksplorasi XOR/crypto,
- helper binary exploitation,
- helper web (tanpa auto-scan),
- forensics offline untuk file/pcap.

Semua disajikan dalam CLI menu interaktif agar mudah dipahami pengguna baru.

---

## Persyaratan

- Python **3.10+**
- Dependensi Python dari `requirements.txt`:
  - `requests`
  - `pycryptodome`
  - `dpkt`

---

## Instalasi

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Menjalankan toolkit

```bash
python3 main.py
```

atau:

```bash
python3 -m ctf_toolkit
```

---

## Alur cepat (untuk pemula)

1. Jalankan `python3 main.py`.
2. Pilih menu sesuai kebutuhan (mis. decode, crypto, forensics).
3. Masukkan data sesuai format input yang diminta.
4. Baca output text + hex (untuk menu yang berbasis bytes).
5. Ulangi dengan parameter lain sampai kandidat flag ditemukan.

---

## Format input yang sering dipakai

Beberapa menu menerima input bytes dengan format:
- `raw:teks_asli` → treat sebagai teks biasa
- `hex:414243` → treat sebagai hex bytes
- `b64:QUJD` → treat sebagai Base64
- tanpa prefix → mode auto-parse

Untuk operasi XOR tertentu, kamu juga bisa kirim **byte-list**:
- `0x43, 100, 0x60, ...`

---

## Ringkasan menu utama

### 1) Decode/Encode
- Base64 encode/decode
- Hex encode/decode
- ROT13 dan ROT-n
- XOR single-byte
- XOR alternating key (even/odd)
- XOR repeating key pattern

### 2) XOR Brute Force
- Brute-force key `0..255`
- Menampilkan kandidat plaintext berdasarkan keyword umum CTF

### 3) Regex Flag Finder
- Cari pola flag umum (`flag{}`, `CTF{}`, `LKS{}`, `LKSJAKTIM{}` dan variannya)

### 4) File Scanner / Strings
- Extract printable strings
- Hitung entropy
- Tampilkan preview hexdump
- Highlight string yang mencurigakan

### 5) HTTP Request Tester
- GET/POST sederhana
- Parameter query/body (`k=v,k2=v2`)
- Opsi verifikasi SSL on/off
- Output response dipotong agar tetap ringkas

### 6) Simple Wordlist Brute (Simulasi)
- Uji daftar password terhadap dummy login checker
- **Default dummy password:** `ctf123` (bisa diubah via env `DUMMY_LOGIN_PASSWORD`)

### 7) Crypto Tools

#### Classical
- Caesar encrypt/decrypt/bruteforce
- Atbash
- Vigenere encrypt/decrypt
- Affine encrypt/decrypt
- Substitution apply + frequency analysis

#### RSA
- Encrypt/decrypt dasar (`m^e mod n`, `c^d mod n`)
- Common modulus attack
- Hastad broadcast attack
- Fermat factorization
- Hitung private exponent `d` dari faktor prima
- Close-primes solver end-to-end (Fermat → hitung `d` → decrypt)

#### AES/Stream
- ECB encrypt/decrypt
- CBC encrypt/decrypt
- CTR encrypt/decrypt
- PKCS#7 pad/unpad
- ECB detection
- CTR keystream reuse (two-time pad) dengan known pair

> Catatan: dukungan ECB disediakan untuk kebutuhan analisis CTF/legacy challenge, bukan untuk sistem produksi.

#### PRNG
- LCG generate
- LCG recover parameter saat modulus diketahui

#### Hashes
- MD5, SHA1, SHA256 digest

### 8) BinEx Tools
- Cyclic pattern create
- Cyclic offset find
- Pack/unpack (`p32/p64/u32/u64`)
- ELF triage/checksec-lite (heuristic PIE/NX/RELRO/Canary)
- Gadget scan dasar (`ret`, `pop rdi; ret`)

### 9) Web Helpers (Safe)
- URL encode/decode
- Base64URL encode/decode
- JWT decode tanpa verifikasi signature
- Request template generator (SQLi/SSRF/SSTI) untuk latihan manual

### 10) Forensics/RE Helpers
- File magic detect
- Hexdump file
- Entropy file
- Strings extractor
- PCAP extractor offline (`.pcap`/`.pcapng`)
- PCAP notes (guidance)
- ZIP recover (corrupted header/trailing)
- JPEG fragment extract + patch dimensi
- Caesar shifter helper

---

## Contoh penggunaan singkat

### A) XOR alternating key dengan byte-list
1. Pilih `Decode/Encode` → `XOR alternating key (even/odd)`.
2. Input data: `0x43, 0x45, 0x54, 0x73, 100, 0x60`.
3. Isi key:
   - `Even key = 0x10`
   - `Odd key = 0x08`
4. Toolkit menampilkan hasil sebagai text (UTF-8 ignore) dan hex.

### B) PCAP extractor (offline)
1. Pilih `Forensics/RE Helpers` → `PCAP Extractor`.
2. Isi path file `.pcap`/`.pcapng`.
3. Hasil tersimpan ke folder output, biasanya:
   - `http.txt`
   - `tcp_strings.txt`
   - `dns.txt`
   - `raw_strings.txt`
   - `hits.txt`
   - `summary.txt`

### C) RSA close-primes challenge
1. Pilih `Crypto Tools` → `RSA` → `Close-primes RSA Solve`.
2. Masukkan `n`, `e`, `c`.
3. Toolkit mencoba Fermat factorization, hitung `d`, lalu decrypt.
4. Output menampilkan plaintext text, raw bytes, dan hex.

---

## Struktur proyek

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

---

## Catatan keamanan & batasan

- Tidak ada eksekusi command eksternal dari toolkit.
- Modul aman untuk di-import tanpa menjalankan CLI otomatis.
- Fitur web helper tidak melakukan auto-scan/auto-exploit.
- Analisis PCAP/JPEG/ZIP dilakukan **offline** pada file lokal.
- JWT decode di menu web **tidak memverifikasi signature**.

---

## Validasi cepat setelah perubahan

```bash
python3 -m py_compile $(find . -name '*.py' -not -path './.venv/*')
printf '0\n' | python3 main.py
```

---

## Lisensi

Lihat file [LICENSE](LICENSE).
