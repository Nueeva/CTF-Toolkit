# CTF Toolkit v5 Workbench

Satu kasus menyimpan file asli, hasil turunan, timeline, dan catatan. CLI dan browser membuka folder kasus yang sama. Semua operasi analisis berjalan secara deterministik di komputer yang membuka kasus.

## Mulai dari demo

Jalankan perintah berikut dari folder repo di PowerShell.

    python -m ctf_toolkit case --dir .\exhibit-demo demo layered
    python -m ctf_toolkit case --dir .\exhibit-demo serve

Buka alamat loopback yang dicetak. Pilih **exhibit.png** dan tekan **Run triage**. Pohon artefak menampilkan ZIP setelah IEND serta dua anggota Base64. Pilih salah satu anggota, buka **Preview steps**, lalu **Save branch**. Pilih rentang byte hasil dan tekan **Trace source** untuk menyorot kelompok karakter Base64 yang sesuai. **Bookmark** menyimpan referensi rentang tersebut.

Buka **Compare artifacts** untuk melihat jendela byte kedua file berdampingan dan daftar struktur. Tampilan membatasi satu jendela ke 4 KiB. Tanda sisipan dan penghapusan menunjukkan perbedaan dalam jendela tersebut.

Gunakan **Verify & replay** atau jalankan perintah ini dari proses baru.

    python -m ctf_toolkit case --dir .\exhibit-demo verify --replay
    python -m ctf_toolkit case --dir .\exhibit-demo export --out .\exhibit-report

Folder ekspor berisi case.json, report.md, dan timeline.jsonl. Isi file tetap berada di workspace. Buat paket penuh saat penerima membutuhkan byte sumber untuk replay.

## Kasus baru dan timeline

    python -m ctf_toolkit case --dir .\case-notes init --title "Review offline"
    python -m ctf_toolkit case --dir .\case-notes add .\sample.png .\access.log
    python -m ctf_toolkit case --dir .\case-notes show
    python -m ctf_toolkit doctor

Gunakan ID dari **show** untuk **analyze**, **transform**, **compare**, dan **source**. Recipe kasus mendukung seluruh varian Base (`b64d`/`b64e`, `b64url_d`/`b64url_e`, `hex_decode`/`hex_encode` (`b16d`/`b16e`), `b32d`/`b32e`, `b32hex_d`/`b32hex_e`, `b36d`/`b36e`, `b45d`/`b45e`, `b58d`/`b58e`, `b58_ripple_d`/`b58_ripple_e`, `b62d`/`b62e`, `b85d`/`b85e`, `a85d`/`a85e`, `z85d`/`z85e`, `b91d`/`b91e`) serta `rot13`, `rot47`, `atbash`, `reverse`, dan `url_d`/`url_e`. Untuk menjalankan transformasi secara manual, gunakan:

    python -m ctf_toolkit case --dir .\case-notes transform ARTIFACT_ID --recipe "b64d | hex_encode"

Triage kasus memvalidasi struktur PNG, ZIP, dan GZIP serta mengenali teks UTF-8. Untuk dokumen Office, gunakan parser metadata terpisah dari toolkit. Contoh pembacaan file lokal:

    python -m ctf_toolkit call extract_docx_metadata "@C:\fixtures\memo.docx" --json
    python -m ctf_toolkit call extract_xlsx_metadata "@C:\fixtures\inventory.xlsx" --json

Pada halaman Timeline, pilih sumber lalu pilih profil **Classic PCAP**, **Access log**, atau **JSONL**. JSONL menerima datetime, message, dan timestamp_desc pada setiap baris. Masukkan offset seperti +07:00 jika sumber tidak membawa zona. Event menyimpan teks waktu asli dan presisi sumber. Pilih beberapa event, klik **Annotate selected**, lalu tulis hubungan yang didukung bukti. Ekspor menyertakan baris berzona dalam format JSONL yang bisa diimpor ke Timesketch.

    python -m ctf_toolkit case --dir .\timeline-demo demo timeline
    python -m ctf_toolkit case --dir .\caesar-demo demo caesar

Di lab Caesar, pilih bahasa Indonesia atau Inggris untuk mendapat tiga pergeseran dengan skor tertinggi dan keterbatasan untuk teks singkat.

Batas v1 adalah 32 MiB per artefak, 128 MiB hasil turunan, 256 turunan, dan kedalaman empat tingkat per analisis. Unggahan browser dibatasi 8 MiB. CLI dapat mengimpor file hingga 32 MiB. Simpan workspace SQLite pada disk lokal host.

## Serah terima offline

    python -m ctf_toolkit case --dir .\exhibit-demo pack --out .\exhibit-bag --with-files
    python -m ctf_toolkit case --dir .\received unpack .\exhibit-bag --author reviewer
    python -m ctf_toolkit case --dir .\received verify --replay
    python -m ctf_toolkit case --dir .\received serve

Paket BagIt berupa folder. Salin seluruh folder ke laptop kedua. Pakai **pack** tanpa --with-files untuk mengirim metadata, referensi, dan catatan saja. Paket berisi catatan tersimpan, jadi pilih penerima yang memang boleh membacanya.

Setelah reviewer menambahkan catatan, buat paket metadata di laptop kedua dan impor kembali ke kasus awal.

    python -m ctf_toolkit case --dir .\received pack --out .\review-return
    python -m ctf_toolkit case --dir .\exhibit-demo merge .\review-return --author owner

Jalankan **merge** ulang jika transfer sebelumnya terputus. Catatan yang sudah tercatat akan dilewati. Saat dua orang mengedit versi dasar yang sama, buka **Notes** dan pilih **Resolve** untuk membaca kedua versi lalu menyimpan keputusan.

## Host privat satu tim

Pasang ekstra team pada mesin host. Sediakan sertifikat TLS dan private key yang cocok dengan nama host. Untuk akses dari laptop lain, izin port pada jaringan privat dan gunakan nama atau IP yang tercakup sertifikat.

    python -m pip install -e ".[team]"
    python -m ctf_toolkit team --dir .\team-data init --admin lead
    python -m ctf_toolkit team --dir .\team-data serve --origin https://workbench.example.test:8443 --host 192.0.2.10 --port 8443 --cert .\server-cert.pem --key .\server-key.pem

Ganti alamat, nama, dan lokasi sertifikat dengan konfigurasi tim. Inisialisasi meminta kata sandi lewat prompt. Simpan sertifikat, key, dan folder team-data di luar riwayat Git. Backup lengkap saat host dihentikan mencakup database akun, key host, dan seluruh folder kasus.

Owner membuka **Members** dan membuat undangan untuk editor atau viewer. Undangan berlaku 24 jam dan habis setelah digunakan. Akun yang sudah ada dapat memakai kata sandi akun saat menerima undangan. Workbench menampilkan pembaruan yang tersimpan. Jika editor menyimpan berdasarkan revisi lama, drafnya tetap tersedia untuk dibandingkan dengan revisi terkini.

Untuk membawa hasil review offline ke tim, gunakan perintah ini di host.

    python -m ctf_toolkit team --dir .\team-data import .\exhibit-bag --owner lead
    python -m ctf_toolkit team --dir .\team-data merge CASE_ID .\review-return --actor lead
    python -m ctf_toolkit team --dir .\team-data pack CASE_ID --out .\review-copy --with-files

Ubah akun dan ID sesuai hasil impor. Perintah host menggunakan izin penyimpanan sistem operasi. Tampilkan konflik merge dari tab **Notes** di browser.

## Ukur perilaku klasifikasi

    python scripts/case_benchmark.py --engine legacy
    python scripts/case_benchmark.py --engine v5

Kedua proses menggunakan korpus sintetis yang sama dengan 36 masukan. Skor exact mengharuskan tipe biner terkonfirmasi dan kandidat encoding sesuai label fixture. p95 menghitung waktu analisis per fixture. Peak RSS mencakup interpreter dan impor paket.
