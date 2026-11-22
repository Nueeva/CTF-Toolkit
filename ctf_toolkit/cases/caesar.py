"""A deterministic, bilingual scoring exercise for classical Caesar text."""

from __future__ import annotations

import math
import re
from collections import Counter
from functools import lru_cache

from ctf_toolkit.crypto.classical import caesar_bruteforce

# Original practice prose used only to establish letter and transition frequencies.
_REFERENCE = {
    "id": (
        "Pada musim hujan penduduk desa menyiapkan saluran air di sepanjang jalan. "
        "Sekolah membuka perpustakaan pada pagi hari dan menutup pintu sebelum petang. "
        "Sebagian warga membawa hasil kebun ke pasar, sementara yang lain memperbaiki sepeda. "
        "Petugas mencatat jumlah barang yang masuk ke gudang dan memeriksa kembali daftar harian. "
        "Anak-anak bermain di halaman sesudah mengerjakan tugas dan membaca cerita pendek. "
        "Ketika angin datang dari laut, nelayan menarik perahu ke tempat yang lebih tenang. "
        "Setiap minggu keluarga berkumpul untuk berbicara tentang pekerjaan dan rencana berikutnya. "
        "Bunga tumbuh di sekitar rumah dengan daun yang lebar dan batang yang hijau. "
        "Mahasiswa menyusun laporan berdasarkan pengamatan, lalu menjelaskan perbedaan hasil kepada dosen. "
        "Pendamping mengingatkan bahwa setiap perubahan harus ditulis dengan alasan yang jelas."
    ),
    "en": (
        "During the rainy season the villagers clear the drains beside the road. "
        "The school opens its library each morning and closes the door before evening. "
        "Some residents bring vegetables to the market while others repair their bicycles. "
        "The clerk counts the boxes arriving at the warehouse and checks the daily list. "
        "Children play outside after finishing their homework and reading a short story. "
        "When the wind comes from the sea the fishermen pull their boats into calmer water. "
        "Every week the family gathers to talk about work and make plans for the following days. "
        "Flowers grow near the house with broad leaves and strong green stems. "
        "Students prepare a report from their observations and explain the differences to the teacher. "
        "A colleague reminds everyone to record each change and give a clear reason."
    ),
}


def _words(text: str) -> list[str]:
    return re.findall("[a-z]+", text.lower())


def _pairs(words: list[str]):
    for word in words:
        marked = "^" + word + "$"
        yield from zip(marked, marked[1:])


@lru_cache(maxsize=2)
def _profile(language: str) -> tuple[Counter, Counter, Counter]:
    words = _words(_REFERENCE[language])
    letters = Counter("".join(words))
    pairs = Counter(_pairs(words))
    starts: Counter = Counter()
    for (first, _), count in pairs.items():
        starts[first] += count
    return letters, pairs, starts


def rank_caesar(text: str, language: str) -> dict:
    if language not in _REFERENCE:
        raise ValueError("Choose the id or en Caesar language profile")
    if len(text) > 16_384:
        raise ValueError("Caesar practice input is limited to 16,384 characters")
    letters, pairs, starts = _profile(language)
    denominator = sum(letters.values()) + 26
    ranked = []
    length = len("".join(_words(text)))
    if not length:
        raise ValueError("Caesar input needs Latin alphabet letters")
    for shift, output in caesar_bruteforce(text):
        words = _words(output)
        letter_score = sum(math.log((letters[char] + 1) / denominator) for char in "".join(words))
        transition_score = sum(math.log((pairs[pair] + 0.25) / (starts[pair[0]] + 6.75))
                               for pair in _pairs(words))
        ranked.append({"shift": shift, "text": output, "score": round((letter_score + transition_score) / length, 6)})
    ranked.sort(key=lambda result: (-result["score"], result["shift"]))
    return {"language": language, "limited_evidence": length < 16, "candidates": ranked[:3],
            "scoring": "Mean smoothed log frequency of letters and adjacent symbols in a language profile"}
