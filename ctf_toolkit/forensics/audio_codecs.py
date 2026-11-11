"""
Slot-aligned audio symbol recovery.

Tone bursts in CTF audio payloads are usually emitted on a fixed clock. Rather
than trusting run-length splitting (which duplicates symbols at amplitude
dips), every burst is assigned to a slot index derived from the median burst
period. That makes the nibble / digit / bit streams immune to boundary noise.
"""
from __future__ import annotations

import io
import math
import wave

import numpy as np

PRINTABLE = set(range(32, 127))


def load_wav(source):
    if isinstance(source, (bytes, bytearray)):
        wf = wave.open(io.BytesIO(source), "rb")
    elif isinstance(source, io.BytesIO):
        wf = wave.open(source, "rb")
    else:
        wf = wave.open(str(source), "rb")
    with wf:
        rate = wf.getframerate()
        width = wf.getsampwidth()
        ch = wf.getnchannels()
        frames = wf.readframes(wf.getnframes())
    if width == 1:
        s = np.frombuffer(frames, dtype=np.uint8).astype(np.float64) - 128.0
    elif width == 2:
        s = np.frombuffer(frames, dtype=np.int16).astype(np.float64)
    else:
        s = np.frombuffer(frames, dtype=np.int32).astype(np.float64)
    if ch > 1:
        s = s.reshape(-1, ch)[:, 0]
    return s, rate


def peak_freq(seg: np.ndarray, rate: int, pad: int = 8) -> float:
    if len(seg) < 32:
        return 0.0
    w = seg * np.hanning(len(seg))
    n = len(w) * pad
    sp = np.abs(np.fft.rfft(w, n))
    fr = np.fft.rfftfreq(n, 1.0 / rate)
    sp[:2] = 0
    return float(fr[int(np.argmax(sp))])


def bursts(samples: np.ndarray, rate: int, ratio: float = 0.35):
    """Detect tone bursts: list of (start_sample, length, peak_hz)."""
    win = max(1, int(rate * 0.002))
    env = np.convolve(np.abs(samples), np.ones(win) / win, mode="same")
    if env.max() <= 0:
        return []
    on = env > env.max() * ratio
    out = []
    cur, cnt, start = bool(on[0]), 0, 0
    bounds = []
    for i, v in enumerate(on):
        if bool(v) == cur:
            cnt += 1
        else:
            bounds.append((cur, start, cnt))
            cur, cnt, start = bool(v), 1, i
    bounds.append((cur, start, cnt))
    for is_on, st, ln in bounds:
        if is_on and ln > win * 3:
            out.append((st, ln, peak_freq(samples[st:st + ln], rate)))
    return out


def slot_freqs(samples: np.ndarray, rate: int, ratio: float = 0.35):
    """Collapse bursts onto a fixed symbol clock; return ordered slot frequencies."""
    b = bursts(samples, rate, ratio)
    if len(b) < 3:
        return [], 0
    starts = [x[0] for x in b]
    diffs = sorted(starts[i + 1] - starts[i] for i in range(len(starts) - 1))
    period = diffs[len(diffs) // 2]
    if period <= 0:
        return [x[2] for x in b], 1
    slots = {}
    for st, ln, f in b:
        k = int(round((st - starts[0]) / period))
        slots[k] = f
    return [slots[k] for k in sorted(slots)], period


def _bits_to_bytes(bits, inverted=False):
    b = [1 - x for x in bits] if inverted else bits
    usable = len(b) - (len(b) % 8)
    out = bytearray()
    for i in range(0, usable, 8):
        v = 0
        for k in range(8):
            v = (v << 1) | b[i + k]
        out.append(v)
    return bytes(out)


def _text_score(text: str) -> float:
    if not text:
        return -1
    alpha = sum(ch.isalpha() for ch in text) / len(text)
    printable = sum(ch in PRINTABLE or ch in "\n\r\t" for ch in text) / len(text)
    score = alpha * 6 + printable * 3
    if "GETSFLAG{" in text.upper():
        score += 30
    if any(t in text.upper() for t in ("FLAG", "CTF{")):
        score += 8
    return score


def decode_ascii_ladder(samples: np.ndarray, rate: int) -> str:
    """One tone per character: f = base + step * ord(ch)."""
    freqs, _ = slot_freqs(samples, rate)
    if len(freqs) < 5:
        return ""
    best, best_score = "", 0.0
    for step in np.arange(2.0, 30.0, 0.25):
        for base in np.arange(100.0, 600.0, 2.5):
            codes = [int(round((f - base) / step)) for f in freqs]
            good = [c for c in codes if c in PRINTABLE]
            if len(good) < len(codes) * 0.85:
                continue
            text = "".join(chr(c) for c in good)
            score = _text_score(text)
            if score > best_score:
                best_score, best = score, text
    return best if best_score >= 9 else ""


def decode_continuous_fsk(source, rate: int = 0, step_sec: float = 0.01):
    """Quantise frequency over a gapless FSK carrier into a symbol stream.

    Continuous modem-style payloads never drop to silence, so burst detection
    sees one long tone. Sample the dominant frequency on a fixed grid, collapse
    runs, then rescale run lengths onto the shortest observed symbol period.
    """
    samples = source
    win = max(32, int(rate * step_sec))
    prof = []
    for i in range(0, len(samples) - win, win):
        prof.append(peak_freq(samples[i:i + win], rate))
    if not prof:
        return [], 0
    # cluster profile into discrete levels
    centers = []
    for lo, hi in _cluster_ranges(sorted(prof), 60):
        centers.append((lo + hi) / 2.0)
    q = [min(range(len(centers)), key=lambda i: abs(f - centers[i])) for f in prof]
    runs = []
    cur, cnt = q[0], 0
    for v in q:
        if v == cur:
            cnt += 1
        else:
            runs.append((cur, cnt)); cur, cnt = v, 1
    runs.append((cur, cnt))
    lengths = sorted(c for _v, c in runs)
    unit = max(1, lengths[0])
    seq = []
    for v, c in runs:
        seq.extend([v] * max(1, int(round(c / unit))))
    return seq, len(centers)


def decode_continuous_fsk_text(source, rate: int = 0) -> str:
    seq, levels = decode_continuous_fsk(source, rate)
    if len(seq) < 16 or levels < 2:
        return ""
    best, best_score = "", 0.0
    if levels == 2:
        for inv in (False, True):
            bits = [1 - v if inv else v for v in seq]
            text = _bits_to_bytes(bits).decode("latin-1", errors="ignore")
            s = _text_score(text)
            if s > best_score:
                best_score, best = s, text
    else:
        bits_per = max(1, int(math.log2(levels)))
        acc, n, out = 0, 0, bytearray()
        for v in seq:
            acc = (acc << bits_per) | v
            n += bits_per
            if n >= 8:
                out.append((acc >> (n - 8)) & 0xFF)
                n -= 8
        text = bytes(out).decode("latin-1", errors="ignore")
        best_score, best = _text_score(text), text
    return best if best_score >= 9 else ""


def decode_nibble_ladder(samples: np.ndarray, rate: int) -> str:
    """16-level tone ladder -> hex string -> text."""
    freqs, _ = slot_freqs(samples, rate)
    if len(freqs) < 8:
        return ""
    uniq = sorted(freqs)
    lo, hi = uniq[0], uniq[-1]
    if hi - lo < 100:
        return ""
    best, best_score = "", 0.0
    for levels in (16, 8, 4):
        step = (hi - lo) / (levels - 1)
        idx = [max(0, min(levels - 1, int(round((f - lo) / step)))) for f in freqs]
        if levels == 16:
            hexs = "".join(f"{i:x}" for i in idx)
            if len(hexs) % 2:
                hexs = hexs[:-1]
            try:
                text = bytes.fromhex(hexs).decode("latin-1")
            except ValueError:
                continue
        else:
            bits_per = int(math.log2(levels))
            acc, n, out = 0, 0, bytearray()
            for i in idx:
                acc = (acc << bits_per) | i
                n += bits_per
                if n >= 8:
                    out.append((acc >> (n - 8)) & 0xFF)
                    n -= 8
            text = bytes(out).decode("latin-1", errors="ignore")
        score = _text_score(text)
        if score > best_score:
            best_score, best = score, text
    return best if best_score >= 9 else ""


ROW = {697: 0, 770: 1, 852: 2, 941: 3}
COL = {1209: 0, 1336: 1, 1477: 2, 1633: 3}
KEYPAD = [["1", "2", "3", "A"], ["4", "5", "6", "B"],
          ["7", "8", "9", "C"], ["*", "0", "#", "D"]]


def _goertzel(seg: np.ndarray, freq: float, rate: int) -> float:
    t = np.arange(len(seg)) / rate
    return float(abs(np.sum(seg * np.exp(-2j * np.pi * freq * t))) ** 2)


def decode_dtmf_digits(samples: np.ndarray, rate: int, ratio: float = 0.35) -> str:
    """Dual-tone keypad digits, one digit per burst via row+column correlation."""
    b = bursts(samples, rate, ratio)
    digits = []
    for st, ln, _f in b:
        seg = samples[st:st + ln]
        if len(seg) < 64:
            continue
        rp = [_goertzel(seg, f, rate) for f in ROW]
        cp = [_goertzel(seg, f, rate) for f in COL]
        digits.append(KEYPAD[int(np.argmax(rp))][int(np.argmax(cp))])
    return "".join(digits)


_HEXMAP = {"#": "f", "*": "e", "A": "a", "B": "b", "C": "c", "D": "d"}


def digits_to_text(digits: str) -> str:
    """Try the digit stream as decimal triplets, then as hex pairs."""
    cands = []
    clean = "".join(ch for ch in digits if ch.isdigit() or ch in _HEXMAP)
    # decimal triplets: trim to whole groups, drop trailing null padding
    tri = "".join(ch for ch in clean if ch.isdigit())
    tri = tri.rstrip("0")
    if len(tri) % 3:
        tri = tri[: len(tri) - (len(tri) % 3)]
    if len(tri) >= 6:
        chars = []
        ok = True
        for i in range(0, len(tri), 3):
            v = int(tri[i:i + 3])
            if v not in PRINTABLE:
                ok = False
                break
            chars.append(chr(v))
        if ok:
            cands.append("".join(chars))
    # hex pairs, with keypad letters folded in
    hexs = "".join(_HEXMAP.get(ch, ch) for ch in clean)
    if len(hexs) % 2:
        hexs = hexs[:-1]
    try:
        cands.append(bytes.fromhex(hexs).decode("latin-1"))
    except ValueError:
        pass
    # hex pairs, skipping non-hex glyphs entirely
    hexs2 = "".join(ch for ch in clean if ch in "0123456789abcdefABCDEF")
    if len(hexs2) % 2:
        hexs2 = hexs2[:-1]
    try:
        cands.append(bytes.fromhex(hexs2).decode("latin-1"))
    except ValueError:
        pass
    best, best_score = "", -1
    for c in cands:
        s = _text_score(c)
        if s > best_score:
            best_score, best = s, c
    return best if best_score >= 6 else ""


def decode_fsk_binary(samples: np.ndarray, rate: int, ratio: float = 0.35) -> str:
    """Two-level FSK: symbol frequency > midpoint -> 1, else 0."""
    freqs, _ = slot_freqs(samples, rate, ratio)
    if len(freqs) < 16:
        return ""
    lo, hi = min(freqs), max(freqs)
    if hi - lo < 80:
        return ""
    mid = (lo + hi) / 2.0
    bits = [1 if f > mid else 0 for f in freqs]
    best, best_score = "", 0.0
    for inv in (False, True):
        raw = _bits_to_bytes(bits, inverted=inv)
        text = raw.decode("latin-1", errors="ignore")
        s = _text_score(text)
        if s > best_score:
            best_score, best = s, text
    return best if best_score >= 9 else ""


def decode_mfsk(samples: np.ndarray, rate: int, ratio: float = 0.35) -> str:
    """4/8-level FSK: rank levels, pack bits, recover bytes."""
    freqs, _ = slot_freqs(samples, rate, ratio)
    if len(freqs) < 8:
        return ""
    uniq = []
    for f in sorted(freqs):
        if not uniq or f - uniq[-1] > 60:
            uniq.append(f)
    levels = len(uniq)
    if levels < 2:
        return ""
    centers = []
    for lo, hi in _cluster_ranges(sorted(freqs), 60):
        centers.append((lo + hi) / 2.0)
    levels = len(centers)
    bits_per = max(1, int(math.log2(levels))) if levels > 1 else 1
    idx = [min(range(levels), key=lambda i: abs(f - centers[i])) for f in freqs]
    best, best_score = "", 0.0
    for shift in range(bits_per):
        acc, n, out = 0, 0, bytearray()
        for i in idx:
            acc = (acc << bits_per) | i
            n += bits_per
            if n >= 8:
                out.append((acc >> (n - 8)) & 0xFF)
                n -= 8
        text = bytes(out).decode("latin-1", errors="ignore")
        s = _text_score(text)
        if s > best_score:
            best_score, best = s, text
    return best if best_score >= 9 else ""


def _cluster_ranges(vals, gap):
    groups = [[vals[0]]]
    for v in vals[1:]:
        if v - groups[-1][-1] > gap:
            groups.append([v])
        else:
            groups[-1].append(v)
    return [(g[0], g[-1]) for g in groups]


MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", "..--..": "?", "-..-.": "/", "-....-": "-",
    ".-.-.-": ".", "--..--": ",", ".----.": "'", "-...-": "=",
}


def decode_morse(samples: np.ndarray, rate: int, ratio: float = 0.35) -> str:
    win = max(1, int(rate * 0.002))
    env = np.convolve(np.abs(samples), np.ones(win) / win, mode="same")
    if env.max() <= 0:
        return ""
    on = env > env.max() * ratio
    runs = []
    cur, cnt, start = bool(on[0]), 0, 0
    for i, v in enumerate(on):
        if bool(v) == cur:
            cnt += 1
        else:
            runs.append((cur, cnt))
            cur, cnt = bool(v), 1
    runs.append((cur, cnt))
    ons = sorted(c for s, c in runs if s)
    if not ons:
        return ""
    dit = ons[0] if len(ons) < 4 else ons[len(ons) // 4]
    dah = dit * 2.0
    gap_c = dit * 2.5
    gap_w = dit * 5.0
    tokens, cur = [], []
    for s, length in runs:
        if s:
            if length < win:
                continue
            cur.append("-" if length >= dah else ".")
        else:
            if length >= gap_w:
                if cur:
                    tokens.append("".join(cur)); cur = []
                tokens.append("/")
            elif length >= gap_c:
                if cur:
                    tokens.append("".join(cur)); cur = []
    if cur:
        tokens.append("".join(cur))
    text = "".join(" " if t == "/" else MORSE.get(t, "") for t in tokens).strip()
    # a hex-only body means the message was hex-encoded
    if text and len(text) % 2 == 0 and all(c in "0123456789ABCDEF" for c in text.replace(" ", "")):
        try:
            return bytes.fromhex(text.replace(" ", "")).decode("latin-1")
        except ValueError:
            pass
    return text


def auto_decode(samples: np.ndarray, rate: int) -> dict:
    out = {}
    for name, fn in (
        ("morse", decode_morse),
        ("dtmf", lambda s, r: digits_to_text(decode_dtmf_digits(s, r))),
        ("ascii_ladder", decode_ascii_ladder),
        ("nibble_ladder", decode_nibble_ladder),
        ("fsk_binary", decode_fsk_binary),
        ("mfsk", decode_mfsk),
        ("fsk_continuous", decode_continuous_fsk_text),
    ):
        try:
            v = fn(samples, rate)
            if v:
                out[name] = v
        except Exception as e:
            out[name + "_err"] = str(e)[:70]
    return out