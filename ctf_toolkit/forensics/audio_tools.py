from __future__ import annotations

import io
import wave
import numpy as np


def extract_audio_pcm_lsb(wav_source: str | bytes | io.BytesIO, msb_first: bool = True) -> bytes:
    """
    Extract least significant bit (LSB) stream from PCM WAV audio frames and decode to bytes.
    """
    if isinstance(wav_source, (bytes, bytearray)):
        wf = wave.open(io.BytesIO(wav_source), "rb")
    elif isinstance(wav_source, io.BytesIO):
        wf = wave.open(wav_source, "rb")
    else:
        wf = wave.open(str(wav_source), "rb")

    with wf:
        sampwidth = wf.getsampwidth()
        nframes = wf.getnframes()
        frames = wf.readframes(nframes)

    if sampwidth == 1:
        samples = np.frombuffer(frames, dtype=np.uint8)
    elif sampwidth == 2:
        samples = np.frombuffer(frames, dtype=np.int16)
    else:
        samples = np.frombuffer(frames, dtype=np.int32)

    lsb = samples & 1
    total_bits = len(lsb)
    usable_bits = total_bits - (total_bits % 8)

    byte_arr = bytearray()
    for i in range(0, usable_bits, 8):
        byte_val = 0
        if msb_first:
            for b in range(8):
                byte_val = (byte_val << 1) | int(lsb[i + b])
        else:
            for b in range(8):
                byte_val |= (int(lsb[i + b]) << b)
        byte_arr.append(byte_val)

    return bytes(byte_arr)

def extract_audio_tone_bytes(
    wav_source: str | bytes | io.BytesIO,
    base_freq: float = 300.0,
    step_hz: float = 10.0,
    min_beep_dur: float = 0.02,
) -> str:
    """
    Segment audio tone pulses using amplitude envelope convolution,
    extract the dominant peak frequency of each pulse, and decode transmitted
    ASCII bytes via linear frequency mapping: freq = base_freq + step_hz * ord(c).
    """
    if isinstance(wav_source, (bytes, bytearray)):
        wf = wave.open(io.BytesIO(wav_source), "rb")
    elif isinstance(wav_source, io.BytesIO):
        wf = wave.open(wav_source, "rb")
    else:
        wf = wave.open(str(wav_source), "rb")

    with wf:
        rate = wf.getframerate()
        frames = wf.readframes(wf.getnframes())

    samples = np.frombuffer(frames, dtype=np.int16)
    abs_samples = np.abs(samples)

    win = max(1, int(rate * 0.01))
    envelope = np.convolve(abs_samples, np.ones(win) / win, mode="same")
    threshold = float(np.max(envelope) * 0.25)
    is_beep = envelope > threshold

    beep_segments: list[tuple[int, int]] = []
    in_beep = False
    start_idx = 0

    for i, b in enumerate(is_beep):
        if b and not in_beep:
            in_beep = True
            start_idx = i
        elif not b and in_beep:
            in_beep = False
            if (i - start_idx) / rate >= min_beep_dur:
                beep_segments.append((start_idx, i))

    if in_beep and (len(is_beep) - start_idx) / rate >= min_beep_dur:
        beep_segments.append((start_idx, len(is_beep)))

    recovered_chars: list[str] = []
    for st, en in beep_segments:
        seg = samples[st:en]
        if len(seg) < 20:
            continue
        fft = np.abs(np.fft.rfft(seg))
        freqs = np.fft.rfftfreq(len(seg), 1.0 / rate)
        peak_idx = np.argmax(fft[1:]) + 1
        peak_f = float(freqs[peak_idx])

        code = round((peak_f - base_freq) / step_hz)
        if 32 <= code <= 126:
            recovered_chars.append(chr(code))

    return "".join(recovered_chars)

def dtmf_digits_to_ascii(digits: str) -> str:
    """
    Convert a string of DTMF dialed digits into ASCII characters.
    Handles space-separated or concatenated 3-digit decimal ASCII values (e.g., '071 069 084' -> 'GET').
    """
    # Remove non-digits
    clean = "".join(ch for ch in digits if ch.isdigit())
    if len(clean) % 3 != 0:
        # Try space-split if not clean multiple of 3
        parts = digits.split()
        chars = []
        for p in parts:
            p_clean = "".join(ch for ch in p if ch.isdigit())
            if p_clean:
                v = int(p_clean)
                if 0 <= v <= 255:
                    chars.append(chr(v))
        return "".join(chars)

    chars = []
    for i in range(0, len(clean), 3):
        v = int(clean[i : i + 3])
        if 0 <= v <= 255:
            chars.append(chr(v))
    return "".join(chars)


def demodulate_audio_fsk(
    wav_source: str | bytes | io.BytesIO,
    freq_0: float = 1000.0,
    freq_1: float = 1800.0,
    baud_rate: float = 25.0,
    msb_first: bool = True,
) -> bytes:
    """
    Demodulate a binary Frequency Shift Keying (FSK) audio signal into bytes using correlation.
    """
    if isinstance(wav_source, (bytes, bytearray)):
        wf = wave.open(io.BytesIO(wav_source), "rb")
    elif isinstance(wav_source, io.BytesIO):
        wf = wave.open(wav_source, "rb")
    else:
        wf = wave.open(str(wav_source), "rb")

    with wf:
        rate = wf.getframerate()
        frames = wf.readframes(wf.getnframes())

    samples = np.frombuffer(frames, dtype=np.int16)
    samples_per_bit = max(1, int(rate / baud_rate))

    t = np.arange(samples_per_bit) / rate
    cos_0 = np.cos(2 * np.pi * freq_0 * t)
    sin_0 = np.sin(2 * np.pi * freq_0 * t)
    cos_1 = np.cos(2 * np.pi * freq_1 * t)
    sin_1 = np.sin(2 * np.pi * freq_1 * t)

    bits: list[int] = []
    for i in range(0, len(samples) - samples_per_bit + 1, samples_per_bit):
        chunk = samples[i : i + samples_per_bit]
        p0 = float(np.dot(chunk, cos_0) ** 2 + np.dot(chunk, sin_0) ** 2)
        p1 = float(np.dot(chunk, cos_1) ** 2 + np.dot(chunk, sin_1) ** 2)
        bits.append(1 if p1 > p0 else 0)

    usable_bits = len(bits) - (len(bits) % 8)
    byte_arr = bytearray()
    for i in range(0, usable_bits, 8):
        byte_val = 0
        if msb_first:
            for b in range(8):
                byte_val = (byte_val << 1) | bits[i + b]
        else:
            for b in range(8):
                byte_val |= bits[i + b] << b
        byte_arr.append(byte_val)

    return bytes(byte_arr)



def decode_mfsk(
    samples: np.ndarray,
    rate: int,
    tone_frequencies: list[float],
    symbol_samples: int,
) -> bytes:
    """Demodulate M-ary Frequency Shift Keying (M-FSK) audio signal into bytes."""
    num_symbols = len(samples) // symbol_samples
    symbols: list[int] = []
    for i in range(num_symbols):
        chunk = samples[i * symbol_samples : (i + 1) * symbol_samples]
        fft_vals = np.abs(np.fft.rfft(chunk))
        fft_freqs = np.fft.rfftfreq(len(chunk), 1.0 / rate)
        peak = fft_freqs[np.argmax(fft_vals)]
        best_sym = int(np.argmin([abs(peak - f) for f in tone_frequencies]))
        symbols.append(best_sym)

    M = len(tone_frequencies)
    bits_per_symbol = int(np.log2(M))
    symbols_per_byte = 8 // bits_per_symbol

    result = bytearray()
    for i in range(0, len(symbols) - symbols_per_byte + 1, symbols_per_byte):
        val = 0
        for b in range(symbols_per_byte):
            val = (val << bits_per_symbol) | symbols[i + b]
        result.append(val)
    return bytes(result)


def decode_16fsk_nibbles(
    samples: np.ndarray,
    rate: int,
    base_freq: float = 400.0,
    step_freq: float = 120.0,
    chunk_samples: int = 800,
) -> str:
    """Decode 16-FSK ladder audio into hex string and ASCII plaintext."""
    num_chunks = len(samples) // chunk_samples
    nibbles: list[str] = []
    for i in range(num_chunks):
        chunk = samples[i * chunk_samples : (i + 1) * chunk_samples]
        fft_vals = np.abs(np.fft.rfft(chunk * np.hanning(len(chunk))))
        peak = np.fft.rfftfreq(len(chunk), 1.0 / rate)[np.argmax(fft_vals)]
        k = max(0, min(15, int(round((peak - base_freq) / step_freq))))
        nibbles.append(f"{k:x}")

    hex_str = "".join(nibbles)
    if len(hex_str) % 2 != 0:
        hex_str = hex_str[:-1]
    try:
        return bytes.fromhex(hex_str).decode("latin-1", errors="ignore")
    except Exception:
        return hex_str


def decode_dtmf_tones(
    samples: np.ndarray,
    rate: int,
    period_samples: int = 880,
    tone_active_samples: int = 550,
) -> str:
    """Decode standard DTMF dual-frequency touch-tone keypad bursts."""
    dtmf_rows = [697, 770, 852, 941]
    dtmf_cols = [1209, 1336, 1477, 1633]
    keypad = {
        (697, 1209): "1", (697, 1336): "2", (697, 1477): "3", (697, 1633): "A",
        (770, 1209): "4", (770, 1336): "5", (770, 1477): "6", (770, 1633): "B",
        (852, 1209): "7", (852, 1336): "8", (852, 1477): "9", (852, 1633): "C",
        (941, 1209): "*", (941, 1336): "0", (941, 1477): "#", (941, 1633): "D",
    }

    num_tones = len(samples) // period_samples
    keys: list[str] = []
    for i in range(num_tones):
        chunk = samples[i * period_samples : i * period_samples + tone_active_samples]
        rp = [np.sum(chunk * np.sin(2 * np.pi * f * np.arange(len(chunk)) / rate))**2 + np.sum(chunk * np.cos(2 * np.pi * f * np.arange(len(chunk)) / rate))**2 for f in dtmf_rows]
        cp = [np.sum(chunk * np.sin(2 * np.pi * f * np.arange(len(chunk)) / rate))**2 + np.sum(chunk * np.cos(2 * np.pi * f * np.arange(len(chunk)) / rate))**2 for f in dtmf_cols]
        r = dtmf_rows[np.argmax(rp)]
        c = dtmf_cols[np.argmax(cp)]
        keys.append(keypad[(r, c)])
    return "".join(keys)


def decode_dual_band_fsk(
    samples: np.ndarray,
    rate: int,
    symbol_samples: int = 880,
    low_base: float = 500.0,
    low_step: float = 100.0,
    high_base: float = 2200.0,
    high_step: float = 100.0,
) -> bytes:
    """
    Decode dual-band FSK audio signal where low band encodes the high nibble
    and high band encodes the low nibble of each transmitted byte.
    """
    num_symbols = len(samples) // symbol_samples
    out = bytearray()
    for i in range(num_symbols):
        chunk = samples[i * symbol_samples : (i + 1) * symbol_samples]
        fft_vals = np.abs(np.fft.rfft(chunk * np.hanning(len(chunk))))
        freqs = np.fft.rfftfreq(len(chunk), 1.0 / rate)

        low_mask = (freqs >= 300) & (freqs <= 1800)
        low_peak = freqs[low_mask][np.argmax(fft_vals[low_mask])]
        high_nibble = max(0, min(15, int(round((low_peak - low_base) / low_step))))

        high_mask = (freqs >= 1900) & (freqs <= 4000)
        high_peak = freqs[high_mask][np.argmax(fft_vals[high_mask])]
        low_nibble = max(0, min(15, int(round((high_peak - high_base) / high_step))))

        out.append((high_nibble << 4) | low_nibble)
    return bytes(out)



def decode_audio_cw_morse(
    wav_source: str | bytes | io.BytesIO,
    carrier_hz: float = 700.0,
    threshold_ratio: float = 0.3,
) -> str:
    """
    Demodulate a Continuous Wave (CW) Morse code audio WAV file into decoded plaintext.
    Measures envelope on/off durations to classify dits (.), dahs (-), letter spaces, and word spaces.
    """
    from ctf_toolkit.crypto.morse import morse_decode

    if isinstance(wav_source, (bytes, bytearray)):
        wf = wave.open(io.BytesIO(wav_source), "rb")
    elif isinstance(wav_source, io.BytesIO):
        wf = wave.open(wav_source, "rb")
    else:
        wf = wave.open(str(wav_source), "rb")

    with wf:
        rate = wf.getframerate()
        frames = wf.readframes(wf.getnframes())

    samples = np.frombuffer(frames, dtype=np.int16).astype(np.float64)
    win = max(1, int(rate * 0.005))
    envelope = np.convolve(np.abs(samples), np.ones(win) / win, mode="same")
    thresh = float(np.max(envelope) * threshold_ratio)
    active = envelope > thresh

    runs: list[tuple[bool, int]] = []
    if len(active) == 0:
        return ""
    curr_state = bool(active[0])
    start = 0
    for i, val in enumerate(active):
        if bool(val) != curr_state:
            runs.append((curr_state, i - start))
            curr_state = bool(val)
            start = i
    runs.append((curr_state, len(active) - start))

    on_lengths = [dur for state, dur in runs if state and dur > win]
    if not on_lengths:
        return ""
    dit_len = float(min(on_lengths))
    dah_thresh = dit_len * 2.0

    morse_tokens: list[str] = []
    curr_char: list[str] = []
    for state, dur in runs:
        if state:
            if dur < win:
                continue
            curr_char.append("-" if dur >= dah_thresh else ".")
        else:
            if dur >= dit_len * 5.0:
                if curr_char:
                    morse_tokens.append("".join(curr_char))
                    curr_char = []
                morse_tokens.append("/")
            elif dur >= dit_len * 2.0:
                if curr_char:
                    morse_tokens.append("".join(curr_char))
                    curr_char = []
    if curr_char:
        morse_tokens.append("".join(curr_char))

    morse_str = " ".join(morse_tokens)
    return morse_decode(morse_str)
