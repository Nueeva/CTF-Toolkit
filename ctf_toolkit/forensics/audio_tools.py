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

