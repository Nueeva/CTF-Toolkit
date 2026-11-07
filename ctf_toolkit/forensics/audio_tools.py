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
