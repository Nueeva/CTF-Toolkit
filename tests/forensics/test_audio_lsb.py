import io
import wave
import numpy as np
from ctf_toolkit.forensics.audio_tools import extract_audio_pcm_lsb


def test_extract_audio_pcm_lsb() -> None:
    secret = b"GETSFLAG{test_audio_lsb}"
    bits = [int(b) for byte in secret for b in f"{byte:08b}"]
    total_samples = len(bits) + 32

    # Create synthetic samples with LSB matching bits
    samples = np.zeros(total_samples, dtype=np.int16)
    for idx, bit in enumerate(bits):
        samples[idx] = (samples[idx] & ~1) | bit

    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(8000)
        wf.writeframes(samples.tobytes())

    buf.seek(0)
    recovered = extract_audio_pcm_lsb(buf)
    assert secret in recovered
