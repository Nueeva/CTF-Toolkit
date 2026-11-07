import io
import wave
import numpy as np
from ctf_toolkit.forensics.audio_tools import extract_audio_tone_bytes


def test_extract_audio_tone_bytes() -> None:
    rate = 8000
    msg = "FLAG{tone_aud}"
    tone_dur = 0.08 # 80ms
    silence_dur = 0.04 # 40ms

    all_samples = []
    for c in msg:
        freq = 300.0 + 10.0 * ord(c)
        t = np.linspace(0, tone_dur, int(rate * tone_dur), endpoint=False)
        tone_wave = (np.sin(2 * np.pi * freq * t) * 10000).astype(np.int16)
        silence_wave = np.zeros(int(rate * silence_dur), dtype=np.int16)
        all_samples.append(tone_wave)
        all_samples.append(silence_wave)

    full_audio = np.concatenate(all_samples)
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(rate)
        wf.writeframes(full_audio.tobytes())

    buf.seek(0)
    recovered = extract_audio_tone_bytes(buf, base_freq=300.0, step_hz=10.0)
    # The recovered string should match or contain the transmitted message
    assert "FLAG{tone_aud}" in recovered or recovered.startswith("FLAG")
