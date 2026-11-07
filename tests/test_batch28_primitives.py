from __future__ import annotations

import io
import wave
import numpy as np

from ctf_toolkit.crypto.classical import t9_decode
from ctf_toolkit.forensics.audio_tools import dtmf_digits_to_ascii, demodulate_audio_fsk
from ctf_toolkit.osint_misc.config_hunter import parse_properties, parse_markdown_table


def test_t9_decode():
    # '8 33 999 66 444 66 33 8 33 99 8' -> 'teyninetext'
    assert t9_decode("8 33 999 66 444 66 33 8 33 99 8") == "teyninetext"
    # '44 33 555 555 666' -> 'hello'
    assert t9_decode("44 33 555 555 666") == "hello"


def test_dtmf_digits_to_ascii():
    # 071 069 084 -> GET
    assert dtmf_digits_to_ascii("071 069 084") == "GET"
    assert dtmf_digits_to_ascii("071069084") == "GET"


def test_demodulate_audio_fsk():
    # Synthesize test FSK audio for "FLAG"
    # Freq0 = 1000 Hz, Freq1 = 1800 Hz, baud = 50 (20ms/bit)
    rate = 8000
    baud = 50.0
    spb = int(rate / baud)
    message = b"FLAG"
    
    bits = []
    for byte in message:
        for b in range(8):
            bits.append((byte >> (7 - b)) & 1)
            
    samples_list = []
    t = np.arange(spb) / rate
    for bit in bits:
        f = 1800.0 if bit == 1 else 1000.0
        wave_chunk = (np.sin(2 * np.pi * f * t) * 16000).astype(np.int16)
        samples_list.append(wave_chunk)
        
    full_audio = np.concatenate(samples_list)
    bio = io.BytesIO()
    with wave.open(bio, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(rate)
        wf.writeframes(full_audio.tobytes())
        
    bio.seek(0)
    recovered = demodulate_audio_fsk(bio, freq_0=1000.0, freq_1=1800.0, baud_rate=baud, msb_first=True)
    assert recovered == b"FLAG"


def test_parse_properties():
    content = """
# Application properties
app.name = TestApp
app.version: 1.0.0
! Secret token
app.secret = secret123
"""
    props = parse_properties(content)
    assert props["app.name"] == "TestApp"
    assert props["app.version"] == "1.0.0"
    assert props["app.secret"] == "secret123"


def test_parse_markdown_table():
    md = """
| Parameter | Value | Description |
|:----------|:------|:------------|
| host      | 127.0.0.1 | Localhost |
| port      | 8080      | HTTP Port |
"""
    rows = parse_markdown_table(md)
    assert len(rows) == 2
    assert rows[0]["Parameter"] == "host"
    assert rows[0]["Value"] == "127.0.0.1"
    assert rows[1]["Parameter"] == "port"
    assert rows[1]["Value"] == "8080"
