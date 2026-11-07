from __future__ import annotations

MORSE_CODE_DICT: dict[str, str] = {
    "A": ".-",
    "B": "-...",
    "C": "-.-.",
    "D": "-..",
    "E": ".",
    "F": "..-.",
    "G": "--.",
    "H": "....",
    "I": "..",
    "J": ".---",
    "K": "-.-",
    "L": ".-..",
    "M": "--",
    "N": "-.",
    "O": "---",
    "P": ".--.",
    "Q": "--.-",
    "R": ".-.",
    "S": "...",
    "T": "-",
    "U": "..-",
    "V": "...-",
    "W": ".--",
    "X": "-..-",
    "Y": "-.--",
    "Z": "--..",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
    "0": "-----",
    "{": "-.--.",
    "}": "-.--.-",
    "_": "..--.-",
    ".": ".-.-.-",
    ",": "--..--",
    "?": "..--..",
    "/": "-..-.",
    "-": "-....-",
    ":": "---...",
    ";": "-.-.-.",
    "=": "-...-",
    "+": ".-.-.",
}

REVERSE_MORSE: dict[str, str] = {val: key for key, val in MORSE_CODE_DICT.items()}


def morse_decode(morse_text: str) -> str:
    """Decode Morse code string where letters are space-separated and words by '/' or double spaces."""
    cleaned = morse_text.strip()
    words = cleaned.split(" / ") if " / " in cleaned else [cleaned]
    decoded_words: list[str] = []

    for word in words:
        tokens = word.split()
        chars = [REVERSE_MORSE.get(tok, f"[{tok}]") for tok in tokens if tok]
        decoded_words.append("".join(chars))

    return " ".join(decoded_words)


def morse_encode(text: str) -> str:
    """Encode alphanumeric and standard CTF punctuation text into Morse code."""
    words = text.upper().split(" ")
    encoded_words: list[str] = []

    for word in words:
        tokens = [MORSE_CODE_DICT[ch] for ch in word if ch in MORSE_CODE_DICT]
        encoded_words.append(" ".join(tokens))

    return " / ".join(encoded_words)


def fractionated_morse_decode(ciphertext: str) -> str:
    """Decode Fractionated Morse cipher."""
    trigrams = []
    for c1 in [".", "-", "x"]:
        for c2 in [".", "-", "x"]:
            for c3 in [".", "-", "x"]:
                trigrams.append(c1 + c2 + c3)
    frac_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0"
    frac_map = {frac_alpha[i]: trigrams[i] for i in range(27)}

    morse_stream = "".join(frac_map.get(c.upper(), "") for c in ciphertext)
    morse_words = morse_stream.rstrip("x").split("x")
    return "".join(REVERSE_MORSE.get(m, "?") for m in morse_words if m).lower()


def morbit_decode(ciphertext: str) -> str:
    """Decode Morbit cipher."""
    morbit_pairs = []
    for c1 in [".", "-", "x"]:
        for c2 in [".", "-", "x"]:
            morbit_pairs.append(c1 + c2)
    morbit_map = {str(i + 1): morbit_pairs[i] for i in range(9)}

    morse_stream = "".join(morbit_map.get(c, "") for c in ciphertext if c in morbit_map)
    morse_words = morse_stream.rstrip("x").split("x")
    return "".join(REVERSE_MORSE.get(m, "?") for m in morse_words if m).lower()
