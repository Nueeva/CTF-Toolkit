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
