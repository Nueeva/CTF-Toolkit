from __future__ import annotations

import re


def brainfuck_eval(source: str, input_str: str = "", max_steps: int = 5_000_000) -> str:
    """Execute Brainfuck code in a bounded, safe virtual machine."""
    clean_src = [c for c in source if c in "><+-.,[]"]
    brackets: dict[int, int] = {}
    stack: list[int] = []

    for i, cmd in enumerate(clean_src):
        if cmd == "[":
            stack.append(i)
        elif cmd == "]":
            if not stack:
                raise ValueError(f"Unmatched closing bracket at index {i}")
            j = stack.pop()
            brackets[j] = i
            brackets[i] = j

    if stack:
        raise ValueError(f"Unmatched opening bracket at index {stack[-1]}")

    mem = [0] * 30000
    ptr = 0
    pc = 0
    steps = 0
    inp_ptr = 0
    output: list[str] = []

    while pc < len(clean_src):
        steps += 1
        if steps > max_steps:
            raise TimeoutError("Execution step limit exceeded (infinite loop protection)")

        cmd = clean_src[pc]
        if cmd == ">":
            ptr = (ptr + 1) % 30000
        elif cmd == "<":
            ptr = (ptr - 1) % 30000
        elif cmd == "+":
            mem[ptr] = (mem[ptr] + 1) & 0xFF
        elif cmd == "-":
            mem[ptr] = (mem[ptr] - 1) & 0xFF
        elif cmd == ".":
            output.append(chr(mem[ptr]))
        elif cmd == ",":
            if inp_ptr < len(input_str):
                mem[ptr] = ord(input_str[inp_ptr]) & 0xFF
                inp_ptr += 1
            else:
                mem[ptr] = 0
        elif cmd == "[" and mem[ptr] == 0:
            pc = brackets[pc]
        elif cmd == "]" and mem[ptr] != 0:
            pc = brackets[pc]

        pc += 1

    return "".join(output)


def ook_to_brainfuck(source: str, variant: str = "standard") -> str:
    """Translate Ook! source code into equivalent Brainfuck syntax (standard or inverted)."""
    tokens = re.findall(r"Ook[\.\?\!]", source)
    if len(tokens) % 2 != 0:
        raise ValueError("Ook! source must contain an even number of tokens")

    if variant == "inverted":
        ook_map = {
            "Ook? Ook.": ">",
            "Ook. Ook?": "<",
            "Ook! Ook!": "+",
            "Ook. Ook.": "-",
            "Ook. Ook!": ".",
            "Ook! Ook.": ",",
            "Ook? Ook!": "[",
            "Ook! Ook?": "]",
        }
    else:
        ook_map = {
            "Ook. Ook?": ">",
            "Ook? Ook.": "<",
            "Ook. Ook.": "+",
            "Ook! Ook!": "-",
            "Ook! Ook.": ".",
            "Ook. Ook!": ",",
            "Ook! Ook?": "[",
            "Ook? Ook!": "]",
        }

    bf: list[str] = []
    for i in range(0, len(tokens), 2):
        pair = f"{tokens[i]} {tokens[i+1]}"
        if pair in ook_map:
            bf.append(ook_map[pair])
    return "".join(bf)


def ook_eval(source: str, input_str: str = "", max_steps: int = 5_000_000, variant: str = "auto") -> str:
    """Interpret and execute Ook! source code directly with auto-variant fallback."""
    if variant in ("standard", "inverted"):
        bf_code = ook_to_brainfuck(source, variant=variant)
        return brainfuck_eval(bf_code, input_str=input_str, max_steps=max_steps)

    bf_code = ook_to_brainfuck(source, variant="standard")
    out = brainfuck_eval(bf_code, input_str=input_str, max_steps=max_steps)
    if out and any(32 <= ord(c) <= 126 for c in out):
        return out

    try:
        bf_inv = ook_to_brainfuck(source, variant="inverted")
        out_inv = brainfuck_eval(bf_inv, input_str=input_str, max_steps=max_steps)
        if out_inv and any(32 <= ord(c) <= 126 for c in out_inv):
            return out_inv
    except Exception:
        pass
    return out


def deadfish_eval(source: str) -> str:
    """Interpret and execute Deadfish esolang source code (i: +1, d: -1, s: ^2, o: out)."""
    val = 0
    out = []
    for c in source:
        if c == "i":
            val += 1
        elif c == "d":
            val -= 1
        elif c == "s":
            val = val * val
        elif c == "o":
            out.append(chr(val) if val < 256 else str(val))
        if val == -1 or val == 256:
            val = 0
    return "".join(out)


def spoon_eval(source: str) -> str:
    """Interpret Spoon esolang bitstream (1: +, 000: -, 001010: output ASCII)."""
    val = 0
    out = []
    i = 0
    while i < len(source):
        if source[i] == "1":
            val = (val + 1) & 0xFF
            i += 1
        elif source[i : i + 6] == "001010":
            out.append(chr(val))
            i += 6
        elif source[i : i + 3] == "000":
            val = (val - 1) & 0xFF
            i += 3
        else:
            i += 1
    return "".join(out)


def whitespace_eval(source: str | bytes) -> str:
    """Interpret Whitespace esolang character stream that pushes and outputs characters."""
    if isinstance(source, bytes):
        text = source.decode("latin1", errors="ignore")
    else:
        text = source

    rep = text.replace(" ", "S").replace("\t", "T").replace("\n", "L")
    tokens = rep
    idx = 0
    output_chars: list[str] = []
    while idx < len(tokens):
        if tokens[idx : idx + 2] == "SS":
            idx += 2
            l_pos = tokens.find("L", idx)
            if l_pos != -1:
                num_str = tokens[idx:l_pos]
                idx = l_pos + 1
                if num_str:
                    sign = 1 if num_str[0] == "S" else -1
                    bits = num_str[1:].replace("S", "0").replace("T", "1")
                    val = int(bits, 2) if bits else 0
                    val = sign * val
                    if tokens[idx : idx + 4] == "TLSS":
                        output_chars.append(chr(val))
                        idx += 4
                    else:
                        output_chars.append(chr(val))
            else:
                break
        else:
            idx += 1
    return "".join(output_chars)


def piet_nibbles_decode(codels: list[tuple[int, int, int]]) -> str:
    """Decode Piet color palette codels (Hue * 3 + Lightness) to 4-bit nibbles and ASCII string."""
    piet_palette: dict[tuple[int, int, int], int] = {
        (255, 192, 192): 0,
        (255, 0, 0): 1,
        (192, 0, 0): 2,
        (255, 255, 192): 3,
        (255, 255, 0): 4,
        (192, 192, 0): 5,
        (192, 255, 192): 6,
        (0, 255, 0): 7,
        (0, 192, 0): 8,
        (192, 255, 255): 9,
        (0, 255, 255): 10,
        (0, 192, 192): 11,
        (192, 192, 255): 12,
        (0, 0, 255): 13,
        (0, 0, 192): 14,
        (255, 255, 255): 15,
    }
    nibbles = [piet_palette[c] for c in codels if c in piet_palette]
    chars = [chr((nibbles[i] << 4) | nibbles[i + 1]) for i in range(0, len(nibbles) - 1, 2)]
    return "".join(chars)


def eval_stack_vm(code: str) -> str:
    """Execute a simple stack-based bytecode program (PUSH, ADD, SUB, MUL, XOR, EMIT)."""
    stack: list[int] = []
    output: list[str] = []
    for line in code.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split()
        op = parts[0].upper()
        if op == "PUSH":
            stack.append(int(parts[1]))
        elif op == "ADD":
            b = stack.pop()
            a = stack.pop()
            stack.append(a + b)
        elif op == "SUB":
            b = stack.pop()
            a = stack.pop()
            stack.append(a - b)
        elif op == "MUL":
            b = stack.pop()
            a = stack.pop()
            stack.append(a * b)
        elif op == "XOR":
            b = stack.pop()
            a = stack.pop()
            stack.append(a ^ b)
        elif op == "EMIT":
            val = stack.pop()
            output.append(chr(val & 0xFF))
    return "".join(output)



def befunge_extract_strings(grid_text: str) -> str:
    """Extract string literals pushed onto the Befunge-93 2D playfield stack (LIFO pop order)."""
    lines = [line.rstrip("\r\n") for line in grid_text.splitlines() if line.strip()]
    if not lines:
        return ""
    quoted = re.findall(r'"([^"]+)"', grid_text)
    if quoted:
        for q in quoted:
            q_up = q.upper()
            rev = q[::-1]
            rev_up = rev.upper()
            if any(k in q_up for k in ("FLAG{", "CT{", "GETSFLAG{", "CTF{")):
                return q
            if any(k in rev_up for k in ("FLAG{", "CT{", "GETSFLAG{", "CTF{")) or (rev.startswith("{") and rev.endswith("}")):
                return rev
        return "".join(q[::-1] for q in quoted)
    return ""


def decode_collatz_ascii(numbers: list[int], offset: int = 32) -> str:
    """
    Convert a list of integers to ASCII characters via their Collatz (3n+1) stopping time
    plus a constant offset (default +32).
    """
    from ctf_toolkit.utils.math import collatz_stopping_time

    return "".join(chr((collatz_stopping_time(n) + offset) & 0xFF) for n in numbers)
