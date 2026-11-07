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


def ook_to_brainfuck(source: str) -> str:
    """Translate Ook! source code into equivalent Brainfuck syntax."""
    tokens = re.findall(r"Ook[\.\?\!]", source)
    if len(tokens) % 2 != 0:
        raise ValueError("Ook! source must contain an even number of tokens")

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


def ook_eval(source: str, input_str: str = "", max_steps: int = 5_000_000) -> str:
    """Interpret and execute Ook! source code directly."""
    bf_code = ook_to_brainfuck(source)
    return brainfuck_eval(bf_code, input_str=input_str, max_steps=max_steps)
