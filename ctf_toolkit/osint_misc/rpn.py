from __future__ import annotations


def eval_rpn(expression: str) -> int:
    """Evaluate a Reverse Polish Notation (postfix) arithmetic expression."""
    tokens = expression.strip().split()
    stack: list[int] = []
    for token in tokens:
        if token == "+":
            b = stack.pop()
            a = stack.pop()
            stack.append(a + b)
        elif token == "-":
            b = stack.pop()
            a = stack.pop()
            stack.append(a - b)
        elif token == "*":
            b = stack.pop()
            a = stack.pop()
            stack.append(a * b)
        elif token in ("/", "//"):
            b = stack.pop()
            a = stack.pop()
            stack.append(a // b)
        else:
            stack.append(int(token))
    if not stack:
        raise ValueError("Empty RPN expression")
    return stack[-1]


def eval_rpn_tape(lines: list[str]) -> bytes:
    """Evaluate lines of RPN expressions and convert output values to ASCII bytes."""
    out: list[int] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        val = eval_rpn(line)
        out.append(val & 0xFF)
    return bytes(out)
