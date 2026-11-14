"""Return-Oriented Programming (ROP) and Sigreturn (SROP) frame builders."""

from __future__ import annotations

import struct
from typing import Any
from ctf_toolkit.binex.pwn_tools import build_rop_chain

__all__ = ["build_rop_chain", "SigreturnFrameX86_64", "build_sigreturn_frame_x86_64"]


class SigreturnFrameX86_64:
    """Linux x86_64 sigcontext / ucontext structure for sys_rt_sigreturn (syscall 15).

    When a signal returns, the kernel restores CPU state from this stack frame.
    By forging this frame and invoking syscall 15 (e.g. via pop rax; ret with 15),
    an attacker can set all general-purpose registers (rax, rdi, rsi, rdx, rsp, rip)
    simultaneously in single-gadget environments.
    """

    def __init__(self) -> None:
        self.regs: dict[str, int] = {
            "r8": 0, "r9": 0, "r10": 0, "r11": 0,
            "r12": 0, "r13": 0, "r14": 0, "r15": 0,
            "rdi": 0, "rsi": 0, "rbp": 0, "rbx": 0,
            "rdx": 0, "rax": 0, "rcx": 0, "rsp": 0,
            "rip": 0, "eflags": 0x246, "cs": 0x33, "gs": 0, "fs": 0,
        }

    def set(self, reg: str, val: int) -> None:
        low = reg.lower()
        if low not in self.regs:
            raise KeyError(f"Unknown register {reg!r}; available: {list(self.regs.keys())}")
        self.regs[low] = val

    def build(self) -> bytes:
        frame = bytearray(0x100)  # 256 bytes
        # Offsets matching struct sigcontext on Linux x86_64:
        struct.pack_into("<Q", frame, 0x28, self.regs["r8"])
        struct.pack_into("<Q", frame, 0x30, self.regs["r9"])
        struct.pack_into("<Q", frame, 0x38, self.regs["r10"])
        struct.pack_into("<Q", frame, 0x40, self.regs["r11"])
        struct.pack_into("<Q", frame, 0x48, self.regs["r12"])
        struct.pack_into("<Q", frame, 0x50, self.regs["r13"])
        struct.pack_into("<Q", frame, 0x58, self.regs["r14"])
        struct.pack_into("<Q", frame, 0x60, self.regs["r15"])
        struct.pack_into("<Q", frame, 0x68, self.regs["rdi"])
        struct.pack_into("<Q", frame, 0x70, self.regs["rsi"])
        struct.pack_into("<Q", frame, 0x78, self.regs["rbp"])
        struct.pack_into("<Q", frame, 0x80, self.regs["rbx"])
        struct.pack_into("<Q", frame, 0x88, self.regs["rdx"])
        struct.pack_into("<Q", frame, 0x90, self.regs["rax"])
        struct.pack_into("<Q", frame, 0x98, self.regs["rcx"])
        struct.pack_into("<Q", frame, 0xa0, self.regs["rsp"])
        struct.pack_into("<Q", frame, 0xa8, self.regs["rip"])
        struct.pack_into("<Q", frame, 0xb0, self.regs["eflags"])
        struct.pack_into("<H", frame, 0xb8, self.regs["cs"])
        struct.pack_into("<H", frame, 0xba, self.regs["gs"])
        struct.pack_into("<H", frame, 0xbc, self.regs["fs"])
        return bytes(frame)


def build_sigreturn_frame_x86_64(
    rax: int = 59,
    rdi: int = 0,
    rsi: int = 0,
    rdx: int = 0,
    rsp: int = 0,
    rip: int = 0,
    **extra_regs: Any,
) -> bytes:
    """Build a complete 256-byte Linux x86_64 sigreturn frame.

    Defaults to sys_execve (rax=59). Specify registers as keyword arguments.
    """
    frame = SigreturnFrameX86_64()
    frame.set("rax", rax)
    frame.set("rdi", rdi)
    frame.set("rsi", rsi)
    frame.set("rdx", rdx)
    frame.set("rsp", rsp)
    frame.set("rip", rip)
    for k, v in extra_regs.items():
        if isinstance(v, int):
            frame.set(k, v)
    return frame.build()
