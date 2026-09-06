#!/usr/bin/env python3
"""M9 - Shellcode Encoder

A real encoder/decoder toolkit for x86-64:

  * single-byte XOR encode/decode
  * repeating-key (multi-byte) XOR encode/decode
  * XOR key finder (single-byte brute force against a known plaintext, or
    printable-ASCII heuristic)
  * reversible alphanumeric transform (62-char alphabet, 2 output chars/byte)
  * a REAL machine-code decoder stub (x86-64) used to decode a buffer in place
  * decode-and-execute of a benign 0x90 NOP sled + INT3 in an ISOLATED
    subprocess via a hand-built minimal static ELF (self-decoding blob)

Fully offline, stdlib-only. The only payload ever "executed" is a run of NOP
(0x90) instructions terminated by an INT3 (0xCC) breakpoint - a well-known safe
probe that proves the decode-then-execute path works without performing any
action on the host. Execution happens in temporary directories only.

Usage:
    python3 shellcode.py demo
    python3 shellcode.py encode <hex|file> [--key K] [--multi N] [--alpha]
    python3 shellcode.py decode <hex|file> [--key K]
    python3 shellcode.py findkey <file|hex> [--plaintext HEX]
    python3 shellcode.py verify <encoded-hex> [--key K]
"""

import argparse
import binascii
import json
import os
import random
import struct
import subprocess
import sys
import tempfile


X86_64 = (sys.platform == "linux" and
          (os.uname().machine in ("x86_64", "amd64")))


ALNUM_ALPHABET = (
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
)


class ShellcodeEncoder:
    """Encoder/decoder toolkit. stdlib only."""

    def __init__(self, arch="x64", seed=None, key=None):
        if arch not in ("x86", "x64"):
            raise ValueError("arch must be x86 or x64")
        self.arch = arch
        rnd = random.Random(seed)
        if key is None:
            key = rnd.randrange(1, 256)
        self.key = key % 256

    # -- XOR encode / decode -------------------------------------------
    def xor_encode(self, data, key=None):
        key = self.key if key is None else key % 256
        return bytes(b ^ key for b in data), key

    def xor_decode(self, data, key):
        key = key % 256
        return bytes(b ^ key for b in data)

    def xor_multi_encode(self, data, keys):
        keys = [k % 256 for k in keys]
        n = len(keys)
        return bytes(b ^ keys[i % n] for i, b in enumerate(data)), keys

    def xor_multi_decode(self, data, keys):
        keys = [k % 256 for k in keys]
        n = len(keys)
        return bytes(b ^ keys[i % n] for i, b in enumerate(data))

    # -- XOR key finder --------------------------------------------------
    def find_single_xor_key(self, data, plaintext=None):
        """Brute-force the single-byte XOR key. With a known plaintext, pick
        the key that reproduces it; otherwise pick the key whose decode is
        most printable (used to break naive single-byte XOR)."""
        if plaintext is not None:
            pt = bytes(plaintext)
            if len(pt) > len(data):
                return None
            for k in range(256):
                if bytes(b ^ k for b in data[:len(pt)]) == pt:
                    return k, bytes(b ^ k for b in data)
            return None
        best, best_score = None, -1
        for k in range(256):
            dec = bytes(b ^ k for b in data)
            score = sum(32 <= c < 127 for c in dec)
            if score > best_score:
                best_score = score
                best = k
        return best, bytes(b ^ k for b in data)

    # -- additive transform ----------------------------------------------
    def add_encode(self, data, addend):
        return bytes((b + addend) & 0xFF for b in data), addend % 256

    def add_decode(self, data, addend):
        return bytes((b - addend) & 0xFF for b in data)

    def rol8(self, b, bits=3):
        return ((b << bits) | (b >> (8 - bits))) & 0xFF

    # -- benign probe helpers ---------------------------------------------
    def nop_sled(self, count=32, include_int3=False):
        sled = b"\x90" * count
        if include_int3:
            sled += b"\xcc"
        return sled

    # -- reversible alphanumeric transform ---------------------------------
    def alphanumeric_encode(self, data):
        """Encode arbitrary bytes to a strictly alphanumeric ASCII stream.
        Emission: each input byte -> two chars from a 62-char alphabet.
        Always decodable; deterministic; offline."""
        out = []
        for b in data:
            out.append(ALNUM_ALPHABET[b // len(ALNUM_ALPHABET)])
            out.append(ALNUM_ALPHABET[b % len(ALNUM_ALPHABET)])
        return "".join(out).encode("ascii")

    def alphanumeric_decode(self, data):
        """Invert alphanumeric_encode."""
        if len(data) % 2 != 0:
            raise ValueError("alphanumeric payload must have even length")
        s = data.decode("ascii")
        out = bytearray()
        for i in range(0, len(s), 2):
            hi = ALNUM_ALPHABET.index(s[i])
            lo = ALNUM_ALPHABET.index(s[i + 1])
            out.append((hi * len(ALNUM_ALPHABET) + lo) & 0xFF)
        return bytes(out)

    # -- REAL x86-64 decoder stub ------------------------------------------
    def x86_64_decode_stub(self):
        """Machine-code bytes for a self-contained decoder callable as:

            void *stub(void *buf, size_t len, unsigned char key)

        In-place single-byte XOR decode loop (rdi=buf, rsi=len, dl=key),
        verified byte-for-byte against real execution on x86-64:

            mov  rcx, rsi            48 89 f1
        L:  mov  al, byte [rdi]      8a 07
            xor  al, dl              30 d0
            mov  byte [rdi], al      88 07
            inc  rdi                 48 ff c7
            loop L                   e2 f5
            mov  rax, rdi            48 89 f8
            ret                      c3
        """
        return bytes([
            0x48, 0x89, 0xf1,          # mov rcx, rsi (count)
            0x8a, 0x07,                # mov al, byte [rdi]
            0x30, 0xd0,                # xor al, dl
            0x88, 0x07,                # mov byte [rdi], al
            0x48, 0xff, 0xc7,          # inc rdi
            0xe2, 0xf5,                # loop L
            0x48, 0x89, 0xf8,          # mov rax, rdi
            0xc3,                      # ret
        ])

    def self_decoding_stub(self, payload_len, key):
        """Position-independent x86-64 decoder that XOR-decodes a payload
        placed immediately after it in memory, then falls through into it.

        Layout (26 bytes, then the encoded payload):
            call next              e8 00 00 00 00
        next:
            pop  rsi               5e           ; rsi = base+5
            add  rsi, 0x15         48 83 c6 15  ; -> payload at base+26
            xor  rcx, rcx          48 31 c9
            mov  cl, <len>         b1 <len>
        L:  mov  al, [rsi]         8a 06
            xor  al, <key>         34 <key>
            mov  [rsi], al         88 06
            inc  rsi               48 ff c6
            loop L                 e2 f5
            ; execution falls into the decoded payload below
        """
        stub = bytearray()
        stub += b"\xe8\x00\x00\x00\x00"          # call next
        stub += b"\x5e"                           # pop rsi
        stub += bytes([0x48, 0x83, 0xc6, 0x15])   # add rsi, 21
        stub += b"\x48\x31\xc9"                   # xor rcx, rcx
        stub += bytes([0xb1, payload_len & 0xFF]) # mov cl, len
        stub += b"\x8a\x06"                       # mov al, [rsi]
        stub += bytes([0x34, key & 0xFF])         # xor al, key
        stub += b"\x88\x06"                       # mov [rsi], al
        stub += b"\x48\xff\xc6"                   # inc rsi
        stub += b"\xe2\xf5"                       # loop L
        assert len(stub) == 26
        return bytes(stub)


# ---------------------------------------------------------------------------
# minimal static ELF64 (no libc) holder for the self-decoding blob
# ---------------------------------------------------------------------------

def build_minimal_elf(code, flags=7):
    """Hand-built x86-64 static ELF: one RWX PT_LOAD segment; entry point
    points at `code`, which sits right after the 64-byte ELF header + the
    56-byte program header."""
    hdrsz = 64 + 56
    e_entry = 0x400000 + hdrsz
    ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    eh = struct.pack("<16sHHIQQQIHHHHHH",
                     ident, 2, 62, 1, e_entry, 64, 0, 0,
                     64, 56, 1, 0, 0, 0)
    ph = struct.pack("<IIQQQQQQ",
                     1, flags, 0, 0x400000, 0,
                     hdrsz + len(code), hdrsz + len(code), 0x1000)
    return eh + ph + code


def _executable_elf_of_blob(stub, payload):
    return build_minimal_elf(stub + payload, flags=7)


def _run_probe_elf(elf_bytes):
    """Run a probe ELF in a temporary dir; return (returncode, tmpdir, path).
    The directory is cleaned up by the caller."""
    td = tempfile.mkdtemp(prefix="m9probe_")
    path = os.path.join(td, "probe")
    with open(path, "wb") as f:
        f.write(elf_bytes)
    os.chmod(path, 0o755)
    r = subprocess.run([path], cwd=td, timeout=20,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode, td, path


def execute_sled_probe():
    """Decode-and-execute a benign 0x90 NOP sled + INT3 in an isolated
    subprocess. Builds a self-decoding ELF whose entry code XOR-decodes the
    encoded sled in place, then falls through into it; the INT3 raises
    SIGTRAP which terminates the process. Returns True when the process died
    of SIGTRAP (i.e. the decoded sled actually executed)."""
    if not X86_64:
        raise RuntimeError("decode-and-execute probe requires x86-64 Linux")
    sled = b"\x90" * 16 + b"\xcc"
    key = 0x5A
    encoded = bytes(b ^ key for b in sled)
    enc = ShellcodeEncoder(arch="x64")
    stub = enc.self_decoding_stub(len(sled), key)
    elf = _executable_elf_of_blob(stub, encoded)
    code, td, path = _run_probe_elf(elf)
    import shutil
    shutil.rmtree(td, ignore_errors=True)
    return code == -signal_SIGTRAP()


def signal_SIGTRAP():
    import signal
    return signal.SIGTRAP


# ---------------------------------------------------------------------------
# demo / CLI
# ---------------------------------------------------------------------------

DEFAULT_PAYLOAD_HEX = "48 31 c0 50 48 89 e6 48 31 d2 90 90 cc"


def _read_input(arg):
    """Read bytes from a hex string or a file path."""
    if os.path.isfile(arg):
        with open(arg, "rb") as f:
            return f.read()
    cleaned = arg.replace(" ", "").replace("\n", "").replace("0x", "")
    return binascii.unhexlify(cleaned)


def demo(args=None):
    print("=" * 66)
    print("  M9 - Shellcode Encoder - offline decode+execute demo")
    print("=" * 66)
    enc = ShellcodeEncoder(arch="x64", seed=1)
    payload = binascii.unhexlify(DEFAULT_PAYLOAD_HEX.replace(" ", ""))
    print("  Input payload   : %d bytes" % len(payload))

    enc_bytes, key = enc.xor_encode(payload, key=0x7C)
    print("  XOR key         : 0x%02x" % key)
    print("  Encoded len     : %d bytes" % len(enc_bytes))

    roundtrip = enc.xor_decode(enc_bytes, key)
    print("  Python roundtrip match: %s" % (roundtrip == payload))

    alpha = enc.alphanumeric_encode(payload)
    print("  Alphanumeric    : %s" % alpha.decode("ascii"))
    alpha_back = enc.alphanumeric_decode(alpha)
    print("  Alnum roundtrip match: %s" % (alpha_back == payload))

    found_k, _ = enc.find_single_xor_key(enc_bytes, plaintext=payload[:8])
    print("  XOR key finder  : recovered 0x%02x (expected 0x%02x)"
          % (found_k, key))

    try:
        ok = execute_sled_probe()
        print("  Isolated decode+execute NOP/int3 probe: %s" %
              ("REACHED INT3 (OK)" if ok else "FAILED"))
    except RuntimeError as e:
        print("  Isolated decode+execute probe: skipped (%s)" % e)

    print("exit=0")
    return 0


def _write_output(args, result, blob):
    outdir = args.output or os.path.join("reports", "m9")
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "report.json"), "w") as f:
        json.dump(result, f, indent=2)
    with open(os.path.join(outdir, "report.md"), "w") as f:
        f.write("## M9 report\n\n```json\n%s\n```\n"
                % json.dumps(result, indent=2))
        if blob is not None:
            f.write("\n```\n%s\n```\n" % hexdump(blob))
    if blob is not None:
        with open(os.path.join(outdir, "output.bin"), "wb") as f:
            f.write(blob)
    return os.path.join(outdir, "report.json")


def cmd_encode(args):
    data = _read_input(args.input)
    enc = ShellcodeEncoder(arch=args.arch, seed=args.seed)
    key = args.key if args.key is not None else enc.key
    enc.key = key % 256
    result = {"input_len": len(data), "input_sha256": _sha256(data)}
    if args.alpha:
        encoded = enc.alphanumeric_encode(data)
        result["method"] = "alphanumeric"
        result["alphabet"] = ALNUM_ALPHABET
        result["encoded_hex"] = encoded.hex()
        result["ascii"] = encoded.decode("ascii")
    elif args.multi:
        keys = [(key + i) % 256 for i in range(args.multi)]
        encoded, keys = enc.xor_multi_encode(data, keys)
        result["method"] = "xor_multi"
        result["keys"] = ["0x%02x" % k for k in keys]
        result["encoded_hex"] = encoded.hex()
    else:
        encoded, key2 = enc.xor_encode(data, key)
        result["method"] = "xor"
        result["key"] = "0x%02x" % (key2 % 256)
        result["encoded_hex"] = encoded.hex()
        result["stub_hex"] = enc.self_decoding_stub(
            len(data), key2 % 256).hex()
    path = _write_output(args, result, None)
    print(json.dumps(result, indent=2))
    print("report: %s" % path)
    return 0


def cmd_decode(args):
    data = _read_input(args.input)
    key = int(args.key, 0) if not isinstance(args.key, int) else args.key
    enc = ShellcodeEncoder()
    dec = enc.xor_decode(data, key)
    result = {"key": "0x%02x" % (key % 256),
              "decoded_hex": dec.hex(),
              "ascii": dec.decode("ascii", errors="replace")}
    path = _write_output(args, result, dec)
    print(json.dumps(result, indent=2))
    print("report: %s" % path)
    return 0


def cmd_findkey(args):
    data = _read_input(args.input)
    enc = ShellcodeEncoder()
    plaintext = None
    if args.plaintext:
        plaintext = binascii.unhexlify(args.plaintext.replace(" ", ""))
    found = enc.find_single_xor_key(data, plaintext=plaintext)
    if found is None:
        print("No key found (plaintext too long for data)")
        return 1
    key, dec = found
    result = {"key": "0x%02x" % key,
              "decoded_hex": dec.hex(),
              "ascii": dec.decode("ascii", errors="replace")}
    path = _write_output(args, result, dec)
    print(json.dumps(result, indent=2))
    print("report: %s" % path)
    return 0


def cmd_verify(args):
    if not X86_64:
        print("verify requires x86-64 Linux")
        return 1
    enc = ShellcodeEncoder()
    status = {"arch": "x86-64"}
    if args.input is not None and args.key is not None:
        data = _read_input(args.input)
        key = (int(args.key, 0) if not isinstance(args.key, int)
               else args.key) % 256
        try:
            dec = _decoded_bytes_via_stub(data, key)
            status["machine_decode_ok"] = bool(dec == bytes(b ^ key for b in data))
            status["decoded_hex"] = dec.hex()
        except RuntimeError as e:
            status["machine_decode_ok"] = "skipped: %s" % e
    else:
        try:
            status["execute_probe"] = "reached-int3" if execute_sled_probe() \
                else "failed"
        except RuntimeError as e:
            status["execute_probe"] = "skipped: %s" % e
    path = _write_output(args, status, None)
    print(json.dumps(status, indent=2))
    print("report: %s" % path)
    if status.get("machine_decode_ok") is False or \
            status.get("execute_probe") == "failed":
        return 1
    return 0


def _sha256(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _decoded_bytes_via_stub(encoded, key):
    """Decode a buffer in place with the REAL machine-code decoder stub by
    mapping it read/write/execute and calling it. Deterministic on x86-64
    Linux; the caller must hold the mmap lifetime across the call."""
    if not X86_64:
        raise RuntimeError("machine-code decode requires x86-64 Linux")
    import ctypes
    import mmap
    stub = ShellcodeEncoder(arch="x64").x86_64_decode_stub()
    buf = (ctypes.c_ubyte * len(encoded)).from_buffer_copy(encoded)
    mm = mmap.mmap(-1, len(stub),
                   prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    mm.write(stub)
    arr = (ctypes.c_char * len(stub)).from_buffer(mm)
    fnc = ctypes.CFUNCTYPE(ctypes.c_void_p,
                           ctypes.POINTER(ctypes.c_ubyte),
                           ctypes.c_size_t,
                           ctypes.c_ubyte)
    res = fnc(ctypes.addressof(arr))(buf, len(encoded), key % 256)
    if not res:
        raise RuntimeError("decoder returned NULL")
    return bytes(buf)


def hexdump(b, cols=16):
    lines = []
    for i in range(0, len(b), cols):
        chunk = b[i:i + cols]
        hexpart = " ".join("%02x" % x for x in chunk)
        hexpart = hexpart.ljust(cols * 3)
        asc = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        lines.append("%08x  %s  %s" % (i, hexpart, asc))
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="shellcode.py",
        description="M9 - Shellcode Encoder (XOR / alphanumeric, real x86-64 "
                    "decoder, isolated decode-and-execute)")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("demo", help="offline demo (exits 0)")

    p_enc = sub.add_parser("encode", help="encode a payload")
    p_enc.add_argument("input", help="hex string or file path")
    p_enc.add_argument("--arch", choices=["x86", "x64"], default="x64")
    p_enc.add_argument("--key", type=lambda v: int(v, 0), default=None)
    p_enc.add_argument("--multi", type=int, default=0, help="repeating key len")
    p_enc.add_argument("--alpha", action="store_true", help="alphanumeric")
    p_enc.add_argument("--seed", type=int, default=None)
    p_enc.add_argument("-o", "--output", default=None)

    p_dec = sub.add_parser("decode", help="decode XOR payload")
    p_dec.add_argument("input", help="hex string or file path")
    p_dec.add_argument("--key", type=lambda v: int(v, 0), required=True)
    p_dec.add_argument("-o", "--output", default=None)

    p_fk = sub.add_parser("findkey", help="brute-force single-byte XOR key")
    p_fk.add_argument("input", help="hex string or file path")
    p_fk.add_argument("--plaintext", default=None, help="known plaintext hex")
    p_fk.add_argument("-o", "--output", default=None)

    p_ver = sub.add_parser("verify", help="decode+execute probe")
    p_ver.add_argument("input", nargs="?", default=None, help="encoded hex")
    p_ver.add_argument("--key", type=lambda v: int(v, 0), default=None)
    p_ver.add_argument("-o", "--output", default=None)

    args = parser.parse_args(argv)
    if args.cmd == "demo":
        return demo()
    if args.cmd == "encode":
        return cmd_encode(args)
    if args.cmd == "decode":
        return cmd_decode(args)
    if args.cmd == "findkey":
        return cmd_findkey(args)
    if args.cmd == "verify":
        return cmd_verify(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())