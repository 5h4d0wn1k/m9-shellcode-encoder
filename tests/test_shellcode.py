#!/usr/bin/env python3
"""Tests for m9-shellcode-encoder."""
import binascii
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "firmware"))
import shellcode as sc

SCRIPT = os.path.join(ROOT, "firmware", "shellcode.py")
X86_64 = sc.X86_64


class TestXorEncodeDecode(unittest.TestCase):
    def test_single_byte_roundtrip(self):
        enc = sc.ShellcodeEncoder(seed=7)
        data = bytes(range(256))
        encd, key = enc.xor_encode(data)
        self.assertEqual(sc.ShellcodeEncoder().xor_decode(encd, key), data)
        self.assertNotEqual(encd, data)

    def test_key_scale_seed(self):
        enc1 = sc.ShellcodeEncoder(seed=42)
        enc2 = sc.ShellcodeEncoder(seed=42)
        self.assertEqual(enc1.key, enc2.key)

    def test_multi_roundtrip(self):
        enc = sc.ShellcodeEncoder(seed=3)
        data = b"repeating-key xor test"
        keys = [0x11, 0x22, 0x33, 0x44]
        encd, _ = enc.xor_multi_encode(data, keys)
        self.assertEqual(enc.xor_multi_decode(encd, keys), data)
        self.assertNotEqual(encd, data)


class TestKeyFinder(unittest.TestCase):
    def test_known_plaintext(self):
        data = b"secret message"
        key = 0x4C
        encd = bytes(b ^ key for b in data)
        found, dec = sc.ShellcodeEncoder().find_single_xor_key(
            encd, plaintext=data[:8])
        self.assertEqual(found, key)
        self.assertEqual(dec, data)

    def test_printable_heuristic(self):
        data = b"the quick brown fox jumps"
        key = 0x0A
        encd = bytes(b ^ key for b in data)
        # the heuristic always produces a key; the decode is deterministic
        found, dec = sc.ShellcodeEncoder().find_single_xor_key(encd)
        self.assertIsNotNone(found)
        self.assertTrue(0 <= found <= 255)
        self.assertEqual(len(dec), len(data))

    def test_plaintext_too_long(self):
        data = b"ab"
        self.assertIsNone(
            sc.ShellcodeEncoder().find_single_xor_key(
                bytes([1, 2]), plaintext=b"abcdef"))


class TestAlphanumeric(unittest.TestCase):
    def test_alnum_roundtrip(self):
        data = bytes(range(0, 90))
        alpha = sc.ShellcodeEncoder().alphanumeric_encode(data)
        self.assertTrue(all(32 <= c < 127 for c in alpha))
        for c in alpha:
            self.assertTrue(chr(c).isalnum())
        self.assertEqual(sc.ShellcodeEncoder().alphanumeric_decode(alpha), data)

    def test_strict_alphabet(self):
        data = b"\x00\xff\x10\x7f"
        alpha = sc.ShellcodeEncoder().alphanumeric_encode(data)
        for c in alpha.decode():
            self.assertIn(c, sc.ALNUM_ALPHABET)


class TestDecoderStub(unittest.TestCase):
    def test_stub_disassembly_length(self):
        stub = sc.ShellcodeEncoder().x86_64_decode_stub()
        self.assertEqual(len(stub), 18)
        self.assertEqual(stub[:3], b"\x48\x89\xf1")

    def test_self_decoding_stub_length(self):
        stub = sc.ShellcodeEncoder().self_decoding_stub(16, 0x5A)
        self.assertEqual(len(stub), 26)


class TestMinimalElf(unittest.TestCase):
    def test_elf_header(self):
        code = b"\xcc"
        elf = sc.build_minimal_elf(code)
        self.assertEqual(elf[:4], b"\x7fELF")
        self.assertEqual(elf[4], 2)                   # ELF64 class
        self.assertEqual(elf[5], 1)                   # little endian
        self.assertEqual(elf[16:18], b"\x02\x00")     # ET_EXEC

    def test_simple_int3_elf_dies_sigtrap(self):
        if not X86_64:
            self.skipTest("x86-64 only")
        elf = sc.build_minimal_elf(b"\xcc")
        code, td, path = sc._run_probe_elf(elf)
        import shutil
        shutil.rmtree(td, ignore_errors=True)
        self.assertEqual(code, -5)  # SIGTRAP


@unittest.skipUnless(X86_64, "x86-64 only")
class TestExecuteSledProbe(unittest.TestCase):
    def test_probe_reaches_int3(self):
        self.assertTrue(sc.execute_sled_probe())


class TestCli(unittest.TestCase):
    def test_demo_exits_zero(self):
        r = subprocess.run([sys.executable, SCRIPT, "demo"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("exit=0", r.stdout)

    def test_encode_cli(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "out")
            r = subprocess.run([sys.executable, SCRIPT, "encode",
                                "4831c090", "--key", "0x1b", "-o", out],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(os.path.exists(os.path.join(out, "report.json")))

    def test_decode_roundtrip_cli(self):
        with tempfile.TemporaryDirectory() as td:
            data = bytes([0xca, 0xfe, 0xba, 0xbe])
            key = 0x77
            encd = bytes(b ^ key for b in data)
            r = subprocess.run([sys.executable, SCRIPT, "decode",
                                encd.hex(), "--key", hex(key), "-o", td],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            report = os.path.join(td, "report.json")
            self.assertTrue(os.path.exists(report))
            import json
            with open(report) as f:
                rep = json.load(f)
            self.assertEqual(rep["decoded_hex"], data.hex())

    @unittest.skipUnless(X86_64, "x86-64 only")
    def test_verify_cli(self):
        r = subprocess.run([sys.executable, SCRIPT, "verify"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("reached-int3", r.stdout)


if __name__ == "__main__":
    unittest.main()