# M9 — Shellcode Encoder

A real encoder/decoder toolkit for x86-64 with a **working, verifiable
decode-and-execute** pipeline. Fully offline and stdlib-only.

## What genuinely works

- **Single-byte XOR** encode/decode (fixed or seeded random key).
- **Repeating-key XOR** encode/decode.
- **XOR key finder** — single-byte brute force against a known plaintext, or a
  printable-ASCII heuristic when no plaintext is given.
- **Reversible alphanumeric transform** — arbitrary bytes become a strictly
  alphanumeric ASCII stream (62-char alphabet, 2 output chars per byte) that
  decodes back losslessly.
- **REAL x86-64 machine-code decoder stub** — a 18-byte standalone loop that
  decodes a buffer in place via read/write/execute mapping, verified byte-for-
  byte.
- **Isolated decode-and-execute** — a hand-built minimal **static ELF**
  (no libc) whose entry code XOR-decodes a benign `0x90` NOP-sled + `INT3`
  payload in place, then falls through into it. Running the ELF as a subprocess
  proves the decode-then-execute path by dying of SIGTRAP at the `INT3`. No
  ctypes, no libffi, no compiler needed at runtime.

## CLI

```bash
python3 firmware/shellcode.py --help

python3 firmware/shellcode.py demo                # offline demo (exits 0)
python3 firmware/shellcode.py encode 9090cc --key 0x1b -o reports/m9
python3 firmware/shellcode.py decode <hex> --key 0x1b -o reports/m9
python3 firmware/shellcode.py findkey <hex> --plaintext deadbeef -o reports/m9
python3 firmware/shellcode.py verify [HEX] [--key K]   # decode+execute probe
```

Reports (JSON + Markdown) are written under `reports/` (gitignored).

## Tests

```bash
python3 -m unittest discover -s tests -v
```

17 stdlib unittest cases covering encode/decode round-trips, the key finder,
the alphanumeric transform, ELF construction, the real INT3 signal probe, and
CLI exit codes.

## Live Lab Test Plan

1. In an offline lab VM run `python3 firmware/shellcode.py demo` and confirm it
   prints the digest and `Isolated decode+execute NOP/int3 probe: REACHED INT3
   (OK)` then exits 0.
2. Encode a known payload and confirm `decode` reproduces it bit-for-bit.
3. Run `verify` (no args) — it builds and executes the benign sled ELF in a
   temp dir and reports that the process died of SIGTRAP, proving the
   decode-then-execute path.
4. Only ever encode/execute payloads you have written yourself for your own lab
   machines or explicitly authorized targets. The shipped execute probe only
   ever runs NOP + INT3.

## Metrics

- Transforms: single/multi-XOR, reversible alphanumeric, XOR key finder.
- Decoder: verified 18-byte x86-64 in-place XOR decoder (vmlinuz-grade loop).
- Exec path: minimal static ELF self-decoding blob runs a benign NOP+INT3 sled
  in an isolated subprocess and confirms SIGTRAP.
- Test count: 17 stdlib unittest cases (see `tests/`).
- Dependencies: Python 3 stdlib only (`struct`, `subprocess`, `tempfile`,
  `binascii`, `json`, `argparse`); optional `mmap`/`ctypes` are stdlib too.
- Offline demo: exits 0 and shows a real recovered payload + reached INT3.

## IMPORTANT: Read before use.

This tool is for **educational and authorized use only**. It can execute
machine code you supply. You MUST only ever encode, decode, or execute payloads
you have written yourself, on systems you own or have explicit written
permission to use. Executing untrusted shellcode or shellcode on systems you do
not own may violate computer-crime laws (including the CFAA). The author is
not responsible for misuse. The bundled decode-and-execute probe only ever runs
an inert NOP sled that ends in a breakpoint (INT3) and performs no action.

## License

MIT — see `LICENSE`.