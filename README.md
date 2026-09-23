> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# M9 — Shellcode Encoder & Obfuscation Toolkit (x86-64)

Real encoder/decoder toolkit for x86-64 with a verifiable decode-and-execute pipeline: single-byte and repeating-key XOR, a brute-force key finder, a reversible alphanumeric transform, and an isolated static-ELF execution probe. Offline, stdlib-only.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/m9-shellcode-encoder.svg)](https://github.com/5h4d0wn1k/m9-shellcode-encoder)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/m9-shellcode-encoder.svg)](https://github.com/5h4d0wn1k/m9-shellcode-encoder)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/m9-shellcode-encoder.svg)](https://github.com/5h4d0wn1k/m9-shellcode-encoder)

## Why

Evasion is the skill behind both malware analysis and red-team payload engineering — and it is safest to study in a sandbox. M9 implements the transformations that actually appear in the wild — XOR encoding, brute-force key recovery, alphanumeric (printable-ASCII) stream transforms — and proves the decode-then-execute path end-to-end by running a benign NOP-sled + `INT3` payload inside an isolated, hand-built static ELF that dies of `SIGTRAP`. Nothing harmful executes, nothing leaves the machine, and every step is reproducible from the CLI.

## Features

- **Single-byte XOR** encode/decode (fixed or seeded random key)
- **Repeating-key XOR** encode/decode (multi-byte key)
- **XOR key finder** — single-byte brute force against a known plaintext, or a printable-ASCII heuristic
- **Reversible alphanumeric transform** — arbitrary bytes → strictly alphanumeric ASCII (62-char alphabet, 2 chars/byte), decoded losslessly
- **Real x86-64 decoder stub** — 18-byte standalone loop, verified byte-for-byte
- **Isolated decode-and-execute** — minimal static ELF (no libc) decodes a benign `0x90` NOP sled + `INT3` in place; subprocess dies of `SIGTRAP`, proving the path

## Quickstart

```bash
# Offline demo (exit 0)
python3 firmware/shellcode.py demo

# Encode / decode with a key
python3 firmware/shellcode.py encode 9090cc --key 0x1b -o reports/m9
python3 firmware/shellcode.py decode <hex> --key 0x1b -o reports/m9

# Recover a single-byte key
python3 firmware/shellcode.py findkey <hex> --plaintext deadbeef -o reports/m9

# Decode + execute probe (isolated subprocess, benign payload)
python3 firmware/shellcode.py verify [HEX] --key 0x1b

# Unit tests
python3 -m unittest discover -s tests
```

## Project structure

- `firmware/shellcode.py` — encoder, decoder, key finder, alphanumeric transform, ELF probe, CLI
- `tests/` — unit tests over encode/decode round-trips and the execution probe

## Documentation

- [ETHICS.md](ETHICS.md) — educational purpose and authorized use only
- [SCOPE.md](SCOPE.md) — authorized-testing scope checklist
- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [CONTRIBUTING.md](CONTRIBUTING.md) — safe contribution guidelines

## Contributing

New encoders, heuristic improvements and probe fixtures are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md); the only executable payload stays the benign NOP-sled + `INT3` probe.

## License

MIT — see [LICENSE](LICENSE). Provided **AS IS**, without warranty, for education and authorized malware-analysis / red-team lab use only.