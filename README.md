# M9 — Shellcode Encoder

Shellcode encoding techniques for exploit development education.

## Overview

This project demonstrates shellcode encoding/obfuscation techniques:
- XOR encoding (single-byte and multi-byte keys)
- Additive encoding
- Alphanumeric-safe encoding
- Position-independent decoder stub generation
- NOP sled generation
- Hexdumping output

## Features

- **XOR encode**: single and multi-byte XOR ciphers
- **Add encode**: additive transformations
- **Alphanumeric**: converts bytes toward ASCII-safe output
- **x86/x64**: architecture-aware output
- **Decoder stubs**: position-independent assembly sketches
- **Hexdump**: formatted byte display

## Usage

```bash
python3 shellcode.py x64 90cd80cc
python3 shellcode.py x86 31c050682f2f7368
```

## Example Output

```
=== M9 - Shellcode Encoder ===
Architecture: x64
Input (3 bytes):
00000000  90 cd 80  ...

-- XOR Encoding (single byte key=0x3a) --
Cipher hex: aa0a...
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
