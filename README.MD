# Glass-Worm POC — Unicode Variation Selector Obfuscation

I learnt about the supply chain attack from Glassworm that using invisible code so I made this with the help of Claude Sonnet 4.6 to demonstrate how it works.

> ⚠️ **This repository is a defensive security research tool.** The POC exists solely to demonstrate the attack technique so that the companion detection tool (`auditor.py`) can be understood, tested, and validated against a real sample. The primary deliverable of this project is **detection — not exploitation.**

Educational proof-of-concept demonstrating the Unicode steganography technique observed in the Glassworm supply chain malware campaign (March 2026). Built for understanding attacker tradecraft and improving detection tooling.

---

## Background

Glassworm and related threat actors were observed hiding malicious JavaScript inside Unicode variation selectors — codepoints that carry no visible glyph in most editors, terminals, and code review interfaces including GitHub diffs and VSCode. The payload is embedded directly in source files and is invisible to the naked eye, bypassing visual code review entirely.

This POC reproduces the technique using the supplementary variation selector block (`U+E0100–U+E01FF`) for encoding, with fallback support for the base block (`U+FE00–U+FE0F`).

---

## How It Works

### Encoding

Each byte of the UTF-8 payload is mapped to a codepoint in the supplementary variation selector block:

```
byte → chr(0xE0100 + byte)
```

This produces a sequence of characters that render as nothing in most text renderers. The hidden sequence is then spliced into a decoy string at a configurable split point, producing a file that appears syntactically normal.

### Decoding (runtime loader)

The embedded JS decoder iterates over the string codepoints, extracts bytes from the variation selector ranges, reconstructs the payload as a UTF-8 string, and passes it to `eval()`.

```
U+E0100–U+E01FF  →  byte = codepoint - 0xE0100
U+FE00–U+FE0F   →  byte = codepoint - 0xFE00
```

---

## Usage

```bash
python3 poc.py -p '<payload>' [-o output.js] [--decoy '<decoy code>']
```

### Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `-p`, `--payload` | JavaScript payload to hide | required |
| `-o`, `--output` | Output filename | `malicious.js` |
| `--decoy` | Visible decoy code string | `console.log('Hello, World!');` |

### Examples

```bash
# Basic usage
python3 poc.py -p 'console.log("hidden")'

# Custom output file and decoy
python3 poc.py -p 'console.log("hidden")' -o output.js --decoy "const x = 42;"

# Execute output
node malicious.js
```

---

## 🛡️ Detection Tool — `auditor.py`

> This is the **main purpose of this repository.** The POC generates a controlled sample; `auditor.py` is the actual defensive output.

`auditor.py` is a standalone Python scanner that detects Glassworm-style Unicode steganography and related supply chain attack indicators across JavaScript, TypeScript, and Python codebases. It requires no dependencies beyond the Python standard library.

### Usage

```bash
# Scan your entire node_modules
python3 auditor.py ./node_modules --verbose

# Scan a specific file
python3 auditor.py /path/to/suspicious.js

# Scan Python site-packages
python3 auditor.py ~/.local/lib/python3.11/site-packages

# Use in CI — exits code 2 on CRITICAL, 1 on any finding, 0 on clean
python3 auditor.py ./src && echo "Clean"
```

### What It Detects

| Severity | Category | Description |
|----------|----------|-------------|
| 🔴 CRITICAL | `variation_selector_steganography` | Variation selectors (`U+FE00–U+FE0F`, `U+E0100–U+E01EF`) found in source — definitive IOC |
| 🔴 CRITICAL | `eval_decoded` | `eval(atob(...))` / `eval(Buffer.from(...))` chains |
| 🔴 CRITICAL | `exec_decoded` | Python `exec(b64decode(...))` or similar |
| 🔴 CRITICAL | `solana_rpc` | Solana RPC endpoints hardcoded — Glassworm C2 channel |
| 🟠 HIGH | `invisible_line_content` | Line appears blank but contains hidden characters |
| 🟠 HIGH | `suspicious_npm_hook` | `preinstall`/`postinstall` executing node/bash |
| 🟠 HIGH | `gcal_c2` | Google Calendar `.ics` fetch — Glassworm zombie payload delivery |
| 🟡 MEDIUM | `init_json_persist` | `init.json` reference — Glassworm 48hr re-execution lock |
| 🟡 MEDIUM | `tz_fingerprint` | Timezone/locale env checks — nation-state victim filtering |
| 🟡 MEDIUM | `aes_header` | AES-256-CBC in response header context |

### CI Integration

Drop it into a pre-commit hook or pipeline to catch infected dependencies before they execute:

```bash
# .git/hooks/pre-commit
python3 auditor.py ./node_modules
if [ $? -eq 2 ]; then
  echo "[!] CRITICAL findings in dependencies. Commit blocked."
  exit 1
fi
```

### Quick Grep (no dependencies)

If you just want a fast one-liner before running the full auditor:

```bash
grep -rP "[\xef\xb8\x80-\xef\xb8\x8f]" --include="*.js" --include="*.py" .
```

---

## Indicators of Compromise (Glassworm)

| IOC | Description |
|-----|-------------|
| `init.json` with timestamp field | Glassworm 48hr re-execution lock |
| Solana RPC calls in JS/TS source | Blockchain C2 channel |
| `preinstall` hook running `node` | npm-based dropper |
| TZ/locale env checks skipping Russian locales | Nation-state attribution tell |
| Google Calendar `.ics` fetch | Zombie proxy payload delivery |

---

## References

- [Ars Technica — Supply chain attack using invisible code hits GitHub and other repositories](https://arstechnica.com/security/2026/03/supply-chain-attack-using-invisible-code-hits-github-and-other-repositories/)
- [Socket.dev — Open VSX Transitive Glassworm Campaign](https://socket.dev/blog/open-vsx-transitive-glassworm-campaign)
- [Low Level Learning — "hackers are getting way too creative" (YouTube)](https://youtu.be/ZrD9MC_BXGk)
- MITRE ATT&CK: T1027 (Obfuscated Files), T1059.007 (JS execution), T1102 (Web Service C2)

---

## Disclaimer

This tool is for educational and defensive security research only. Use only against systems you own or have explicit written permission to test. The author takes no responsibility for misuse.
