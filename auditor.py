#!/usr/bin/env python3
"""
Supply Chain Malware Auditor
Detects Glassworm-style Unicode steganography and related IOCs.

Covers:
  - Unicode variation selectors (U+FE00–U+FE0F, U+E0100–U+E01EF)
  - Zero-width / invisible characters
  - Suspicious eval() patterns
  - npm preinstall/postinstall hooks
  - Solana RPC endpoints
  - Abnormal line gap heuristic
  - Encoded string + exec chains (Python)

Usage:
  python3 auditor.py <path>              # scan a directory or file
  python3 auditor.py ./node_modules
  python3 auditor.py ~/.local/lib/python3.x/site-packages
  python3 auditor.py /tmp/infected_example.js
"""

import os
import sys
import re
import json
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── Unicode ranges ─────────────────────────────────────────────────────────────

VARIATION_SELECTORS = (
    set(range(0xFE00, 0xFE10)) |       # VS1–VS16
    set(range(0xFE20, 0xFE30)) |       # Combining half marks (also abusable)
    set(range(0xE0100, 0xE01F0))       # VS17–VS256 (supplementary)
)

INVISIBLE_CHARS = {
    0x200B,  # Zero Width Space
    0x200C,  # Zero Width Non-Joiner
    0x200D,  # Zero Width Joiner
    0x2060,  # Word Joiner
    0x2061,  # Function Application
    0x2062,  # Invisible Times
    0x2063,  # Invisible Separator
    0x2064,  # Invisible Plus
    0xFEFF,  # BOM / Zero Width No-Break Space
    0x00AD,  # Soft Hyphen
    0x180E,  # Mongolian Vowel Separator
}

# ── Suspicious pattern regexes ─────────────────────────────────────────────────

PATTERNS = {
    # Eval on decoded/transformed data
    "eval_decoded": re.compile(
        r'eval\s*\(\s*(?:atob|Buffer\.from|decode|unescape|String\.fromCharCode)',
        re.IGNORECASE
    ),
    # Direct eval on variable (weaker signal)
    "eval_var": re.compile(r'\beval\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)'),
    # Python exec on decoded data
    "exec_decoded": re.compile(
        r'exec\s*\(\s*(?:base64|b64decode|decode|bytes\.fromhex|codecs)',
        re.IGNORECASE
    ),
    # Solana RPC
    "solana_rpc": re.compile(
        r'(?:api\.mainnet-beta\.solana\.com|rpc\.ankr\.com/solana|'
        r'solana-api\.projectserum\.com|devnet\.solana\.com)',
        re.IGNORECASE
    ),
    # Solana wallet address pattern (base58, 32-44 chars)
    "solana_wallet": re.compile(r'\b[1-9A-HJ-NP-Za-km-z]{32,44}\b'),
    # Google Calendar C2 pattern from Glassworm
    "gcal_c2": re.compile(r'calendar\.google\.com.*(?:ical|ics|embed)', re.IGNORECASE),
    # Glassworm persistence IOC
    "init_json_persist": re.compile(r'init\.json', re.IGNORECASE),
    # Environment variable fingerprinting (TZ skip)
    "tz_fingerprint": re.compile(
        r'(?:process\.env\.TZ|os\.environ.*TZ|timezone.*Russia|'
        r'Europe/Moscow|Asia/Yekaterinburg)',
        re.IGNORECASE
    ),
    # AES key in response headers (Glassworm specific)
    "aes_header": re.compile(r'(?:AES.{0,10}256|aes-256-cbc)', re.IGNORECASE),
    # Proxy/SOCKS setup
    "socks_proxy": re.compile(r'(?:socks[45]|createServer.*proxy|net\.createServer)', re.IGNORECASE),
    # preinstall hook running node/sh
    "preinstall_exec": re.compile(r'"(?:pre|post)install"\s*:\s*"(?:node|sh|bash|python)', re.IGNORECASE),
    # Suspicious string manipulation before eval
    "strip_unicode_exec": re.compile(
        r'(?:replace|filter|map).*(?:\\\\uFE0|\\\\uE01|0xFE0|0xE01).*(?:eval|exec)',
        re.IGNORECASE
    ),
}

SEVERITY = {
    "eval_decoded":        "CRITICAL",
    "exec_decoded":        "CRITICAL",
    "solana_rpc":          "CRITICAL",
    "gcal_c2":             "HIGH",
    "socks_proxy":         "HIGH",
    "preinstall_exec":     "HIGH",
    "strip_unicode_exec":  "HIGH",
    "init_json_persist":   "MEDIUM",
    "tz_fingerprint":      "MEDIUM",
    "aes_header":          "MEDIUM",
    "eval_var":            "LOW",
    "solana_wallet":       "INFO",   # noisy, flag only with other hits
}

# ── Data structures ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str
    category: str
    file: str
    line: int
    detail: str
    snippet: str = ""

@dataclass
class FileResult:
    path: str
    findings: list = field(default_factory=list)

    @property
    def max_severity(self):
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for level in order:
            if any(f.severity == level for f in self.findings):
                return level
        return None

# ── Core analysis ───────────────────────────────────────────────────────────────

SCAN_EXTS = {'.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx', '.py', '.json'}
SKIP_DIRS = {'.git', '__pycache__', '.cache', 'dist', '.npm', 'coverage'}

def scan_unicode(path: str, text: str, lines: list) -> list[Finding]:
    findings = []
    vs_lines = {}
    invis_lines = {}

    for i, ch in enumerate(text):
        cp = ord(ch)
        lineno = text[:i].count('\n') + 1
        if cp in VARIATION_SELECTORS:
            vs_lines.setdefault(lineno, []).append(hex(cp))
        elif cp in INVISIBLE_CHARS:
            invis_lines.setdefault(lineno, []).append(hex(cp))

    for lineno, cps in vs_lines.items():
        findings.append(Finding(
            severity="CRITICAL",
            category="variation_selector_steganography",
            file=path,
            line=lineno,
            detail=f"Variation selectors found: {cps[:8]}{'...' if len(cps)>8 else ''}",
            snippet=lines[lineno-1][:120] if lineno <= len(lines) else ""
        ))

    for lineno, cps in invis_lines.items():
        findings.append(Finding(
            severity="HIGH",
            category="invisible_unicode",
            file=path,
            line=lineno,
            detail=f"Invisible unicode chars: {cps[:8]}",
            snippet=lines[lineno-1][:120] if lineno <= len(lines) else ""
        ))

    return findings


def scan_line_gap(path: str, lines: list) -> list[Finding]:
    """
    Heuristic: a 'blank' line that is actually non-empty (contains only
    invisible chars) between real code lines is a strong signal.
    """
    findings = []
    for i, line in enumerate(lines):
        stripped_visible = ''.join(
            ch for ch in line if unicodedata.category(ch) not in ('Cf', 'Mn') and ch != ' '
        )
        if not stripped_visible and len(line.rstrip('\n')) > 0:
            findings.append(Finding(
                severity="HIGH",
                category="invisible_line_content",
                file=path,
                line=i + 1,
                detail=f"Line appears blank but contains {len(line.rstrip())} non-rendering chars",
                snippet=repr(line[:40])
            ))
    return findings


def scan_patterns(path: str, lines: list) -> list[Finding]:
    findings = []
    # wallet hits only matter alongside other signals — track separately
    wallet_hits = []

    for i, line in enumerate(lines):
        lineno = i + 1
        for name, pattern in PATTERNS.items():
            if pattern.search(line):
                sev = SEVERITY[name]
                f = Finding(
                    severity=sev,
                    category=name,
                    file=path,
                    line=lineno,
                    detail=f"Pattern match: {name}",
                    snippet=line.strip()[:120]
                )
                if name == "solana_wallet":
                    wallet_hits.append(f)
                else:
                    findings.append(f)

    # Only surface wallet hits if there are other suspicious findings
    if wallet_hits and findings:
        findings.extend(wallet_hits[:3])  # cap noise

    return findings


def scan_package_json(path: str, text: str) -> list[Finding]:
    findings = []
    try:
        data = json.loads(text)
        scripts = data.get('scripts', {})
        for hook in ['preinstall', 'postinstall', 'prepare', 'install']:
            if hook in scripts:
                cmd = scripts[hook]
                # Flag if it runs arbitrary code, not just build tools
                if re.search(r'(?:node\s+(?!_modules)|curl|wget|bash|sh\s+-|python)', cmd):
                    findings.append(Finding(
                        severity="HIGH",
                        category="suspicious_npm_hook",
                        file=path,
                        line=0,
                        detail=f"scripts.{hook} executes: {cmd[:100]}",
                        snippet=cmd[:120]
                    ))
    except json.JSONDecodeError:
        pass
    return findings


def analyze_file(path: str) -> Optional[FileResult]:
    try:
        raw = open(path, encoding='utf-8', errors='replace').read()
    except Exception:
        return None

    lines = raw.splitlines()
    result = FileResult(path=path)

    result.findings.extend(scan_unicode(path, raw, lines))
    result.findings.extend(scan_line_gap(path, lines))
    result.findings.extend(scan_patterns(path, lines))

    if path.endswith('package.json'):
        result.findings.extend(scan_package_json(path, raw))

    return result if result.findings else None


def scan_directory(root: str) -> list[FileResult]:
    results = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            fpath = os.path.join(dirpath, fname)
            if any(fpath.endswith(ext) for ext in SCAN_EXTS):
                r = analyze_file(fpath)
                if r:
                    results.append(r)
    return results


# ── Output ──────────────────────────────────────────────────────────────────────

SEV_COLOR = {
    "CRITICAL": "\033[91m",   # red
    "HIGH":     "\033[93m",   # yellow
    "MEDIUM":   "\033[33m",   # dark yellow
    "LOW":      "\033[36m",   # cyan
    "INFO":     "\033[37m",   # grey
}
RESET = "\033[0m"
BOLD  = "\033[1m"

def print_results(results: list[FileResult], verbose: bool = False):
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    # Sort results by worst severity first
    results.sort(key=lambda r: order.index(r.max_severity) if r.max_severity else 99)

    total_findings = sum(len(r.findings) for r in results)
    critical = sum(1 for r in results if r.max_severity == "CRITICAL")

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}SUPPLY CHAIN AUDIT RESULTS{RESET}")
    print(f"{'='*60}")
    print(f"Files with findings : {len(results)}")
    print(f"Total findings      : {total_findings}")
    print(f"Critical files      : {BOLD}{SEV_COLOR.get('CRITICAL','')}{critical}{RESET}")
    print(f"{'='*60}\n")

    for result in results:
        max_sev = result.max_severity
        color = SEV_COLOR.get(max_sev, "")
        print(f"{color}{BOLD}[{max_sev}]{RESET} {result.path}")

        # Group findings by severity
        for sev in order:
            sev_findings = [f for f in result.findings if f.severity == sev]
            if not sev_findings:
                continue
            c = SEV_COLOR.get(sev, "")
            for f in sev_findings:
                loc = f"line {f.line}" if f.line else "package.json"
                print(f"  {c}▶ [{sev}]{RESET} {f.category} ({loc})")
                print(f"    {f.detail}")
                if f.snippet and verbose:
                    print(f"    snippet: {repr(f.snippet[:80])}")
        print()


# ── Entry point ─────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 auditor.py <path> [--verbose]")
        sys.exit(1)

    target = sys.argv[1]
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    print(f"[*] Scanning: {target}")

    if os.path.isfile(target):
        r = analyze_file(target)
        results = [r] if r else []
    elif os.path.isdir(target):
        results = scan_directory(target)
    else:
        print(f"[!] Path not found: {target}")
        sys.exit(1)

    if not results:
        print("[+] No suspicious findings detected.")
    else:
        print_results(results, verbose=verbose)
        # Exit code for CI integration
        if any(r.max_severity == "CRITICAL" for r in results):
            sys.exit(2)
        sys.exit(1)


if __name__ == '__main__':
    main()
