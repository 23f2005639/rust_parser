#!/usr/bin/env python3
"""
ULPF Tamper Simulation Script
Simulates a malicious adversary attempting to tamper with an archived Parquet block
by modifying an IP address or deleting a record in the storage archive.
"""

import sys
import os
import subprocess

def tamper_file(file_path):
    if not os.path.exists(file_path):
        print(f"[!] Target file not found: {file_path}")
        sys.exit(1)

    print(f"[*] Simulating unauthorized forensic tampering on: {file_path}")

    # Check for ulpf binary
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ulpf_bin = os.path.join(repo_root, "target", "release", "ulpf")

    if os.path.exists(ulpf_bin):
        cmd = [ulpf_bin, "tamper", "--file", file_path, "--leaf", "0", "--ip", "10.99.99.99"]
        res = subprocess.run(cmd)
        if res.returncode == 0:
            return

    # Fallback to direct byte flip
    with open(file_path, "rb") as f:
        data = bytearray(f.read())

    if len(data) < 200:
        print("[!] File too small to simulate tamper.")
        sys.exit(1)

    offset = int(len(data) * 0.6)
    original_byte = data[offset]
    tampered_byte = original_byte ^ 0xFF
    data[offset] = tampered_byte

    with open(file_path, "wb") as f:
        f.write(data)

    print(f"[+] Malicious bit-flip injected at byte offset {offset} (0x{original_byte:02x} -> 0x{tampered_byte:02x})")
    print("[+] File saved with altered forensic state. Run 'ulpf verify' to detect tamper!")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "data/parquet/block_00000.parquet"
    tamper_file(target)
