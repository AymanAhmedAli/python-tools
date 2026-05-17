#!/usr/bin/env python3
# ================================
# recon.py - Basic Recon Tool
# Author: Ayman Ahmed
# Usage: python3 recon.py <IP>
# ================================

import subprocess
import sys
import os

def ping_check(target):
    print(f"[*] Checking if {target} is alive...")
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", target],
        capture_output=True
    )
    if result.returncode == 0:
        print(f"[+] {target} is UP")
        return True
    else:
        print(f"[-] {target} is DOWN")
        return False

def port_scan(target):
    print(f"\n[*] Scanning ports on {target}...")
    subprocess.run(["nmap", "-sV", target])

# MAIN
if len(sys.argv) != 2:
    print("Usage: python3 recon.py <IP>")
    sys.exit(1)

target = sys.argv[1]
print("=" * 40)
print(f"  RECON TOOL - {target}")
print("=" * 40)

def web_scan(target):
    print(f"\n[*] Web scanning {target}...")
    subprocess.run([
        "nmap", "--script=http-title,http-enum",
        "-p", "80,443,8080", target
    ])

if ping_check(target):
    port_scan(target)
    web_scan(target)
