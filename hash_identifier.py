#!/usr/bin/env python3
# ================================
# hash_identifier.py - Hash Type Identifier
# Author: Ayman Ahmed
# Usage: python3 hash_identifier.py <hash>
#        python3 hash_identifier.py -f <file>
# Example: python3 hash_identifier.py 5f4dcc3b5aa765d61d8327deb882cf99
# ================================

import re       # Regular expressions for hash pattern matching
import sys      # Command line arguments and exit
import hashlib  # For hash verification examples

# ================================
# Hash patterns database
# Each entry: (name, regex_pattern, length, description)
# ================================
HASH_PATTERNS = [
    # ===== MD5 Family =====
    (
        "MD5",
        r"^[a-f0-9]{32}$",
        32,
        "MD5 — 128-bit hash. Commonly used for passwords (INSECURE). Crackable with GPU."
    ),
    (
        "MD5 (Unix)",
        r"^\$1\$.{8}\$.{22}$",
        None,
        "MD5-Crypt — Unix/Linux password format. Format: $1$salt$hash"
    ),
    (
        "MD4",
        r"^[a-f0-9]{32}$",
        32,
        "MD4 — Predecessor to MD5. Used in NTLM authentication (Windows)."
    ),

    # ===== SHA Family =====
    (
        "SHA-1",
        r"^[a-f0-9]{40}$",
        40,
        "SHA-1 — 160-bit hash. Used in old SSL/TLS. Deprecated and insecure."
    ),
    (
        "SHA-256",
        r"^[a-f0-9]{64}$",
        64,
        "SHA-256 — 256-bit hash. Part of SHA-2 family. Widely used and secure."
    ),
    (
        "SHA-512",
        r"^[a-f0-9]{128}$",
        128,
        "SHA-512 — 512-bit hash. Strongest SHA-2 variant. Very secure."
    ),
    (
        "SHA-384",
        r"^[a-f0-9]{96}$",
        96,
        "SHA-384 — 384-bit hash. Part of SHA-2 family."
    ),

    # ===== Unix/Linux Password Formats =====
    (
        "SHA-512 (Unix)",
        r"^\$6\$.{8,16}\$.{86}$",
        None,
        "SHA-512-Crypt — Modern Linux password hash. Format: $6$salt$hash"
    ),
    (
        "SHA-256 (Unix)",
        r"^\$5\$.{8,16}\$.{43}$",
        None,
        "SHA-256-Crypt — Linux password hash. Format: $5$salt$hash"
    ),
    (
        "bcrypt",
        r"^\$2[ayb]\$.{56}$",
        None,
        "bcrypt — Adaptive password hashing. Resistant to brute force. Very secure."
    ),

    # ===== Windows Password Formats =====
    (
        "NTLM",
        r"^[a-f0-9]{32}$",
        32,
        "NTLM — Windows password hash. Used in Active Directory authentication."
    ),
    (
        "NTHash (NetNTLMv2)",
        r"^[a-f0-9]{32}:[a-f0-9]{32}$",
        None,
        "NetNTLMv2 — Windows challenge-response hash. Captured via Responder."
    ),
    (
        "LM Hash",
        r"^[a-f0-9]{32}:[a-f0-9]{32}$",
        None,
        "LM Hash — Legacy Windows hash. Extremely weak. Split into two 7-char parts."
    ),

    # ===== Database / Web Formats =====
    (
        "MySQL (old)",
        r"^[a-f0-9]{16}$",
        16,
        "MySQL v3.x password hash. Very weak — 16 hex chars."
    ),
    (
        "MySQL (SHA1)",
        r"^\*[A-F0-9]{40}$",
        41,
        "MySQL v4.1+ password hash. Format: *<SHA1(SHA1(password))>"
    ),
    (
        "Django (SHA1)",
        r"^sha1\$.+\$[a-f0-9]{40}$",
        None,
        "Django SHA1 password hash. Format: sha1$salt$hash"
    ),
    (
        "Django (bcrypt)",
        r"^bcrypt\$\$2[ayb]\$.{56}$",
        None,
        "Django bcrypt password hash."
    ),
    (
        "Wordpress",
        r"^\$P\$.{31}$",
        None,
        "WordPress/phpBB3 password hash. Based on phpass framework."
    ),

    # ===== Other Formats =====
    (
        "Base64",
        r"^[A-Za-z0-9+/]{20,}={0,2}$",
        None,
        "Base64 encoded string. Not a hash — encoding, not encryption."
    ),
    (
        "CRC32",
        r"^[a-f0-9]{8}$",
        8,
        "CRC32 — 32-bit checksum. Not a cryptographic hash."
    ),
    (
        "Kerberos 5 (etype 23)",
        r"^\$krb5asrep\$23\$.+",
        None,
        "Kerberos AS-REP hash. Captured during AS-REP Roasting attack."
    ),
    (
        "Kerberos 5 TGS (etype 23)",
        r"^\$krb5tgs\$23\$.+",
        None,
        "Kerberos TGS hash. Captured during Kerberoasting attack."
    ),
]

def identify_hash(hash_string):
    """
    Analyze a hash string and return all possible matches.
    Matches are based on length and regex pattern.
    Returns a list of (name, description) tuples.
    """
    hash_string = hash_string.strip()   # Remove leading/trailing whitespace
    hash_lower = hash_string.lower()    # Normalize to lowercase for matching
    hash_length = len(hash_string)      # Get hash length for filtering

    matches = []  # Store all matching hash types

    for name, pattern, expected_length, description in HASH_PATTERNS:
        # Skip if length doesn't match (when length is specified)
        if expected_length and hash_length != expected_length:
            continue

        # Check if hash matches the regex pattern
        if re.match(pattern, hash_lower, re.IGNORECASE):
            matches.append((name, description))

    return matches

def analyze_hash(hash_string):
    """
    Full hash analysis function.
    Prints detailed information about the identified hash.
    """
    hash_string = hash_string.strip()

    print("=" * 65)
    print(f"  HASH IDENTIFIER")
    print(f"  Input  : {hash_string[:60]}{'...' if len(hash_string) > 60 else ''}")
    print(f"  Length : {len(hash_string)} characters")
    print("=" * 65)

    # Check if input contains only valid hash characters
    if re.match(r'^[a-f0-9]+$', hash_string.lower()):
        print(f"  Charset: Hexadecimal (0-9, a-f)")
    elif re.match(r'^[A-Za-z0-9+/=]+$', hash_string):
        print(f"  Charset: Base64 (A-Z, a-z, 0-9, +, /, =)")
    else:
        print(f"  Charset: Mixed/Special characters")

    print()

    # Run identification
    matches = identify_hash(hash_string)

    if matches:
        print(f"  [+] Possible hash types ({len(matches)} match{'es' if len(matches) > 1 else ''}):\n")
        for i, (name, description) in enumerate(matches, 1):
            print(f"  {i}. {name}")
            print(f"     {description}")
            print()
    else:
        print("  [-] No matching hash type found.")
        print("  [*] Try checking the hash format manually.")

    # Suggest cracking tools based on hash type
    print("=" * 65)
    print("  CRACKING SUGGESTIONS:")
    print("=" * 65)

    hash_lower = hash_string.lower()
    hash_len = len(hash_string)

    if hash_len == 32 and re.match(r'^[a-f0-9]{32}$', hash_lower):
        # Could be MD5 or NTLM
        print("  Hashcat mode 0  (MD5):  hashcat -m 0 hash.txt wordlist.txt")
        print("  Hashcat mode 1000 (NTLM): hashcat -m 1000 hash.txt wordlist.txt")
        print("  John:  john --format=raw-md5 hash.txt")
        print("  John:  john --format=nt hash.txt")

    elif hash_len == 40:
        print("  Hashcat mode 100 (SHA1): hashcat -m 100 hash.txt wordlist.txt")
        print("  John: john --format=raw-sha1 hash.txt")

    elif hash_len == 64:
        print("  Hashcat mode 1400 (SHA256): hashcat -m 1400 hash.txt wordlist.txt")
        print("  John: john --format=raw-sha256 hash.txt")

    elif hash_len == 128:
        print("  Hashcat mode 1700 (SHA512): hashcat -m 1700 hash.txt wordlist.txt")
        print("  John: john --format=raw-sha512 hash.txt")

    elif hash_string.startswith("$6$"):
        print("  Hashcat mode 1800 (SHA512-Crypt): hashcat -m 1800 hash.txt wordlist.txt")
        print("  John: john --format=sha512crypt hash.txt")

    elif hash_string.startswith("$2"):
        print("  Hashcat mode 3200 (bcrypt): hashcat -m 3200 hash.txt wordlist.txt")
        print("  John: john --format=bcrypt hash.txt")

    elif hash_string.startswith("$krb5tgs"):
        print("  Hashcat mode 13100 (Kerberoast): hashcat -m 13100 hash.txt wordlist.txt")
        print("  John: john --format=krb5tgs hash.txt")

    elif hash_string.startswith("$krb5asrep"):
        print("  Hashcat mode 18200 (AS-REP Roast): hashcat -m 18200 hash.txt wordlist.txt")
        print("  John: john --format=krb5asrep hash.txt")

    else:
        print("  hashcat --identify hash.txt")
        print("  john --list=formats | grep -i <type>")

    print("=" * 65)

def process_file(filepath):
    """
    Process a file containing multiple hashes (one per line).
    Identifies each hash and prints results.
    """
    try:
        with open(filepath, "r") as f:
            hashes = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        print(f"[*] Processing {len(hashes)} hashes from {filepath}\n")

        for i, hash_string in enumerate(hashes, 1):
            print(f"\n[Hash {i}/{len(hashes)}]")
            analyze_hash(hash_string)

    except FileNotFoundError:
        print(f"[-] File not found: {filepath}")
        sys.exit(1)

# ================================
# Entry Point
# ================================
if __name__ == "__main__":
    # Validate command line arguments
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 hash_identifier.py <hash>")
        print("  python3 hash_identifier.py -f <file>")
        print()
        print("Examples:")
        print("  python3 hash_identifier.py 5f4dcc3b5aa765d61d8327deb882cf99")
        print("  python3 hash_identifier.py -f hashes.txt")
        sys.exit(1)

    # Check if file mode (-f flag)
    if sys.argv[1] == "-f":
        if len(sys.argv) < 3:
            print("[-] Please provide a file path: python3 hash_identifier.py -f <file>")
            sys.exit(1)
        process_file(sys.argv[2])
    else:
        # Single hash mode
        analyze_hash(sys.argv[1])
