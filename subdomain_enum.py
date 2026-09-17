#!/usr/bin/env python3
# ================================
# subdomain_enum.py - Subdomain Enumerator
# Author: Ayman Ahmed
# Usage: python3 subdomain_enum.py <domain> [wordlist]
# Example: python3 subdomain_enum.py example.com
# ================================

import socket       # DNS resolution for each subdomain
import sys          # Command line arguments and exit
import threading    # Run multiple lookups in parallel
import queue        # Thread-safe task queue
from datetime import datetime  # Timestamp for scan start/end

# ================================
# Default wordlist if none provided
# ================================
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "test",
    "staging", "portal", "vpn", "remote", "blog", "shop",
    "app", "secure", "login", "dashboard", "support", "cdn",
    "static", "assets", "images", "beta", "demo", "internal",
    "intranet", "exchange", "smtp", "pop", "imap", "ns1", "ns2",
    "mx", "webmail", "cloud", "backup", "monitor", "git", "jenkins"
]

# ================================
# Configuration
# ================================
THREAD_COUNT = 50       # Number of concurrent threads
found_subdomains = []   # List to store discovered subdomains
lock = threading.Lock() # Prevent race conditions between threads

def resolve_subdomain(domain, subdomain):
    """
    Attempt DNS resolution for a subdomain.
    If resolved successfully -> subdomain exists.
    If DNS lookup fails -> subdomain does not exist.
    """
    target = f"{subdomain}.{domain}"  # Build full subdomain FQDN
    try:
        # Perform DNS A record lookup
        ip = socket.gethostbyname(target)

        # Safely append to shared list (thread-safe)
        with lock:
            found_subdomains.append((target, ip))
            print(f"    [+] Found: {target:<40} → {ip}")

    except socket.gaierror:
        pass  # DNS resolution failed — subdomain does not exist

def worker(domain, subdomain_queue):
    """
    Worker function executed by each thread.
    Pulls subdomains from the queue and resolves them.
    """
    while not subdomain_queue.empty():
        try:
            subdomain = subdomain_queue.get_nowait()  # Get next subdomain
            resolve_subdomain(domain, subdomain)
            subdomain_queue.task_done()               # Mark task as complete
        except queue.Empty:
            break

def load_wordlist(wordlist_path):
    """
    Load subdomains from a file.
    Returns a list of subdomain prefixes to test.
    """
    try:
        with open(wordlist_path, "r") as f:
            # Read lines, strip whitespace, skip empty lines and comments
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        print(f"[*] Loaded {len(words)} subdomains from {wordlist_path}")
        return words
    except FileNotFoundError:
        print(f"[-] Wordlist not found: {wordlist_path}")
        print("[*] Using default built-in wordlist")
        return DEFAULT_WORDLIST

def run_enum(domain, wordlist):
    """
    Main enumeration orchestrator.
    Builds the queue, spawns threads, and prints results.
    """
    print("=" * 55)
    print(f"  SUBDOMAIN ENUMERATOR")
    print(f"  Domain : {domain}")
    print(f"  Words  : {len(wordlist)}")
    print(f"  Threads: {THREAD_COUNT}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 55)

    # Build queue with all subdomains to test
    subdomain_queue = queue.Queue()
    for word in wordlist:
        subdomain_queue.put(word)

    # Spawn and start worker threads
    threads = []
    for _ in range(THREAD_COUNT):
        t = threading.Thread(target=worker, args=(domain, subdomain_queue))
        t.daemon = True   # Thread dies if main program exits
        t.start()
        threads.append(t)

    # Wait for all threads to finish
    for t in threads:
        t.join()

    # Print final summary
    print("\n" + "=" * 55)
    print(f"  ENUMERATION COMPLETE")
    print(f"  Finished : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Found    : {len(found_subdomains)} subdomains")
    print("=" * 55)

    if found_subdomains:
        print("\n  SUMMARY:")
        print(f"  {'SUBDOMAIN':<42} {'IP'}")
        print(f"  {'-'*55}")
        for subdomain, ip in sorted(found_subdomains):
            print(f"  {subdomain:<42} {ip}")

# ================================
# Entry Point
# ================================
if __name__ == "__main__":
    # Validate command line arguments
    if len(sys.argv) < 2:
        print("Usage: python3 subdomain_enum.py <domain> [wordlist]")
        print("Example: python3 subdomain_enum.py example.com")
        print("Example: python3 subdomain_enum.py example.com /usr/share/wordlists/subdomains.txt")
        sys.exit(1)

    domain = sys.argv[1]  # Target domain

    # Load wordlist from file or use default
    if len(sys.argv) > 2:
        wordlist = load_wordlist(sys.argv[2])
    else:
        print(f"[*] No wordlist provided — using built-in wordlist ({len(DEFAULT_WORDLIST)} entries)")
        wordlist = DEFAULT_WORDLIST

    run_enum(domain, wordlist)
