#!/usr/bin/env python3
# ================================
# dir_bruteforce.py - Web Directory Bruteforcer
# Author: Ayman Ahmed
# Usage: python3 dir_bruteforce.py <URL> [wordlist]
# Example: python3 dir_bruteforce.py http://192.168.1.1
# Example: python3 dir_bruteforce.py http://192.168.1.1 /usr/share/wordlists/dirb/common.txt
# ================================

import requests     # HTTP requests for directory discovery
import sys          # Command line arguments and exit
import threading    # Run multiple requests in parallel
import queue        # Thread-safe task queue
from datetime import datetime  # Timestamp for scan start/end

# Disable SSL warnings for HTTPS targets without valid certificates
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================================
# Default wordlist if none provided
# ================================
DEFAULT_WORDLIST = [
    "admin", "login", "dashboard", "panel", "config",
    "backup", "uploads", "images", "assets", "static",
    "api", "v1", "v2", "test", "dev", "staging",
    "robots.txt", "sitemap.xml", ".env", "web.config",
    "phpinfo.php", "info.php", "index.php", "index.html",
    "wp-admin", "wp-login.php", "wp-content", "wordpress",
    "administrator", "phpmyadmin", "mysql", "database",
    "logs", "log", "error.log", "access.log", "debug",
    "shell.php", "cmd.php", "upload.php", "file.php",
    "user", "users", "account", "accounts", "profile",
    "register", "signup", "forgot", "reset", "auth",
    "token", "secret", "private", "hidden", "internal",
    "old", "new", "temp", "tmp", "cache", "cgi-bin",
    "scripts", "includes", "lib", "vendor", "node_modules"
]

# ================================
# Configuration
# ================================
THREAD_COUNT = 20       # Number of concurrent threads (lower = safer)
TIMEOUT = 5             # HTTP request timeout in seconds
found_paths = []        # List to store discovered paths
lock = threading.Lock() # Prevent race conditions between threads

# HTTP status codes that indicate a valid/interesting path
INTERESTING_CODES = [200, 201, 204, 301, 302, 307, 401, 403]

def check_path(base_url, path):
    """
    Send HTTP GET request to base_url/path.
    Record the response if status code is interesting.
    Ignores 404 (not found) responses.
    """
    # Build full URL — avoid double slashes
    url = f"{base_url.rstrip('/')}/{path}"

    try:
        # Send GET request with timeout, follow redirects disabled
        response = requests.get(
            url,
            timeout=TIMEOUT,
            verify=False,       # Skip SSL verification
            allow_redirects=False  # Don't follow redirects automatically
        )

        # Only record interesting status codes (not 404)
        if response.status_code in INTERESTING_CODES:
            # Get content length for additional context
            content_length = len(response.content)

            # Safely store result (thread-safe)
            with lock:
                found_paths.append((path, response.status_code, content_length))

                # Color-code output based on status code
                if response.status_code == 200:
                    status_display = f"[200 OK]      "
                elif response.status_code in [301, 302, 307]:
                    status_display = f"[{response.status_code} REDIRECT]"
                elif response.status_code == 403:
                    status_display = f"[403 FORBIDDEN]"
                elif response.status_code == 401:
                    status_display = f"[401 AUTH REQ] "
                else:
                    status_display = f"[{response.status_code}]          "

                print(f"    [+] {status_display} /{path:<30} ({content_length} bytes)")

    except requests.exceptions.ConnectionError:
        pass  # Target unreachable or connection refused

    except requests.exceptions.Timeout:
        pass  # Request timed out — skip silently

    except requests.exceptions.RequestException:
        pass  # Any other request error — skip silently

def worker(base_url, path_queue):
    """
    Worker function executed by each thread.
    Pulls paths from the queue and checks them one by one.
    """
    while not path_queue.empty():
        try:
            path = path_queue.get_nowait()  # Get next path from queue
            check_path(base_url, path)
            path_queue.task_done()          # Mark task as complete
        except queue.Empty:
            break

def load_wordlist(wordlist_path):
    """
    Load directory names from a wordlist file.
    Returns a list of paths to test.
    """
    try:
        with open(wordlist_path, "r") as f:
            # Read lines, strip whitespace, skip empty and commented lines
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        print(f"[*] Loaded {len(words)} paths from {wordlist_path}")
        return words
    except FileNotFoundError:
        print(f"[-] Wordlist not found: {wordlist_path}")
        print("[*] Using default built-in wordlist")
        return DEFAULT_WORDLIST

def run_bruteforce(base_url, wordlist):
    """
    Main bruteforce orchestrator.
    Validates target, builds queue, spawns threads, prints results.
    """
    print("=" * 65)
    print(f"  DIRECTORY BRUTEFORCER")
    print(f"  Target : {base_url}")
    print(f"  Words  : {len(wordlist)}")
    print(f"  Threads: {THREAD_COUNT}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)

    # Verify target is reachable before starting
    try:
        test = requests.get(base_url, timeout=TIMEOUT, verify=False)
        print(f"[*] Target is reachable — Status: {test.status_code}\n")
    except requests.exceptions.ConnectionError:
        print(f"[-] Cannot reach target: {base_url}")
        print("[-] Make sure the URL is correct and the server is running")
        sys.exit(1)

    # Build queue with all paths to test
    path_queue = queue.Queue()
    for path in wordlist:
        path_queue.put(path)

    # Spawn and start worker threads
    threads = []
    for _ in range(THREAD_COUNT):
        t = threading.Thread(target=worker, args=(base_url, path_queue))
        t.daemon = True   # Thread dies if main program exits
        t.start()
        threads.append(t)

    # Wait for all threads to finish
    for t in threads:
        t.join()

    # Print final summary
    print("\n" + "=" * 65)
    print(f"  BRUTEFORCE COMPLETE")
    print(f"  Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Found   : {len(found_paths)} interesting paths")
    print("=" * 65)

    if found_paths:
        print("\n  SUMMARY:")
        print(f"  {'STATUS':<8} {'PATH':<35} {'SIZE'}")
        print(f"  {'-'*55}")
        for path, status, size in sorted(found_paths, key=lambda x: x[1]):
            print(f"  {status:<8} /{path:<35} {size} bytes")

# ================================
# Entry Point
# ================================
if __name__ == "__main__":
    # Validate command line arguments
    if len(sys.argv) < 2:
        print("Usage: python3 dir_bruteforce.py <URL> [wordlist]")
        print("Example: python3 dir_bruteforce.py http://192.168.1.1")
        print("Example: python3 dir_bruteforce.py http://192.168.1.1 /usr/share/wordlists/dirb/common.txt")
        sys.exit(1)

    base_url = sys.argv[1]  # Target base URL

    # Add http:// if no scheme provided
    if not base_url.startswith(("http://", "https://")):
        base_url = "http://" + base_url
        print(f"[*] No scheme provided — using: {base_url}")

    # Load wordlist from file or use default
    if len(sys.argv) > 2:
        wordlist = load_wordlist(sys.argv[2])
    else:
        print(f"[*] No wordlist provided — using built-in wordlist ({len(DEFAULT_WORDLIST)} entries)")
        wordlist = DEFAULT_WORDLIST

    run_bruteforce(base_url, wordlist)
