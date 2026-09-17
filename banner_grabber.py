#!/usr/bin/env python3
# ================================
# banner_grabber.py - Service Banner Grabber
# Author: Ayman Ahmed
# Usage: python3 banner_grabber.py <IP> [ports]
# Example: python3 banner_grabber.py 192.168.1.1
# Example: python3 banner_grabber.py 192.168.1.1 21,22,80,443,8080
# ================================

import socket       # Network connections for banner grabbing
import sys          # Command line arguments and exit
import threading    # Run multiple grabs in parallel
from datetime import datetime  # Timestamp for scan start/end

# ================================
# Default ports to check if none specified
# ================================
DEFAULT_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    6379,  # Redis
    8080,  # HTTP Alternate
    8443,  # HTTPS Alternate
    9200,  # Elasticsearch
    27017  # MongoDB
]

# ================================
# Probes to send per service type
# These trigger the service to reveal its banner
# ================================
PROBES = {
    80:   b"HEAD / HTTP/1.0\r\n\r\n",       # HTTP
    8080: b"HEAD / HTTP/1.0\r\n\r\n",       # HTTP Alt
    8443: b"HEAD / HTTP/1.0\r\n\r\n",       # HTTPS Alt
    443:  b"HEAD / HTTP/1.0\r\n\r\n",       # HTTPS
    21:   b"",                               # FTP sends banner on connect
    22:   b"",                               # SSH sends banner on connect
    25:   b"EHLO test\r\n",                 # SMTP
    110:  b"",                               # POP3 sends banner on connect
    143:  b"",                               # IMAP sends banner on connect
    3306: b"",                               # MySQL sends banner on connect
    6379: b"INFO\r\n",                       # Redis
    9200: b"GET / HTTP/1.0\r\n\r\n",        # Elasticsearch
}

TIMEOUT = 3         # Connection timeout in seconds
results = []        # List to store grabbed banners
lock = threading.Lock()  # Prevent race conditions between threads

def grab_banner(ip, port):
    """
    Connect to a port and grab the service banner.
    Sends a probe if needed, then reads the response.
    Returns the banner string or None if failed.
    """
    try:
        # Create TCP socket and set timeout
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)

        # Attempt connection to target port
        sock.connect((ip, port))

        # Send probe if defined for this port
        probe = PROBES.get(port, b"")
        if probe:
            sock.send(probe)  # Send service-specific probe

        # Receive banner response (up to 1024 bytes)
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()

        # Clean up banner — keep first 2 lines only
        banner_lines = [line.strip() for line in banner.split("\n") if line.strip()]
        clean_banner = " | ".join(banner_lines[:2])  # Join first 2 lines

        sock.close()  # Close connection after grabbing

        # Safely store result (thread-safe)
        with lock:
            results.append((port, "OPEN", clean_banner))
            print(f"    [+] Port {port:5d}  OPEN  → {clean_banner[:60]}")

    except socket.timeout:
        # Connection timed out — port may be filtered
        with lock:
            results.append((port, "FILTERED", "Connection timed out"))

    except ConnectionRefusedError:
        # Port is closed — connection actively rejected
        pass

    except Exception as e:
        # Any other error — log it
        with lock:
            results.append((port, "ERROR", str(e)[:50]))

def run_grabber(ip, ports):
    """
    Main banner grabber orchestrator.
    Spawns threads for each port and prints results.
    """
    print("=" * 65)
    print(f"  BANNER GRABBER")
    print(f"  Target : {ip}")
    print(f"  Ports  : {len(ports)} ports")
    print(f"  Timeout: {TIMEOUT}s per port")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)

    # Spawn one thread per port for parallel grabbing
    threads = []
    for port in ports:
        t = threading.Thread(target=grab_banner, args=(ip, port))
        t.daemon = True   # Thread dies if main program exits
        t.start()
        threads.append(t)

    # Wait for all threads to complete
    for t in threads:
        t.join()

    # Filter only open ports for summary
    open_results = [(p, s, b) for p, s, b in results if s == "OPEN"]

    # Print final summary
    print("\n" + "=" * 65)
    print(f"  GRAB COMPLETE")
    print(f"  Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Open   : {len(open_results)} ports")
    print("=" * 65)

    if open_results:
        print("\n  SUMMARY:")
        print(f"  {'PORT':<8} {'STATUS':<10} {'BANNER'}")
        print(f"  {'-'*60}")
        for port, status, banner in sorted(open_results):
            print(f"  {port:<8} {status:<10} {banner[:45]}")

# ================================
# Entry Point
# ================================
if __name__ == "__main__":
    # Validate command line arguments
    if len(sys.argv) < 2:
        print("Usage: python3 banner_grabber.py <IP> [ports]")
        print("Example: python3 banner_grabber.py 192.168.1.1")
        print("Example: python3 banner_grabber.py 192.168.1.1 21,22,80,443,8080")
        sys.exit(1)

    ip = sys.argv[1]  # Target IP address

    # Parse port list or use defaults
    if len(sys.argv) > 2:
        try:
            # Parse comma-separated port list from argument
            ports = [int(p.strip()) for p in sys.argv[2].split(",")]
        except ValueError:
            print("[-] Invalid port format. Use: 21,22,80,443")
            sys.exit(1)
    else:
        print(f"[*] No ports specified — using default list ({len(DEFAULT_PORTS)} ports)")
        ports = DEFAULT_PORTS

    # Validate IP address format
    try:
        socket.inet_aton(ip)
    except socket.error:
        print(f"[-] Invalid IP address: {ip}")
        sys.exit(1)

    run_grabber(ip, ports)
