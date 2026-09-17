#!/usr/bin/env python3
# ================================
# port_scanner.py - Custom TCP Port Scanner
# Author: Ayman Ahmed
# Usage: python3 port_scanner.py <IP> [start_port] [end_port]
# Example: python3 port_scanner.py 192.168.1.1 1 1024
# ================================

import socket      # Network connections and socket operations
import sys         # Command line arguments and exit
import threading   # Run multiple scans in parallel
import queue       # Thread-safe task queue
from datetime import datetime  # Timestamp for scan start/end

# ================================
# Configuration
# ================================
THREAD_COUNT = 100      # Number of concurrent threads
TIMEOUT = 0.5           # Connection timeout in seconds
open_ports = []         # List to store discovered open ports
lock = threading.Lock() # Prevent race conditions between threads

def scan_port(ip, port):
    """
    Attempt a TCP connection to a specific port.
    If connection succeeds -> port is open.
    If connection fails -> port is closed or filtered.
    """
    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)  # Set connection timeout

        # Attempt to connect to the target port
        result = sock.connect_ex((ip, port))

        if result == 0:  # 0 = successful connection = port is open
            # Try banner grabbing to identify the running service
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode().strip()
                banner = banner.split("\n")[0]  # Keep first line only
            except:
                banner = "No banner"

            # Safely append to shared list (thread-safe)
            with lock:
                open_ports.append((port, banner))
                print(f"    [+] Port {port:5d}/tcp  OPEN  — {banner[:50]}")

        sock.close()  # Close the connection

    except socket.error:
        pass  # Ignore expected errors (closed/filtered ports)

def worker(ip, port_queue):
    """
    Worker function executed by each thread.
    Pulls ports from the queue and scans them one by one.
    """
    while not port_queue.empty():
        try:
            port = port_queue.get_nowait()  # Get next port from queue
            scan_port(ip, port)
            port_queue.task_done()          # Mark task as complete
        except queue.Empty:
            break

def run_scan(ip, start_port, end_port):
    """
    Main scan orchestrator.
    Builds the port queue, spawns threads, and prints results.
    """
    print("=" * 55)
    print(f"  PORT SCANNER")
    print(f"  Target : {ip}")
    print(f"  Range  : {start_port} - {end_port}")
    print(f"  Threads: {THREAD_COUNT}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 55)

    # Build the queue with all ports in the specified range
    port_queue = queue.Queue()
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    # Spawn and start worker threads
    threads = []
    for _ in range(THREAD_COUNT):
        t = threading.Thread(target=worker, args=(ip, port_queue))
        t.daemon = True   # Thread dies if main program exits
        t.start()
        threads.append(t)

    # Wait for all threads to finish
    for t in threads:
        t.join()

    # Print final summary
    print("\n" + "=" * 55)
    print(f"  SCAN COMPLETE")
    print(f"  Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Open Ports Found: {len(open_ports)}")
    print("=" * 55)

    if open_ports:
        print("\n  SUMMARY:")
        print(f"  {'PORT':<10} {'BANNER'}")
        print(f"  {'-'*50}")
        for port, banner in sorted(open_ports):
            print(f"  {port:<10} {banner[:45]}")

# ================================
# Entry Point
# ================================
if __name__ == "__main__":
    # Validate command line arguments
    if len(sys.argv) < 2:
        print("Usage: python3 port_scanner.py <IP> [start_port] [end_port]")
        print("Example: python3 port_scanner.py 192.168.1.1 1 1024")
        sys.exit(1)

    ip = sys.argv[1]                                               # Target IP
    start_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1    # First port
    end_port = int(sys.argv[3]) if len(sys.argv) > 3 else 1024   # Last port

    # Validate IP address format
    try:
        socket.inet_aton(ip)
    except socket.error:
        print(f"[-] Invalid IP address: {ip}")
        sys.exit(1)

    # Validate port range boundaries
    if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
        print("[-] Port range must be between 1 and 65535")
        sys.exit(1)

    run_scan(ip, start_port, end_port)
