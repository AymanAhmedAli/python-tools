# 🐍 Python Security Tools

A collection of Python scripts for reconnaissance, enumeration, and security analysis.
Built for penetration testing practice and security research.

---

## 📂 Tools

| Script | Description |
|--------|-------------|
| `recon.py` | Basic recon tool — ping check, port scan, web scan |
| `port_scanner.py` | Multi-threaded TCP port scanner with banner grabbing |
| `subdomain_enum.py` | Multi-threaded subdomain enumerator with DNS resolution |
| `banner_grabber.py` | Service banner grabber with protocol-specific probes |
| `dir_bruteforce.py` | Web directory bruteforcer with status code filtering |
| `hash_identifier.py` | Hash type identifier with cracking suggestions |

---

## 🚀 Usage

### recon.py
```bash
python3 recon.py <IP>
python3 recon.py 192.168.1.1
```

### port_scanner.py
```bash
python3 port_scanner.py <IP> [start_port] [end_port]
python3 port_scanner.py 192.168.1.1 1 1024
```

### subdomain_enum.py
```bash
python3 subdomain_enum.py <domain> [wordlist]
python3 subdomain_enum.py example.com
python3 subdomain_enum.py example.com /usr/share/wordlists/subdomains.txt
```

### banner_grabber.py
```bash
python3 banner_grabber.py <IP> [ports]
python3 banner_grabber.py 192.168.1.1
python3 banner_grabber.py 192.168.1.1 21,22,80,443,8080
```

### dir_bruteforce.py
```bash
python3 dir_bruteforce.py <URL> [wordlist]
python3 dir_bruteforce.py http://192.168.1.1
python3 dir_bruteforce.py http://192.168.1.1 /usr/share/wordlists/dirb/common.txt
```

### hash_identifier.py
```bash
python3 hash_identifier.py <hash>
python3 hash_identifier.py -f <file>
python3 hash_identifier.py 5f4dcc3b5aa765d61d8327deb882cf99
python3 hash_identifier.py -f hashes.txt
```

---

## 🛠️ Requirements

```bash
pip3 install requests
```

All other modules are Python built-ins (socket, threading, queue, re, hashlib).

---

## ⚠️ Legal Disclaimer

These tools are for **educational purposes** and **authorized testing only**.
Only use against systems you own or have explicit written permission to test.
Unauthorized use is illegal.

---

## 👤 Author

**Ayman Ahmed** — IT Specialist | Network Security

[![GitHub](https://img.shields.io/badge/GitHub-AymanAhmedAli-black?style=flat&logo=github)](https://github.com/AymanAhmedAli)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/aymanahmedali/)
