# 🛡️ LabGuard — Network Asset Inventory & Security Audit Tool

**Author:** Zinhar Abdullah  
**Tech Stack:** Python, Flask, Socket Programming, HTML/CSS/JS  
**Purpose:** Cybersecurity project built to simulate real-world engineering lab security processes — asset discovery, port scanning, risk classification, and compliance reporting.

---

## 🎯 What It Does

LabGuard is a Python-based tool that helps cybersecurity professionals **protect engineering lab environments** by:

- **Discovering all active assets** on a network via TCP port scanning
- **Enumerating open services** and fingerprinting them via banner grabbing
- **Classifying risk levels** (CRITICAL / HIGH / MEDIUM / LOW) for each open port
- **Generating audit-ready reports** in JSON, CSV, and plain-text formats
- **Providing actionable remediation steps** for each identified vulnerability
- **Tracking scan history** for compliance audit trails

This directly addresses the core responsibilities of GE Aerospace's Cybersecurity Intern role:
> *"defining, implementing, and maintaining cybersecurity processes within engineering labs... driving secure configurations, asset inventory, access control, and audit practices."*

---

## 🚀 Quick Start

```bash
# Install dependencies
pip install flask python-nmap

# Run demo scan (on permitted test hosts)
python main.py --demo

# Scan specific targets
python main.py --targets 192.168.1.1 192.168.1.5 --range common

# Launch web dashboard
python main.py --web
# Then open http://localhost:5000
```

---

## 📁 Project Structure

```
labguard/
├── scanner.py          # Core scanning engine (TCP probing, banner grabbing, risk classification)
├── app.py              # Flask web dashboard
├── main.py             # CLI entry point
├── templates/
│   └── dashboard.html  # Interactive web UI
└── reports/            # Auto-generated audit reports (JSON, CSV, TXT)
```

---

## 🔍 Key Technical Concepts Used

| Concept | Implementation |
|---------|---------------|
| **TCP Socket Programming** | Custom port prober using `socket.create_connection()` |
| **Concurrent Scanning** | `ThreadPoolExecutor` for parallel port probing |
| **Banner Grabbing** | HTTP HEAD requests + raw socket reads for service fingerprinting |
| **Risk Classification** | Hardcoded CVE-aligned risk map for 20+ services |
| **Compliance Reporting** | Multi-format export (JSON audit log, CSV asset register, TXT report) |
| **REST API** | Flask endpoints for scan control, status polling, report download |
| **Reverse DNS** | `socket.gethostbyaddr()` for hostname resolution |

---

## 📊 Sample Output

```
  ✅ 127.0.0.1 (localhost) — 2 open ports — Risk: MEDIUM
  🟠 scanme.nmap.org — 4 open ports — Risk: HIGH

╔══════════════════════════════════════════════╗
║         AUDIT SUMMARY                        ║
╠══════════════════════════════════════════════╣
║  Hosts Scanned   : 2                         ║
║  Critical Issues : 0                         ║
║  High Issues     : 2                         ║
║  Medium Issues   : 1                         ║
║  Status          : REVIEW REQUIRED           ║
╚══════════════════════════════════════════════╝
```

---

## ⚠️ Ethical Usage

Only scan networks and hosts you own or have **explicit permission** to scan. Unauthorized port scanning may be illegal in your jurisdiction. The demo mode (`--demo`) uses `scanme.nmap.org`, which is Nmap's official test server where scanning is explicitly permitted.

---

## 🔗 Links

- GitHub: [github.com/abdullah9975](https://github.com/abdullah9975)
- LinkedIn: [linkedin.com/in/zinhar-abdullah-bb171b2b5](https://www.linkedin.com/in/zinhar-abdullah-bb171b2b5/)
