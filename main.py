"""
LabGuard CLI — Command-line interface for LabGuard scanner.
Usage:
    python main.py --targets 192.168.1.1 192.168.1.2 --range common
    python main.py --demo          # Run with demo/localhost targets
    python main.py --web           # Start web dashboard
"""

import argparse
import os
import sys
from datetime import datetime
from scanner import scan_network, export_json, export_csv, export_txt


def cli_scan(targets: list, port_range: str):
    """Run a CLI scan and save all report formats."""
    print("""
  ██╗      █████╗ ██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██║     ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██║     ███████║██████╔╝██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██║     ██╔══██║██╔══██╗██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ███████╗██║  ██║██████╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
  Network Asset Inventory & Security Audit Tool  |  Author: Zinhar Abdullah
    """)

    report = scan_network(targets, port_range)

    os.makedirs("reports", exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join("reports", f"audit_{ts}")

    export_json(report, base + ".json")
    export_csv(report, base + ".csv")
    export_txt(report, base + ".txt")

    s = report["summary"]
    print(f"""
╔══════════════════════════════════════════════╗
║         AUDIT SUMMARY                        ║
╠══════════════════════════════════════════════╣
║  Hosts Scanned   : {s['total_hosts']:<27}║
║  Critical Issues : {s['critical_issues']:<27}║
║  High Issues     : {s['high_issues']:<27}║
║  Medium Issues   : {s['medium_issues']:<27}║
║  Status          : {s['compliance_status']:<27}║
╚══════════════════════════════════════════════╝
    """)


def demo_scan():
    """Run a demonstration scan on publicly available test hosts."""
    demo_targets = [
        "scanme.nmap.org",    # Nmap's official test server (scanning permitted)
        "127.0.0.1",           # Localhost
    ]
    print("[*] Running DEMO scan on permitted public test hosts...")
    print("[*] scanme.nmap.org is Nmap's official test server — scanning is explicitly allowed.\n")
    cli_scan(demo_targets, "common")


def main():
    parser = argparse.ArgumentParser(
        description="LabGuard — Network Asset Inventory & Security Audit Tool"
    )
    parser.add_argument("--targets", nargs="+", help="IP addresses or hostnames to scan")
    parser.add_argument("--range", choices=["common", "extended", "full"],
                        default="common", help="Port scan range")
    parser.add_argument("--demo", action="store_true",
                        help="Run demo scan on permitted test hosts")
    parser.add_argument("--web", action="store_true",
                        help="Start web dashboard on http://localhost:5000")
    args = parser.parse_args()

    if args.web:
        print("[*] Starting LabGuard Web Dashboard...")
        os.system("python app.py")
    elif args.demo:
        demo_scan()
    elif args.targets:
        cli_scan(args.targets, args.range)
    else:
        parser.print_help()
        print("\n  Quick start: python main.py --demo\n")


if __name__ == "__main__":
    main()
