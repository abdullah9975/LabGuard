"""
LabGuard - Network Asset Inventory & Security Audit Tool
Author: Zinhar Abdullah
Description: Scans lab networks to discover assets, enumerate open ports,
             flag insecure services, and generate audit-ready reports.
             Aligned with cybersecurity lab compliance requirements.
"""

import socket
import json
import csv
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Risk Classification ───────────────────────────────────────────────────────
# Maps common port numbers to service names and risk levels
PORT_RISK_MAP = {
    21:   ("FTP",         "HIGH",   "Unencrypted file transfer — disable or replace with SFTP"),
    22:   ("SSH",         "LOW",    "Secure shell — verify key-based auth is enforced"),
    23:   ("Telnet",      "CRITICAL","Unencrypted remote access — immediate remediation required"),
    25:   ("SMTP",        "MEDIUM", "Mail transfer — ensure relay is restricted"),
    53:   ("DNS",         "LOW",    "DNS service — verify it is not open resolver"),
    80:   ("HTTP",        "MEDIUM", "Unencrypted web — redirect to HTTPS"),
    110:  ("POP3",        "HIGH",   "Unencrypted mail retrieval — disable or use TLS"),
    135:  ("RPC",         "HIGH",   "Windows RPC — common attack vector, restrict access"),
    139:  ("NetBIOS",     "HIGH",   "Legacy file sharing — disable if unused"),
    143:  ("IMAP",        "MEDIUM", "Email protocol — enforce TLS"),
    443:  ("HTTPS",       "LOW",    "Encrypted web — verify certificate validity"),
    445:  ("SMB",         "HIGH",   "File sharing — patch regularly, restrict externally"),
    3306: ("MySQL",       "HIGH",   "Database exposed — bind to localhost only"),
    3389: ("RDP",         "HIGH",   "Remote desktop — restrict via firewall, enforce MFA"),
    5432: ("PostgreSQL",  "HIGH",   "Database exposed — bind to localhost only"),
    5900: ("VNC",         "CRITICAL","Remote desktop without encryption — disable or tunnel via SSH"),
    6379: ("Redis",       "CRITICAL","In-memory DB — often unauthenticated by default"),
    8080: ("HTTP-Alt",    "MEDIUM", "Alternative web port — verify authentication"),
    8443: ("HTTPS-Alt",   "LOW",    "Alternative HTTPS — verify certificate"),
    27017:("MongoDB",     "CRITICAL","NoSQL database — often exposed without auth"),
}

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ── Core Scanner ──────────────────────────────────────────────────────────────

def resolve_hostname(ip: str) -> str:
    """Attempt reverse DNS lookup for an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "Unknown"


def probe_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    """
    Attempt a TCP connection to determine if a port is open.
    Returns True if port is open, False otherwise.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    """
    Attempt to grab a service banner for fingerprinting.
    Returns banner string or empty string on failure.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = s.recv(256).decode(errors="ignore").strip()
            # Return first non-empty line
            for line in data.splitlines():
                if line.strip():
                    return line.strip()[:80]
    except Exception:
        pass
    return ""


def scan_host(ip: str, ports: list, timeout: float = 0.5) -> dict:
    """
    Scan a single host: resolve hostname, probe ports, grab banners.
    Returns a structured asset record.
    """
    hostname = resolve_hostname(ip)
    open_ports = []
    risk_flags = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(probe_port, ip, p, timeout): p for p in ports}
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                service, risk, recommendation = PORT_RISK_MAP.get(
                    port, (f"Unknown-{port}", "INFO", "Unknown service — investigate")
                )
                banner = grab_banner(ip, port)
                open_ports.append({
                    "port": port,
                    "service": service,
                    "risk": risk,
                    "recommendation": recommendation,
                    "banner": banner
                })
                risk_flags.append(risk)

    # Sort ports by risk severity
    open_ports.sort(key=lambda x: (RISK_ORDER.get(x["risk"], 99), x["port"]))

    # Overall host risk = highest individual port risk
    overall_risk = "SECURE"
    if risk_flags:
        overall_risk = min(risk_flags, key=lambda r: RISK_ORDER.get(r, 99))

    return {
        "ip": ip,
        "hostname": hostname,
        "status": "UP" if open_ports else "UP (no flagged ports)",
        "open_ports": open_ports,
        "overall_risk": overall_risk,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def scan_network(targets: list, port_range: str = "common") -> dict:
    """
    Scan a list of IP addresses or hostnames.
    port_range: 'common' | 'extended' | 'full'
    Returns complete audit report dictionary.
    """
    port_sets = {
        "common":   list(PORT_RISK_MAP.keys()),
        "extended": list(PORT_RISK_MAP.keys()) + [
            8888, 9200, 9300, 2181, 1521, 5984, 6443, 2379, 4444, 1433
        ],
        "full":     list(range(1, 1025))
    }
    ports = port_sets.get(port_range, port_sets["common"])

    results = []
    print(f"[*] Starting LabGuard scan on {len(targets)} target(s), {len(ports)} ports each...")

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_host, ip, ports): ip for ip in targets}
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            risk_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                         "LOW": "🟢", "SECURE": "✅", "INFO": "🔵"}.get(result["overall_risk"], "⚪")
            print(f"  {risk_icon} {result['ip']} ({result['hostname']}) — "
                  f"{len(result['open_ports'])} open ports — Risk: {result['overall_risk']}")

    # Sort results by risk
    results.sort(key=lambda x: RISK_ORDER.get(x["overall_risk"], 99))

    # Summary statistics
    total_critical = sum(1 for h in results for p in h["open_ports"] if p["risk"] == "CRITICAL")
    total_high = sum(1 for h in results for p in h["open_ports"] if p["risk"] == "HIGH")
    total_medium = sum(1 for h in results for p in h["open_ports"] if p["risk"] == "MEDIUM")

    report = {
        "scan_metadata": {
            "tool": "LabGuard v1.0",
            "author": "Zinhar Abdullah",
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "targets_scanned": len(targets),
            "port_range": port_range,
            "ports_checked": len(ports)
        },
        "summary": {
            "total_hosts": len(results),
            "critical_issues": total_critical,
            "high_issues": total_high,
            "medium_issues": total_medium,
            "compliance_status": "NON-COMPLIANT" if total_critical > 0 else
                                 "REVIEW REQUIRED" if total_high > 0 else "COMPLIANT"
        },
        "hosts": results
    }
    return report


# ── Export Functions ──────────────────────────────────────────────────────────

def export_json(report: dict, filepath: str):
    """Export full audit report as JSON."""
    with open(filepath, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] JSON report saved: {filepath}")


def export_csv(report: dict, filepath: str):
    """Export asset inventory as CSV (asset register format)."""
    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP Address", "Hostname", "Port", "Service",
                          "Risk Level", "Banner", "Recommendation", "Scan Time"])
        for host in report["hosts"]:
            if host["open_ports"]:
                for p in host["open_ports"]:
                    writer.writerow([
                        host["ip"], host["hostname"],
                        p["port"], p["service"], p["risk"],
                        p.get("banner", ""), p["recommendation"], host["scan_time"]
                    ])
            else:
                writer.writerow([host["ip"], host["hostname"],
                                  "-", "-", "SECURE", "-", "No flagged services detected", host["scan_time"]])
    print(f"[+] CSV asset register saved: {filepath}")


def export_txt(report: dict, filepath: str):
    """Export human-readable audit report as plain text."""
    meta = report["scan_metadata"]
    summ = report["summary"]
    lines = [
        "=" * 70,
        "         LABGUARD — NETWORK ASSET SECURITY AUDIT REPORT",
        "=" * 70,
        f"  Tool          : {meta['tool']}",
        f"  Author        : {meta['author']}",
        f"  Scan Date     : {meta['scan_date']}",
        f"  Targets       : {meta['targets_scanned']}",
        f"  Ports Checked : {meta['ports_checked']}",
        "=" * 70,
        "EXECUTIVE SUMMARY",
        "-" * 70,
        f"  Total Hosts Scanned  : {summ['total_hosts']}",
        f"  Critical Issues      : {summ['critical_issues']}",
        f"  High Issues          : {summ['high_issues']}",
        f"  Medium Issues        : {summ['medium_issues']}",
        f"  Compliance Status    : {summ['compliance_status']}",
        "=" * 70,
        "DETAILED HOST FINDINGS",
        "-" * 70,
    ]
    for host in report["hosts"]:
        lines.append(f"\n  HOST: {host['ip']}  ({host['hostname']})")
        lines.append(f"  Overall Risk: {host['overall_risk']}")
        if host["open_ports"]:
            lines.append(f"  {'PORT':<8} {'SERVICE':<15} {'RISK':<10} {'RECOMMENDATION'}")
            lines.append(f"  {'-'*60}")
            for p in host["open_ports"]:
                lines.append(f"  {p['port']:<8} {p['service']:<15} {p['risk']:<10} {p['recommendation'][:45]}")
                if p.get("banner"):
                    lines.append(f"  {'':8} Banner: {p['banner']}")
        else:
            lines.append("  No flagged services detected.")
    lines += ["", "=" * 70, "END OF REPORT", "=" * 70]
    with open(filepath, "w") as f:
        f.write("\n".join(lines))
    print(f"[+] Text report saved: {filepath}")
