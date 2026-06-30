#!/usr/bin/env python3
"""CVG SHIELD v1.0 — Global Vulnerability Elimination System"""
import json, os, time, hashlib, sqlite3, ssl, urllib.request
from datetime import datetime, timezone

DB = "/tmp/cvg_shield.db"
REPORT_DIR = "/tmp/cvg_shield_reports"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

ASSETS = [
    {"ip": "192.168.1.32", "t": "synology", "role": "QUEEN-12"},
    {"ip": "192.168.1.52", "t": "synology", "role": "QUEEN-20"},
    {"ip": "192.168.1.64", "t": "synology", "role": "QUEEN-30"},
    {"ip": "192.168.1.144", "t": "terramaster", "role": "QUEEN-21"},
    {"ip": "192.168.1.185", "t": "terramaster", "role": "ZNet-Media"},
    {"ip": "192.168.1.7", "t": "truenas", "role": "QUEEN-10"},
    {"ip": "192.168.1.206", "t": "esxi", "role": "ESXi"},
    {"ip": "192.168.1.241", "t": "windows", "role": "DFORGE-11"},
    {"ip": "192.168.1.148", "t": "ilo", "role": "HPiLO"},
    {"ip": "192.168.1.99", "t": "fortiswitch", "role": "FortiSwitch"},
]

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS vulns (id TEXT PRIMARY KEY, source TEXT, cve TEXT, product TEXT, vendor TEXT, severity TEXT, description TEXT, date TEXT, status TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS iocs (id TEXT PRIMARY KEY, type TEXT, value TEXT, source TEXT, threat TEXT, date TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS actions (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, action TEXT, target TEXT, result TEXT)")
    conn.commit()
    return conn

def fetch_json(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "CVG-Shield/1.0"})
    return json.loads(urllib.request.urlopen(req, context=ctx, timeout=timeout).read().decode())

def fetch_text(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 CVG-Shield/1.0"})
    return urllib.request.urlopen(req, context=ctx, timeout=timeout).read().decode()

def main():
    print("=" * 60)
    print("  CVG SHIELD — Global Vulnerability Elimination")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 60)

    conn = init_db()
    c = conn.cursor()

    print("\n[PHASE 1] Ingesting threat feeds...")

    # CISA KEV
    kev_data = fetch_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    vulns = kev_data.get("vulnerabilities", [])
    for v in vulns:
        cve = v.get("cveID", "")
        c.execute("INSERT OR IGNORE INTO vulns VALUES (?,?,?,?,?,?,?,?,?)",
            (cve, "CISA_KEV", cve, v.get("product",""), v.get("vendorProject",""),
             "CRITICAL", v.get("shortDescription","")[:200], datetime.now(timezone.utc).isoformat(), "open"))
    conn.commit()
    print(f"  CISA KEV: {len(vulns)} vulns")

    # Emerging Threats
    et_rules = fetch_text("https://rules.emergingthreats.net/open/suricata/rules/emerging-malware.rules")
    rule_count = sum(1 for line in et_rules.split("\n") if "alert" in line.lower() and line.strip() and not line.startswith("#"))
    print(f"  Emerging Threats: {rule_count} IDS rules")

    # Blocklist.de
    blocklist = fetch_text("https://lists.blocklist.de/lists/all.txt")
    ip_count = sum(1 for line in blocklist.split("\n")[:5000] if line.strip() and not line.startswith("#"))
    print(f"  Blocklist.de: {ip_count} attacker IPs")

    # Phase 2: Match
    print("\n[PHASE 2] Asset-vulnerability matching...")
    matches = []
    c.execute("SELECT cve, product FROM vulns")
    for cve, product in c.fetchall():
        for asset in ASSETS:
            if asset["t"] in product.lower() or asset["role"].lower().split("-")[0] in product.lower():
                matches.append({"asset": asset["role"], "ip": asset["ip"], "cve": cve})

    map_status = "DARK" if len(matches) == 0 else "LIT"
    print(f"\n  MAP STATUS: {map_status}")
    print(f"  Vulnerability matches: {len(matches)}")
    if matches:
        for m in matches[:10]:
            print(f"    {m['asset']:20s} {m['cve']}")

    conn.close()
    return map_status, len(matches)

if __name__ == "__main__":
    main()
