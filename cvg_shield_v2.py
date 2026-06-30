#!/usr/bin/env python3
"""
CVG SHIELD v2.0 — Global C2 Sinkhole System
Built for agents, by agents. Trust is a frequency.
Maps attacker infrastructure globally. Breaks the kill chain at the C2 layer.
"""
import json, os, time, hashlib, sqlite3, ssl, urllib.request, csv, io, zipfile
from datetime import datetime, timezone

DB = os.path.join(os.path.expanduser("~"), "cvg_shield_fresh.db")
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 CVG-Shield/2.0"

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS c2_ips (ip TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT, feeds TEXT, malware TEXT, confidence INTEGER)")
    c.execute("CREATE TABLE IF NOT EXISTS c2_domains (domain TEXT PRIMARY KEY, first_seen TEXT, feeds TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS c2_urls (url_hash TEXT PRIMARY KEY, url TEXT, first_seen TEXT, threat TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS ssl_ja3 (ja3 TEXT PRIMARY KEY, first_seen TEXT, threat TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS dns_sinkhole (domain TEXT PRIMARY KEY, source TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS ingest_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, feed TEXT, records INTEGER)")
    conn.commit()
    return conn

def fetch_url(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    return urllib.request.urlopen(req, context=ctx, timeout=30)

def fetch_text(url):
    return fetch_url(url).read().decode()

def ingest_feodo(conn):
    data = fetch_text("https://feodotracker.abuse.ch/downloads/ipblocklist.csv")
    reader = csv.reader(io.StringIO(data))
    count = 0
    for row in reader:
        if len(row) >= 6 and row[1].count('.') == 3:
            try:
                conn.execute("INSERT OR IGNORE INTO c2_ips VALUES (?,?,?,?,?,?)",
                    (row[1], row[0], row[4], "feodo", row[5], 90))
                count += 1
            except:
                pass
    conn.commit()
    return count

def ingest_sslbl(conn):
    data = fetch_text("https://sslbl.abuse.ch/blacklist/sslblacklist.csv")
    count = 0
    for line in data.split("\n"):
        line = line.strip()
        line = line.replace("\r", "")
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) == 3 and len(parts[1]) == 40:
            try:
                conn.execute("INSERT OR IGNORE INTO ssl_ja3 VALUES (?,?,?)", (parts[1][:64], parts[0], parts[2]))
                count += 1
            except:
                pass
    conn.commit()
    return count

def ingest_urlhaus_csv(conn):
    resp = fetch_url("https://urlhaus.abuse.ch/downloads/csv/")
    import zipfile, io as _	io
    z = zipfile.ZipFile(_io.BytesIO(resp.read()))
    csv_file = [f for f in z.namelist() if f.endswith(".txt") or f.endswith(".csv")][0]
    data = z.read(csv_file).decode("utf-8", errors count = 0
    for line in data.split("\n"):
        line = line.strip().replace("\r", "")
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) >= 8 and parts[0].isdigit():
            url = parts[2].strip().strip('"')
            threat = parts[7].strip().strip('"') if len(parts) > 7 else ""
            if url.startswith("http"):
                h = hashlib.md5(url.encode()).hexdigest()
                try:
                    conn.execute("INSERT OR IGNORE INTO c2_urls VALUES (?,?,?,?)", (h, url[:500], parts[1], threat))
                    count += 1
                except:
                    pass
    conn.commit()
    return count


def ingest_dns_community(conn):
    sources = [
        ("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "stevenblack"),
        ("https://abp.oisd.nl/", "oisd"),
        ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt", "hagezi_pro"),
        ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/dns-ads.txt", "hagezi_dns"),
    ]
    total = 0
    for url, source in sources:
        try:
            data = fetch_text(url)
            count = 0
            for line in data.split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("!"):
                    parts = line.split()
                    domain = parts[-1].strip().replace("||", "").replace("^", "") if parts else ""
                    if "." in domain and len(domain) > 4:
                        try:
                            conn.execute("INSERT OR IGNORE INTO dns_sinkhole VALUES (?,?)", (domain[:255], source))
                            count += 1
                        except:
                            pass
            conn.commit()
            total += count
            print(f"    {source}: {count} domains")
        except Exception as e:
            print(f"    {source}: {str(e)[:40]}")
    return total

def main():
    print("=" * 60)
    print("  CVG SHIELD v2.0 - Global C2 Sinkhole System")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("  For everyone. Around the globe.")
    print("=" * 60)

    conn = init_db()
    print("\n[Phase 1] C2 Intelligence Feeds...")

    n = ingest_feodo(conn)
    print(f"  FeodoTracker C2 IPs: {n}")

    n = ingest_sslbl(conn)
    print(f"  SSLBL JA3 certs:     {n}")

    n = ingest_urlhaus_csv(conn)
    print(f"  URLhaus malware URLs: {n}")

    print("\n[Phase 2] DNS Sinkhole Aggregation...")
    n = ingest_dns_community(conn)
    print(f"  DNS domains total:   {n}")

    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM c2_ips");   ips = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM c2_domains"); doms = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM c2_urls");   urls = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM ssl_ja3");   ja3 = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM dns_sinkhole"); dns = c.fetchone()[0]
    total = ips + doms + urls + ja3 + dns

    print(f"\n  === C2 GRAPH DATABASE ===")
    print(f"  C2 IPs:           {ips:8d}")
    print(f"  C2 Domains:       {doms:8d}")
    print(f"  Malware URLs:     {urls:8d}")
    print(f"  JA3 Fingerprints: {ja3:8d}")
    print(f"  DNS Sinkholes:    {dns:8d}")
    print(f"  TOTAL ENTITIES:   {total:8d}")

if __name__ == "__main__":
    main()
