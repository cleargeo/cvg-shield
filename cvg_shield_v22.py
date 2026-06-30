#!/usr/bin/env python3
import json, os, time, hashlib, sqlite3, ssl, urllib.request, zipfile, io
from datetime import datetime, timezone

DB = os.path.join(os.path.expanduser("~"), "shield_v22.db")
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = "Mozilla/5.0 (Win64) CVG-Shield/2.2"

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS c2_ips (ip TEXT PRIMARY KEY, first_seen TEXT, feeds TEXT, malware TEXT, confidence INTEGER)")
    c.execute("CREATE TABLE IF NOT EXISTS c2_domains (domain TEXT PRIMARY KEY, first_seen TEXT, feeds TEXT, threat TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS c2_urls (url_hash TEXT PRIMARY KEY, url TEXT, first_seen TEXT, threat TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS ssl_certs (sha1 TEXT PRIMARY KEY, first_seen TEXT, threat TEXT)")
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
    count = 0
    for line in data.split("\n"):
        line = line.strip()
        if not line.startswith("\"") or line.startswith("\"#"):
            continue
        parts = line.split("\",\"")
        cleaned = [p.strip().strip("\"") for p in parts]
        if len(cleaned) >= 5 and cleaned[1].count(".") == 3:
            try:
                conn.execute("INSERT OR IGNORE INTO c2_ips VALUES (?,?,?,?,?)",
                    (cleaned[1], datetime.now(timezone.utc).isoformat(), "feodo", cleaned[5] if len(cleaned)>5 else "", 90))
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
                conn.execute("INSERT OR IGNORE INTO ssl_certs VALUES (?,?,?)", (parts[1], parts[0], parts[2]))
                count += 1
            except:
                pass
    conn.commit()
    return count

def ingest_urlhaus(conn):
    resp = fetch_url("https://urlhaus.abuse.ch/downloads/csv/")
    z = zipfile.ZipFile(io.BytesIO(resp.read()))
    csv_file = [f for f in z.namelist() if f.endswith(".txt") or f.endswith(".csv")][0]
    data = z.read(csv_file).decode("utf-8", errors="replace")
    count = 0
    for line in data.split("\n"):
        line = line.strip().replace("\r", "")
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) >= 8 and parts[0].strip('"').isdigit():
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

def ingest_dns(conn):
    sources = [
        ("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "stevenblack"),
        ("https://abp.oisd.nl/", "oisd"),
        ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt", "hagezi"),
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
                    domain = parts[-1].strip().replace("||","").replace("^","") if parts else ""
                    if "." in domain and len(domain) > 4:
                        try:
                            conn.execute("INSERT OR IGNORE INTO dns_sinkhole VALUES (?,?)", (domain[:255], source))
                            count += 1
                        except:
                            pass
            conn.commit()
            total += count
            print("    " + source + ": " + str(count) + " domains")
        except Exception as e:
            print("    " + source + ": FAILED")
    return total

def main():
    print("=" * 60)
    print("  CVG SHIELD v2.2 - Global C2 Sinkhole System")
    print("  " + datetime.now(timezone.utc).isoformat()[:19] + " UTC")
    print("=" * 60)
    conn = init_db()
    print("")
    print("[Phase 1] C2 Feeds...")
    n = ingest_feodo(conn)
    print("  FeodoTracker C2 IPs:  " + str(n))
    n = ingest_sslbl(conn)
    print("  SSLBL SHA1 certs:     " + str(n))
    n = ingest_urlhaus(conn)
    print("  URLhaus malware URLs: " + str(n))
    print("")
    print("[Phase 2] DNS Sinkhole Aggregation...")
    n = ingest_dns(conn)
    print("  DNS domains total:    " + str(n))
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM c2_ips");      ips = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM c2_domains");  doms = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM c2_urls");     urls = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM ssl_certs");   sha1 = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM dns_sinkhole"); dns = c.fetchone()[0]
    print("")
    print("  C2 IPs:                " + str(ips).rjust(8))
    print("  C2 Domains:            " + str(doms).rjust(8))
    print("  Malware URLs:           " + str(urls).rjust(8))
    print("  SSL SHA1 Fingerprints:  " + str(sha1).rjust(8))
    print("  DNS Sinkholes:         " + str(dns).rjust(8))
    total = ips + doms + urls + sha1 + dns
    print("  GRAND TOTAL:           " + str(total).rjust(8))
    conn.close()
    return total

if __name__ == "__main__":
    main()
