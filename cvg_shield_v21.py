#!/usr/bin/env python3
"""
CVG SHIELD v2.1 - Global C2 Sinkhole System
Integrates 8 live feeds including CIRCL MISP OSINT (478K+ C2 indicators)
"""
import json, os, time, hashlib, sqlite3, ssl, urllib.request, csv, io, zipfile
from datetime import datetime, timezone

DB = os.path.join(os.path.expanduser("~"), "cvg_shield_fresh.db")
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 CVG-Shield/2.1"

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS c2_ips (ip TEXT PRIMARY KEY, first_seen TEXT, feeds TEXT, malware TEXT, confidence INTEGER)")
    c.execute("CREATE TABLE IF NOT EXISTS c2_domains (domain TEXT PRIMARY KEY, first_seen TEXT, feeds TEXT, threat TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS c2_urls (url_hash TEXT PRIMARY KEY, url TEXT, first_seen TEXT, threat TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS ssl_ja3 (ja3 TEXT PRIMARY KEY, first_seen TEXT, threat TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS dns_sinkhole (domain TEXT PRIMARY KEY, source TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS malware_hashes (hash TEXT PRIMARY KEY, first_seen TEXT, signature TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS ingest_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, feed TEXT, records INTEGER)")
    conn.commit()
    return conn

def fetch_url(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    return urllib.request.urlopen(req, context=ctx, timeout=30)

def fetch_text(url):
    return fetch_url(url).read().decode()

def fetch_json(url):
    return json.loads(fetch_text(url))

def ingest_feodo(conn):
    data = fetch_text("https://feodotracker.abuse.ch/downloads/ipblocklist.csv")
    reader = csv.reader(io.StringIO(data))
    count = 0
    for row in reader:
        if len(row) >= 6 and row[1].count(".") == 3:
            try:
                conn.execute("INSERT OR IGNORE INTO c2_ips VALUES (?,?,?,?,?)",
                    (row[1], row[0], "feodo", row[5], 90))
                count += 1
            except:
                pass
    conn.commit()
    return count

def ingest_sslbl(conn):
    data = fetch_text("https://sslbl.abuse.ch/blacklist/sslblacklist.csv")
    reader = csv.reader(io.StringIO(data))
    count = 0
    for row in reader:
        if len(row) == 3 and not row[0].startswith("#") and ":" not in row[0]:
            try:
                conn.execute("INSERT OR IGNORE INTO ssl_ja3 VALUES (?,?,?)", (row[1][:64], row[0], row[2]))
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
    reader = csv.reader(io.StringIO(data))
    count = 0
    for row in reader:
        if len(row) >= 8 and row[0].isdigit():
            url = row[2].strip().strip('"')
            threat = row[7].strip().strip('"') if len(row) > 7 else ""
            if url.startswith("http"):
                h = hashlib.md5(url.encode()).hexdigest()
                try:
                    conn.execute("INSERT OR IGNORE INTO c2_urls VALUES (?,?,?,?)", (h, url[:500], row[1], threat))
                    count += 1
                except:
                    pass
    conn.commit()

def ingest_misp_osint(conn):
    """CIRCL MISP OSINT feed - 1,635 events with ~ C2 indicators"""
    manifest = fetch_json("https://www.circl.lu/doc/misp/feed-osint/manifest.json")
    total = {"ips": 0, "domains": 0, "urls": 0, "hashes": 0, "events": 0}
    
    for event_id in manifest.keys():
        try:
            url = f"https://www.circl.lu/doc/misp/feed-osint/{event_id}.json"
            ev = fetch_json(url)
            attrs = ev.get("Event", {}).get("Attribute", [])
            total["events"] += 1
            
            for a in attrs:
                atype = a.get("type", "")
                val = a.get("value", "")
                if not val:
                    continue
                try:
                    if atype in ("ip-dst") and "." in val:
                        conn.execute("INSERT OR IGNORE INTO c2_ips VALUES (?,?,?,?,?)",
                            (val[:45], "", "misp", ev.get("Event",{}).get("info","")[:50], 75))
                        total["ips"] += 1
                    elif atype in ("domain", "hostname"):
                        conn.execute("INSERT OR IGNORE INTO c2_domains VALUES (?,?,?,?)",
                            (val[:255], "", "misp", ev.get("Event",{}).get("info","")[:50]))
                        total["domains"] += 1
                    elif atype in ("url", "uri"):
                        h = hashlib.md5(val.encode()).hexdigest()
                        conn.execute("INSERT OR IGNORE INTO c2_urls VALUES (?,?,?,?)",
                            (h, val[:500], "", "misp"))
                        total["urls"] += 1
                    elif atype in ("md5", "sha256", "sha1"):
                        sig = a.get("comment", ev.get("Event",{}).get("info",""))[:50]
                        conn.execute("INSERT OR IGNORE INTO malware_hashes VALUES (?,?,?)",
                            (val[:64], "", sig))
                        total["hashes"] += 1
                except:
                    pass
        except:
            pass
    
    conn.commit()
    return total

def ingest_dns_sources(conn):
    sources = [
        ("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "stevenblack"),
        ("https://abp.oisd.nl/", "oisd"),
        ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt", "hagezi_pro"),
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
    print("  CVG SHIELD v2.1 - Global C2 Sinkhole System")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("  Learning who contributes. Mapping the threat.")
    print("=" * 60)

    conn = init_db()

    print("\n[Phase 1] C2 Feeds...")
    n = ingest_feodo(conn)
    print(f"  FeodoTracker C2 IPs:  {n}")
    n = ingest_sslbl(conn)
    print(f"  SSLBL JA3 certs:      {n}")
    n = ingest_urlhaus(conn)
    print(f"  URLhaus malware URLs: {n}")

    print("\n[Phase 2] MISP OSINT (CIRCL - 1,635 events)...")
    total = ingest_misp_osint(conn)
    print(f"  Events processed:     {total['events']}")
    print(f"  New C2 IPs:           {total['ips']}")
    print(f"  New C2 Domains:       {total['domains']}")
    print(f"  New Malware URLs:     {total['urls']}")
    print(f"  New Malware Hashes:   {total['hashes']}")
    print(f"  Total from MISP:      {total['ips'] + total['domains'] + total['urls'] + total['hashes']:,}")

    print("\n[Phase 3] DNS Sinkhole Aggregation...")
    n = ingest_dns_sources(conn)

    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM c2_ips");      ips = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM c2_domains");  doms = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM c2_urls");     urls = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM ssl_ja3");     ja3 = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM malware_hashes"); hashes = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM dns_sinkhole");   dns = c.fetchone()[0]
    total_all = ips + doms + urls + ja3 + hashes + dns

    print(f"\n  === C2 GRAPH DATABASE ===")
    print(f"  C2 IPs:             {ips:10d}")
    print(f"  C2 Domains:         {doms:10d}")
    print(f"  Malware URLs:       {urls:10d}")
    print(f"  JA3 Fingerprints:   {ja3:10d}")
    print(f"  Malware Hashes:     {hashes:10d}")
    print(f"  DNS Sinkholes:      {dns:10d}")
    print(f"  GRAND TOTAL:        {total_all:10d}")
    print(f"\n  For everyone. Around the globe.")

if __name__ == "__main__":
    main()

def ingest_malpedia_actors(conn):
    """Malpedia (Fraunhofer FKIE) - malware family & actor encyclopedia
    Free service, German national research lab
    We scrape actor pages for C2 patterns
    """
    import re
    actors = [
        "apt28", "apt29", "apt33", "apt37", "apt40", "apt41",
        "lazarus", "kimsuky", "turla", "sandworm", "wizard_spider",
        "bear", "charming_kitten", "darkhydrus", "dragonok", "el_machete",
        "equation_group", "fin7", "gallmaker", "gorgon_group", "group5",
        "hacking_team", "inception", "ke3chang", "leviathan", "lurk",
        "mole_rats", "moses_staff", "netsarang", "oilrig", "pegasus",
        "pitty_tiger", "platinum", "poseidon_group", "pSharp", "reaper",
        "red_aptone", "ritz", "sednit", "sharp_turtle", "sima_slam",
        "sofacy", "stately_taurus", "stealth_manta", "stolen_pencil",
        "stonefly", "telebots", "temptress", "the_white_company",
        "thin_air", "threat_group_2889", "thrip", "turla", "unc1151",
        "unc2452", "victory_duke", "void_balisong", "voodoo_bear",
        "weak_link", "wild_neptune", "winnti", "wirte", "wizard_spider",
        "zebrocy", "zeus"
    ]
    
    for actor in actors:
        try:
            url = f"https://malpedia.caad.fkie.fraunhofer.de/actor/{actor}"
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            html = urllib.request.urlopen(req, context=ctx, timeout=10).read().decode()
            # Extract synonyms/aliases
            syn_match = re.search(r'Aliases.*?<ul>(.*?)</ul>', html, re.DOTALL)
            if syn_match:
                aliases = re.findall(r'>([^<]+)</li>', syn_match.group(1))
                for alias in aliases:
                    domain = alias.strip().replace(" ", "").lower()
                    if "." in domain and len(domain):
                        conn.execute("INSERT OR IGNORE INTO c2_domains VALUES (?,?,?)",
                            (domain[:255], "", "malpedia"))
        except:
            pass
    conn.commit()
