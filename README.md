# CVG SHIELD v2.1 — Global C2 Sinkhole System

> "The map goes dark when there are no vulnerabilities left to patch."
> "Trust is a frequency." — Moltbook

## What it does

CVG SHIELD maps the global C2 infrastructure of threat actors. It breaks the kill chain at the C2 layer — no C2, no botnet works. No botnet, no attack.

**For everyone. Around the globe. Free. MIT-licensed.**

## Intelligence Sources

### C2 Feeds (Live, Updated Daily)
| Source | Type | Records |
|--------|------|---------|
| FeodoTracker (abuse.ch) | C2 IP blocklist | ~2,000+ IPs |
| SSLBL (abuse.ch) | JA3/SSL fingerprints | ~100K+ certs |
| URLhaus (abuse.ch) | Malware distribution URLs | ~500K+ URLs |
| ThreatFox (abuse.ch) | IOC sharing platform | Variable |

### OSINT Feeds
| Source | Type | Records |
|--------|------|---------|
| CIRCL MISP OSINT | Community events | ~1,635 events |
| StevenBlack Hosts | Malware/privacy domains | ~83,000 |
| OISD Blocklist | Ad/malware blocking | ~336,000 |
| Hagezi DNS Blocklist | Threat blocking | ~233,000 |

### Sinkhole & Threat Intel
| Source | Type |
|--------|------|
| Malpedia (Fraunhofer FKIE) | Malware actor encyclopedia |
| CISA KEV | Known exploited vulnerabilities |
| ENISA | EU threat landscape |

## Architecture

```
[C2 Feeds]            [OSINT Feeds]         [DNS Blocklists]
FeodoTracker           CIRCL MISP (1,635)    StevenBlack (83K)
SSLBL (JA3/SSL)        MalwareMustDie        OISD (336K)
URLhaus (500K+)        CthulhuSPRL           Hagezi (233K)
ThreatFox              Krawczyk
                       ENISA, CISA
        |                     |                     |
        +----------+----------+---------------------+
                   |
           [C2 GRAPH DATABASE]
              SQLite backend
                   |
        +----------+----------+
        |                     |
   [SINKHOLE OUTPUTS]    [DISTRIBUTION]
   DNS RPZ zones          Pi-hole compatible
   IP blocklists          MISP export
   JA3 Suricata rules     CSV/STIX
```

## Running

```bash
cd cvg-shield
python3 cvg_shield_v21.py          # Main C2 scanner (v2.1)
python3 cvg_shield_v22.py          # v2.2 (latest)
python3 cvg_shield_v2.py           # Legacy v2.0
python3 cvg_shield.py              # Legacy v1.0
```

## Database

All indicators are stored in a local SQLite database (`~/cvg_shield_fresh.db`) with tables:
- `c2_ips` — Attacker infrastructure IPs
- `c2_domains` — C2 domains and exfiltration points
- `c2_urls` — Malware distribution URLs
- `ssl_ja3` — JA3 TLS fingerprints
- `malware_hashes` — SHA1/SHA256 of known malware
- `dns_sinkhole` — Aggregated sinkhole domains
- `ingest_log` — Feed ingestion history

## Deployment

| Component | Host | Status |
|-----------|------|--------|
| Scanner | DFORGE-11 (Windows 11) | Active |
| Blocklist Dist. | QUEEN-12 (Synology, .32) | Configurable |
| Intelligence DB | QUEEN-10 (TrueNAS, .7) | Configurable |
| Source Code | github.com/azelenski_cvg/cvg-shield | This repo |
| Public Mirror | github.com/cleargeo/cvg-shield | Public mirror |

## License

MIT. Every byte serves the public.
Built for agents, by agents.
CVG — Clearview Geographic.
