# C2 Threat Actor Deep Dive — Who They Are, Who Tracks Them

> "The creature is the log." — animalhouse, Moltbook

## 1. CIRCL.lu — The Engine Room

**Organization:** Computer Incident Response Center Luxembourg
**Mandate:** Luxembourg National CERT for private sector
**Founded:** Mandated by Ministry of Economy
**MISP Role:** Creator and primary maintainer of the MISP platform itself
**Volume:** 1,056 OSINT events in the public feed (64% of all OSINT events)

**How they operate:**
CIRCL analysts filter, normalize, and enrich raw OSINT sources so consumers aren't drowning in noise. They don't just aggregate — they contextual MISP event includes:
- Indicators of Compromise (domains, IPs, URLs, hashes)
- Threat actor attribution (when possible)
- TLP marking (WHITE/CLEAR/GREEN/AMBER)
- Taxonomy tags (APT, botnet, ransomware, etc.)

**Funding:** Luxembourg Ministry of Economy + EU grants
**Access:** Free, TLP:WHITE events
**API:** MISP standard REST + TAXII

**For SHIELD:** CIRCL is our primary data backbone. Their 1,056 events provide the graph nodes (threat actors, C2 infrastructure, victim sectors).

---

## 2. Krawczyk Industries Limited — Financial Sector Sentinel

**Organization:** Private threat intel company (UK/International)
**Volume:** 242 OSINT events (15% of feed)
**Specialty:** Financial sector threats, banking trojans, organized crime

**Named in events:** Turla, Dridex (banking trojan), Sofacy/APT28 (Russia)
**Contribution pattern:** Focused on financially-motivated threat actors

**For SHIELD:** Their feed gives us banking C2 infrastructure — the nodes that target financial institutions globally.

---

## 3. CthulhuSPRL.be — Belgium OSINT Collective

**Organization:** Belgian OSINT research group
**Volume:** 218 OSINT events (13% of feed)
**Specialty:** Telephony fraud, VoIP abuse, telecom C2

**Named in events:** TeslaCrypt (ransomware), Dridex, malspam campaigns
**Contribution pattern:** Bridges the gap between cybercrime and telecom fraud

**For SHIELD:** Telecom C2 is a blind spot for most security tools. Cthulhu fills it.

---

## 4. MalwareMustDie — Malware Research Group

**Organization:** Independent, non-profit malware research collective
**Founded:** Active since early 2010s
**Named after:** Their motto — defeating malware itself
**Notable discoveries:** Disclosed numerous 0-day malware campaigns
**Contribution:** ~10 MISP events, but HIGH value per event

**How they operate:**
- Reverse-engineer malware samples in real-time
- Publish YARA rules and IOCs before vendors
- Run blog at malwaremustdie.org with detailed technical analysis
**Funding:** Donations, volunteer
**Track record:** First to discover multiple IoT botnets and Linux malware families

**For SHIELD:** High-fidelity indicators with deep technical context. Each indicator has a story.

---

## 5. abuse.ch — The C2 Tracker Network

**Organization:** Non-profit project founded by a single developer
**Founded:** Early 2010s by a Swiss researcher
**Funding:** Donations, Spamhaus partnership
**Legal status:** Non-profit, community-funded

### abuse.ch Projects:

#### URLhaus — Malware Distribution URLs
**What:** Tracks URLs used to distribute malware (not just C2, but download points)
**Volume:** ~35K active URLs
**Data:** URL, threat type, status (online/offline), first_seen, tags
**Update:** Real-time
**API:** POST-based JSON API (requires key for bulk, free for limited queries)
**For SHIELD:** Blocks malware at the download phase (before execution)

#### FeodoTracker — Emotet/QakBot/Dridex C2
**What:** Tracks C2 servers for the Emotet botnet ecosystem (Dridex, QakBot)
**Update:** Real-time
**Data:** IP, port, status, malware family, first_seen, last_online
**Status (2026):** 5 IPs in current CSV (was 100+ during Emotet peak)
**For SHIELD:** Emotet infrastructure intelligence — the botnet that survived multiple law enforcement takedowns

#### SSL Blacklist (SSLBL) — Malicious SSL Certificates
**What:** JA3 fingerprints + SHA1 hashes of SSL certs used by malware C2
**Volume:** 107 active entries
**Data:** Listing date, SHA1 hash, common name / threat label
**For SHIELD:** Even when C2 IPs change, the SSL cert JA3 hash persists. Network-level detection without DNS.

#### ThreatFox — IOC Sharing Platform
**What:** Community IOC sharing (C2 IPs, domains, URLs)
**Data:** ~500 new IOCs per day (varies)
**Update:** Real-time
**API:** POST-based JSON
**For SHIELD:** Fresh IOCs with context (malware family, confidence, first_seen)

---

## 6. Synovus Financial — Financial CERT Light

**Organization:** Synovus Financial Corp (US regional bank)
**MISP events:** 43
**Contribution pattern:** Banking-specific threat intel

**For SHIELD:** Demonstrates that even individual financial institutions contribute back to community defense.

---

## 7. The DFIR Report — Digital Forensics

**Organization:** Private IR firm publishing detailed incident reports
**Approach:** Publish full forensic analysis of real intrusions
**Events:** 4 but each is a complete kill chain reconstruction

**For SHIELD:** Shows us the ATTACKER process — not just indicators but the full playbook (initial access → lateral movement → C2 → exfiltration).

---

## 8. ENISA — EU Threat Landscape

**Organization:** European Union Agency for Cybersecurity
**Volume:** 1 comprehensive annual report (Threat Landscape 2025)
**Content:**
- APT28, APT29, Turla → targeting EU public administration (Russia-nexus)
- Lazarus → cryptocurrency/protocol attacks (North Korea)
- Ransomware → still #1 threat to EU organizations

**For SHIELD:** Strategic context. Tells us WHO is being targeted and WHY.

---

## 9. FIRST.org — Global CSIRT Directory

**Organization:** Forum of Incident Response and Security Teams
**Members:** 800+ CSIRTs in 100+ countries
**Map:** first.org/members/map
**Role:** Not a feed — a NETWORK of feeds

**How to use:**
- Contact national CERT for your country → get early threat warnings
- Join as a team → access member-only TAXII feeds
- Regional groups: APCERT (Asia-Pacific),AfricaCERT, TF-CSIRT (Europe/UK)

**For SHIELD:** FIRST gives us the CONTACTS to push intelligence to every country's CERT.

---

## 10. MISP Project Itself — The Protocol

**Organization:** Open source, maintained by CIRCL
**Communities:**
- CIRCL MISP OSINT (1,100+ orgs) — what we're using
- MISP communities for specific sectors (finance, health, telecom)
- ISAC-specific sharing groups (FS-ISAC via MISP)

**For SHIELD:** MISP IS the language of threat intelligence. By outputting MISP events, our sinkhole data becomes consumable by 1,100+ organizations globally.

---

## SHIELD v2 Architecture

```
[OSINT Sources]       [C2 Sources]         [Vulnerability Sources]
    |                      |                       |
    v                      v                       v
CIRCL MISP feed    abuse.ch (4 feeds)     CISA KEV
(478K indicators)  (URLhaus/Feodo/SSL/FOX)  (1,630 vulns)
    |                      |                       |
    +----------+-----------+                       |
               |                                   v
               +---------+------------> [C2 GRAPH DATABASE]
               |                              (SQLite, signed receipts)
               |                                   |
               v                                   v
[MISP Communities]                     [SINKHOLE OUTPUTS]
1,100+ organizations                   DNS, BGP, IP, SSL-JA3
    |
    v
[NATIONAL CERTS]
800+ FIRST members
```

## Sinkhole Strategy

1. **DNS-level:** Pi-hole + BIND RPZ zones for C2 domains
   → SHIELD domain list → distribute to Pi-hole community
   → Works for ANY network running Pi-hole (millions of installations)

2. **IP-level:** Drop C2 IPs at firewall/BGP level
   → Export to Iptables, nftables, pfSense, Cloudflare WAF

3. **SSL-JA3-level:** Network detection of C2 TLS handshakes
   → Suricata/Snort rules from SSLBL
   → Works regardless of IP/domain rotation

4. **MISP distribution:** Output as MISP events (STIX/TAXII)
   → 1,100+ MISP communities ingest our IOCs automatically
   → Stamps trust: our intel reaches every FIRST.org CERT

## What Makes SHIELD Different

| Feature | Vendor Products | CVG SHIELD |
|---|---|---|
| Scope | Subscriber only | Everyone, globally |
| License | Proprietary | MIT, open source |
| Cost | $50K-$500K/year | Free |
| Source data | Single vendor | 8+ sources, cross-referenced |
| Trust model | Vendor claims | Signed receipts, blockchain audit |
| Infrastructure | Cloud | Self-hosted + federated |
| Intelligence | Aggregated | + Contextualized (Malpedia, DFIR reports) |
| Community | Closed | 1,100+ MISP orgs, 800+ FIRST CERTs |
