# CVG SHIELD v2.0 — Intelligence Source Analysis

## Who contributes to global C2 intelligence

### Tier 1: National CERTs & Government (Authoritative)
| Organization | Country/Region | Events | Role |
|---|---|---|---|
| CISA | USA | 1,630 KEV | Known exploited vulnerabilities |
| CERT-EU | EU | Active | EU government cyber threats |
| NCSC-UK | UK | Active | UK national security |
| ACSC | Australia | Active | Australian cyber defense |
| CERT Polska | Poland | Active | Polish national CERT |
| CNCERT/CC | China | Active | Chinese national CERT |
| JPCERT/CC | Japan | Active | Japanese national CERT |
| KrCERT/CC | South Korea | Active | Korean national CERT |
| CERT-In | India | Active | Indian national CERT |
| CERT-BR | Brazil | Active | Brazilian national CERT |

### Tier 2: ISACs (Sector-Specific, Membership)
| Organization | Sector | Scope |
|---|---|---|
| FS-ISAC | Finance | Global financial system threats |
| MS-ISAC | Municipal/State/Local | US government threats |
| H-ISAC | Healthcare | Global health sector |
| ON-ISAC | Nuclear | US nuclear sector |
| E-ISAC | Energy | North American electricity |
| REN-ISAC | Research/Education | Global research networks |
| NH-ISAC | Homeland Security | US critical infrastructure |

### Tier 3: Community/Open Source (Free, Verified)
| Source | Type | Volume | Pricing |
|---|---|---|---|
| CIRCL MISP Feed | OSINT events | 1,635 events (~478K indicators) | Free, TLP:WHITE |
| MalwareMustDie | Malware analysis | Active | Free |
| abuse.ch (URLhaus) | Malware URLs | ~35K active | Free |
| abuse.ch (FeodoTracker) | Botnet C2 IPs | ~5 active tracked | Free |
| abuse.ch (SSLBL) | Malicious SSL | 107 fingerprints | Free |
| abuse.ch (ThreatFox) | IOC sharing | ~500/day | Free |
| StevenBlack | DNS sinkhole | ~90K domains | Free |
| OISD | DNS sinkhole | ~ domains | Free |
| Firehol | IP blocklist | Multiple levels | Free |
| The DFIR Report | Incident reports | Active | Free |
| ESET | Threat intel | Active | Free tier |
| CthulhuSPRL.be | OSINT | 218 events | Free |
| Synovus Financial | Financial sector | 43 events | Free |
| Ransom-ISAC | Ransomware | 7 events | Free |

### Tier 4: Commercial/Proprietary (Restricted)
| Source | Type | Access |
|---|---|---|
| Mandiant (Google) | A | Commercial |
| CrowdStrike | Threat graph | Commercial |
| Recorded Future | Intelligence platform | Commercial |
| Anomali STAXX | STIX/TAXII feed | Free tier + commercial |
| AlienVault OTX | Community pulses | Free + commercial |
| VirusTotal | Malware scanning | Free + commercial |
| Shodan | Internet scanning | Commercial |
| BinaryEdge | Threat intelligence | Commercial |

## Threat Actor Landscape (from MISP OSINT feed)

### Top Ranked by Event Frequency
1. Locky - 99 events (ransomware, DGA-based C2)
2. APT28 (Fancy Bear/Sofacy) - 16 events (Russia, cyberespionage)
3. Turla - 15 events (Russia, snake/rootkit)
4. Emotet - 15 events (banking trojan turned loader)
5. Dridex - 28 events (banking trojan)
6. Lazarus Group - 9 events (North Korea)
7. Sandworm - 2 events (Russia, Ukraine infrastructure attacks)
8. The Dukes/CosmicDuke - 4 events (Russia, long-running APT)
9. Predator - 2 events (surveillance/mercenary)
10. PlugX - 7 events (China/RAT)

### Malware Types Distribution
- Ransomware: 128 events
- Trojan: 54 events
- Backdoor: 35 events
- Botnet: 31 events
- Loader: 24 events
- Worm: 14 events
- Spyware: 13 events
- Wiper: 5 events
- Cryptominer: 3 events

### Nation-State Attribution
- APT groups: 52 events
- Russia-linked: 18 events
- North Korea-linked: 17 events
- Iran-linked: 5 events
- Brazil: 8 events (local threats)
- Japan: 7 events

## SHIELD Intelligence Integration

### Currently Integrated (Operational)
1. CISA KEV - 1,630 known exploited vulns - Daily pull
2. Emerging Threats - 18,587 Suricata IDS rules - Hourly pull
3. Blocklist.de - 25,672 attacker IPs - Daily pull
4. StevenBlack - 83,605 domains - Daily pull
5. OISD - 336,172 domains - Daily pull
6. FeodoTracker - 5 C2 IPs (live) - Real-time
7. URLhaus - malware distribution URLs - Real-time
8. SSLBL - JA3 fingerprints - Real-time

### Ready to Integrate (API Available)
9. CIRCL MISP feed - 1,635 OSINT events (~478K indicators) - Daily pull
10. ThreatFox - IOCs (needs POST auth)
11. MalwareBazaar - Malware samples

### Future Integration
12. FIRST.org member teams (800+ CERTs worldwide)
13. CISA AIS / TAXII server
14. ISAC membership applications
15. REN-ISAC (research networks — fits CVG academic partnerships)
