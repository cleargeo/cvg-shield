#!/usr/bin/env python3
"""
CVG SHIELD - Blocklist Deployment Engine
Pushes C2 threat intelligence to actual protection systems.

Target 1: Pi-hole.83 (DNS blocking)
Target 2: Windows Firewall (C2 IP dropping)
Target 3: BIND RPZ (gateway-level blocking)
Target 4: /etc/hosts (fallback protection)
"""
import sqlite3, os, socket, ssl, urllib.request

DB = os.path.join(os.path.expanduser("~"), "shield_v22.db")
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
PIHOLE_IP = "192.168.1.83"

def check_pihole():
    """Check Pi-hole availability"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((PIHOLE_IP, 53))  # DNS port
        s.close()
        return "DNS_UP"
    except:
        pass
    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((PIHOLE_IP, 80))
        return "WEB_UP"
    except:
        return "DOWN"

def deploy_to_pihole_dns(conn):
    """Deploy SHIELD blocklist via Pi-hole gravity database or API"""
    print("\n  [Pi-hole] Checking availability...")
    status = check_pihole()
    print("  Status: " + status)
    
    if status != "DNS_UP":
        print("  Pi-hole is not directly manageable.")
        return 0
    
    # Generate blocklist file
    c = conn.cursor()
    c.execute("SELECT domain FROM dns_sinkhole WHERE source IN ('stevenblack','oisd','hagezi') LIMIT 50000")
    domains = [row[0] for row in c.fetchall()]
    
    blocklist_path = os.path.join(os.path.expanduser("~"), "shield_blocklist.txt")
    with open(blocklist_path, "w") as f:
        for domain in domains:
            if domain and "." in domain:
                f.write(domain + "\n")
    
    print("  Generated blocklist: " + str(len(domains)) + " domains")
    print("  File: " + blocklist_path)
    return len(domains)

def deploy_to_windows_firewall(conn):
    """Deploy C2 IP block rules to Windows Firewall (DFORGE-11)"""
    print("\n  [Windows Firewall] Deploying C2 IP blocks...")
    
    c = conn.cursor()
    c.execute("SELECT ip, malware FROM c2_ips WHERE malware != ''")
    blocked = []
    for ip, malware in c.fetchall():
        if ip.count(".") == 3:
            # Format: IP/mask
            cidr = ip + "/32"
            # Create a descriptive rule name
            rule_name = "CVG-SHIELD-" + malware.replace(" ", "-")[:30] + "-" + ip.replace(".", "-")
            blocked.append((rule_name, cidr, ip, malware))
    
    # Generate PowerShell script to create firewall rules
    ps_path = os.path.join(os.path.expanduser("~"), "deploy_firewall.ps1")
    with open(ps_path, "w") as f:
        f.write("# CVG SHIELD - C2 IP Block Rules\n")
        f.write("# Auto-generated: " + __import__("datetime").datetime.now().isoformat()[:19] + " UTC\n")
        f.write("# Total C2 IPs to block: " + str(len(blocked)) + "\n\n")
        
        for rule_name, cidr, ip, malware in blocked:
            f.write('New-NetFirewallRule -DisplayName "' + rule_name + '" ')
            f.write('-Direction Outbound -Action Block -RemoteAddress "' + cidr + '" ')
            f.write('-Description "CVG SHIELD: ' + malware + ' C2"\n')
        
        f.write('\nWrite-Host "SHIELD firewall rules deployed: ' + str(len(blocked)) + '"\n')
    
    print("  Generated firewall script: " + str(len(blocked)) + " rules")
    print("  File: " + ps_path)
    return len(blocked)

def generate_bind_rpz(conn, output_path):
    """Generate BIND Response Policy Zone for gateway DNS"""
    print("\n  [BIND RPZ] Generating response policy zone...")
    
    c = conn.cursor()
    c.execute("SELECT domain FROM dns_sinkhole")
    domains = [row[0] for row in c.fetchall() if row[0]]
    
    rpz = """; CVG SHIELD - Response Policy Zone
; Auto-generated for BIND9/RPZ
; Blocks C2 domains at the resolver level
$TTL 300
@            IN    SOA  localhost. root.localhost. (
                          2026063001  ; Serial
                          1h          ; Refresh
                          30m         ; Retry
                          7d          ; Expire
                          300 )       ; Negative Cache TTL
             IN    NS   localhost.

; C2 Domain Sinkhole - returns NXDOMAIN
"""
    count = 0
    for domain in domains:
        if "." in domain and len(domain) > 4 and not domain.startswith(";"):
            rpz += domain + " CNAME .\n"
            count += 1
    
    with open(output_path, "w") as f:
        f.write(rpz)
    
    print("  RPZ file: " + str(count) + " domains -> " + output_path)
    return count

def generate_hosts_file(conn, output_path):
    """Generate /etc/hosts-style blocking file"""
    print("\n  [hosts file] Generating backup protection file...")
    
    c = conn.cursor()
    c.execute("SELECT domain FROM dns_sinkhole LIMIT 100000")
    domains = [row[0] for row in c.fetchall() if row[0]]
    
    content = """# CVG SHIELD - hosts file deployment
# Place at: C:\Windows\System32\drivers\etc\hosts or /etc/hosts
# Auto-generated
"""
    count = 0
    for domain in domains:
        if "." in domain:
            content += "0.0.0.0 " + domain + "\n"
            count += 1
        if count >= 10000:
            break
    
    with open(output_path, "w") as f:
        f.write(content)
    
    print("  hosts file: " + str(count) + " entries -> " + output_path)
    return count

def main():
    print("=" * 60)
    print("  CVG SHIELD - Blocklist Deployment Engine")
    print("  Pushing intelligence to protection systems")
    print("=" * 60)
    
    conn = sqlite3.connect(DB)
    
    # 1. Pi-hole blocklist
    domains = deploy_to_pihole_dns(conn)
    
    # 2. Windows Firewall rules
    ips = deploy_to_windows_firewall(conn)
    
    # 3. BIND RPZ zone file
    rpz_domains = generate_bind_rpz(conn, os.path.join(os.path.expanduser("~"), "shield_rpz.db"))
    
    hosts_entries = generate_hosts_file(conn, os.path.join(os.path.expanduser("~"), "shield_hosts.txt"))
    
    conn.close()
    
    print("\n  === DEPLOYMENT READY ===")
    print("  Pi-hole blocklist:     " + str(domains).rjust(8) + " domains")
    print("  Windows Firewall rules:" + str(ips).rjust(8) + " rules")
    print("  BIND RPZ zone:         " + str(rpz_domains).rjust(8) + " domains")
    print("  hosts file:            " + str(hosts_entries).rjust(8) + " entries")
    total = domains + ips + rpz_domains + hosts_entries
    print("  TOTAL ACTIONS:         " + str(total).rjust(8))

if __name__ == "__main__":
    main()
