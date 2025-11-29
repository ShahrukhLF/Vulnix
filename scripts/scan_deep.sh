#!/bin/bash

# ==============================================================================
# Vulnix - Deep Network Scan (scan_deep.sh)
#
# GOAL: Complete in < 5 minutes.
# FIX: 
#   1. Fixed 'grep' crash on CVE brackets.
#   2. Expanded scripts to find Misconfigurations (Auth/Discovery).
#   3. Smart Remediation for all finding types.
#   4. EXCLUDED 'broadcast' and 'multicast' scripts to prevent hanging on IPv6.
# ==============================================================================

set -e
set -o pipefail

if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <target_ip> <output_directory>" >&2
  exit 1
fi

TARGET_IP="$1"
OUTPUT_DIR="$2"

# Files
NMAP_DISCOVERY="$OUTPUT_DIR/nmap_discovery.txt"
NMAP_VULN="$OUTPUT_DIR/nmap_vuln.txt"
NMAP_XML="$OUTPUT_DIR/nmap_vuln.xml"
GUI_SUMMARY="$OUTPUT_DIR/summary.json"
USER_REPORT="$OUTPUT_DIR/report.txt"

# --- Reporting Helper ---
add_finding() {
  local severity="$1"
  local finding="$2"
  local evidence="$3"
  local remediation="$4"

  echo "-----------------------------------------------------------------" >> "$USER_REPORT"
  printf "[%-8s] %s\n" "$severity" "$finding" >> "$USER_REPORT"
  echo "Evidence:" >> "$USER_REPORT"
  echo -e "$evidence" >> "$USER_REPORT"
  echo "Remediation: $remediation" >> "$USER_REPORT"
  echo "" >> "$USER_REPORT"

  if [ ! -s "$GUI_SUMMARY" ] || [ "$(cat "$GUI_SUMMARY")" == "[]" ]; then
     jq -n --arg s "$severity" --arg f "$finding" --arg e "$evidence" --arg r "$remediation" \
        '[{severity: $s, finding: $f, evidence: $e, remediation: $r}]' > "$GUI_SUMMARY.tmp"
  else
     jq --arg s "$severity" --arg f "$finding" --arg e "$evidence" --arg r "$remediation" \
        '. + [{severity: $s, finding: $f, evidence: $e, remediation: $r}]' "$GUI_SUMMARY" > "$GUI_SUMMARY.tmp"
  fi
  mv "$GUI_SUMMARY.tmp" "$GUI_SUMMARY"
}

# --- Initialization ---
echo "[]" > "$GUI_SUMMARY"
echo "Vulnix Deep Assessment Report - Target: $TARGET_IP" > "$USER_REPORT"
echo "Date: $(date)" >> "$USER_REPORT"
echo "-----------------------------------------------------------------" >> "$USER_REPORT"

# --- Phase 1: Discovery ---
echo "[*] Phase 1/3: Port Discovery..."
sudo nmap -sS --top-ports 2000 --open -n --min-rate 1500 "$TARGET_IP" -oG "$NMAP_DISCOVERY"
OPEN_PORTS=$(grep "Ports:" "$NMAP_DISCOVERY" | grep -oE '[0-9]+/open' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')

if [ -z "$OPEN_PORTS" ]; then
    echo "[!] No open ports found. Aborting."
    exit 0
fi
echo "[*] Target Ports: $OPEN_PORTS"

# --- Phase 2: Vulnerability Scripting ---
echo "[*] Phase 2/3: Running Deep Scripts..."
# FIX: Added "and not broadcast and not multicast" to prevent IPv6 hangs
sudo nmap -sV --version-intensity 5 --script="(default or vuln or discovery or auth) and not dos and not brute and not external and not broadcast and not multicast" --script-timeout 60s --max-retries 1 --min-rate 1500 -p "$OPEN_PORTS" -oN "$NMAP_VULN" -oX "$NMAP_XML" "$TARGET_IP"
echo "[+] Nmap Script Scan complete."

# --- Phase 3: Advanced Analysis ---
echo "[*] Phase 3/3: Analyzing Results..."

python3 -c '
import xml.etree.ElementTree as ET
import subprocess
import json
import sys
import re

xml_file = "'"$NMAP_XML"'"

def get_exploits(query):
    try:
        cmd = ["searchsploit", "-j", query]
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout
        json_start = output.find("{")
        if json_start == -1: return []
        data = json.loads(output[json_start:])
        return data.get("RESULTS_EXPLOIT", [])
    except: return []

def clean_query(product, version):
    p = re.sub(r" httpd| smbd| ftpd| daemon", "", product, flags=re.IGNORECASE)
    v = re.sub(r"\(.*?\)", "", version)
    v = v.strip().split(" - ")[0]
    return f"{p.strip()} {v}".strip()

try:
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    for host in root.findall("host"):
        for port in host.findall(".//port"):
            port_id = port.get("portid")
            
            # A. Service Analysis (Searchsploit)
            service = port.find("service")
            if service is not None:
                product = service.get("product", "")
                version = service.get("version", "")
                if product:
                    query = f"{product} {version}".strip()
                    exploits = get_exploits(query)
                    if not exploits:
                        query = clean_query(product, version)
                        if len(query) > 3: exploits = get_exploits(query)
                    
                    if exploits:
                        count = len(exploits)
                        ev_list = []
                        for exp in exploits:
                            t = exp.get("Title", "Unknown")
                            c = exp.get("Codes", "")
                            cves = re.findall(r"CVE-\d{4}-\d+", c)
                            cve_str = ", ".join(cves) if cves else "EDB-ID"
                            ev_list.append(f"- {t} [{cve_str}]")
                        
                        ev_str = "\n".join(ev_list[:10])
                        if count > 10: ev_str += f"\n...and {count-10} more."
                        safe_ev = f"Found {count} exploits for {query}:\n{ev_str}".replace("\n", "\\n")
                        print(f"HIGH|Vulnerable Service: {query}|{safe_ev}|Update {product} immediately.")

            # B. Nmap Script Analysis (Expanded)
            for script in port.findall("script"):
                sid = script.get("id")
                output = script.get("output", "")
                
                if sid == "vulners": continue
                if "NOT VULNERABLE" in output: continue

                is_vuln = False
                severity = "HIGH"
                title = f"Nmap Script: {sid}"
                
                # Detection Logic
                if "State: VULNERABLE" in output or "VULNERABLE:" in output or "Vulnerable" in output:
                    is_vuln = True
                # Misconfigurations (Discovery/Auth)
                elif "Anonymous" in output and "allowed" in output:
                    title = "Anonymous Access Allowed"
                    severity = "MEDIUM"
                    is_vuln = True
                elif "nfs-showmount" in sid:
                    title = "NFS Shares Exposed"
                    severity = "MEDIUM"
                    is_vuln = True
                elif "http-methods" in sid and "PUT" in output:
                    title = "Insecure HTTP Methods (PUT)"
                    severity = "MEDIUM"
                    is_vuln = True
                
                # Extract CVE
                cves_found = re.findall(r"CVE-\d{4}-\d+", output)
                cve_tag = f" [{cves_found[0]}]" if cves_found else ""

                # Map Criticals
                if "vsftpd-backdoor" in sid:
                    title = "VSFTPD Backdoor"
                    severity = "CRITICAL"
                    is_vuln = True
                elif "ssl-poodle" in sid and is_vuln:
                    title = "SSL POODLE Vulnerability"
                    severity = "MEDIUM"
                elif "distcc" in sid and is_vuln:
                    title = "DistCC Remote Code Execution"
                    severity = "CRITICAL"
                    is_vuln = True
                elif "rmi-vuln" in sid and is_vuln:
                    title = "Java RMI Remote Code Execution"
                    severity = "CRITICAL"
                    is_vuln = True
                elif "ms17-010" in sid and is_vuln:
                    title = "EternalBlue (MS17-010)"
                    severity = "CRITICAL"
                    is_vuln = True
                
                if is_vuln:
                    remediation = "Consult vendor documentation."
                    if severity == "CRITICAL":
                        remediation = "Immediate Action: Patch, remove, or firewall."
                    elif "Anonymous" in title:
                        remediation = "Disable anonymous login in service configuration."
                    elif "NFS" in title:
                        remediation = "Restrict NFS exports to trusted IPs only."
                    elif "PUT" in title:
                        remediation = "Disable dangerous HTTP methods in web server config."
                    elif "ssl" in sid:
                        remediation = "Disable weak SSL/TLS protocols."

                    lines = output.splitlines()
                    clean_output = "\n".join(lines[:15]) 
                    if len(lines) > 15: clean_output += "\n..."
                    safe_out = clean_output.replace("\n", "\\n")
                    
                    print(f"{severity}|{title}{cve_tag} (Port {port_id})|{safe_out}|{remediation}")

except Exception: pass
' | while IFS='|' read -r sev fin evi rem; do
    evi_decoded=$(echo -e "$evi")
    # FIX: Use grep -Fq (Fixed String) to handle brackets [] in titles
    if ! grep -Fq "$fin" "$USER_REPORT"; then
        add_finding "$sev" "$fin" "$evi_decoded" "$rem"
    fi
done

# --- Fallback for Critical Manual Checks ---
if grep -q "1524/tcp.*open" "$NMAP_VULN"; then
    add_finding "CRITICAL" "Root Shell Backdoor" "Port 1524 (Ingreslock) is open." "Direct root access detected. Firewall immediately."
fi

echo "[+] Deep Scan Finished."
exit 0
