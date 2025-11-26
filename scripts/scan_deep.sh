#!/bin/bash

# ==============================================================================
# Vulnix - Deep Network Scan (scan_deep.sh)
#
# GOAL: Complete in < 5 minutes.
# FIX: 
#   1. Ignores "NOT VULNERABLE" false positives.
#   2. Generates human-readable remediation for Nmap script findings.
#   3. Extracts CVEs from Nmap output into the title.
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

  # Text Report formatting
  echo "-----------------------------------------------------------------" >> "$USER_REPORT"
  printf "[%-8s] %s\n" "$severity" "$finding" >> "$USER_REPORT"
  echo "Evidence:" >> "$USER_REPORT"
  echo -e "$evidence" >> "$USER_REPORT"
  echo "Remediation: $remediation" >> "$USER_REPORT"
  echo "" >> "$USER_REPORT"

  # JSON Summary (Safe Append for GUI)
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

# --- Phase 1: Discovery (Speed Optimized) ---
echo "[*] Phase 1/3: Port Discovery..."
# Scan Top 2000 ports
sudo nmap -sS --top-ports 2000 --open -n --min-rate 1000 "$TARGET_IP" -oG "$NMAP_DISCOVERY"
OPEN_PORTS=$(grep "Ports:" "$NMAP_DISCOVERY" | grep -oE '[0-9]+/open' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')

if [ -z "$OPEN_PORTS" ]; then
    echo "[!] No open ports found. Aborting."
    exit 0
fi
echo "[*] Target Ports: $OPEN_PORTS"

# --- Phase 2: Vulnerability Scripting ---
echo "[*] Phase 2/3: Running Vuln Scripts..."
# Runs standard 'vuln' category scripts.
sudo nmap -sV --script=vuln --script-timeout 2m --max-retries 1 -p "$OPEN_PORTS" -oN "$NMAP_VULN" -oX "$NMAP_XML" "$TARGET_IP"
echo "[+] Nmap Script Scan complete."

# --- Phase 3: Advanced Analysis (Python XML Parser) ---
echo "[*] Phase 3/3: Analyzing Results (XML Parsing)..."

python3 -c '
import xml.etree.ElementTree as ET
import subprocess
import json
import sys
import re

xml_file = "'"$NMAP_XML"'"

# --- Searchsploit Logic ---
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

# --- Parser Start ---
try:
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    # 1. Process Hosts/Ports
    for host in root.findall("host"):
        for port in host.findall(".//port"):
            port_id = port.get("portid")
            proto = port.get("protocol")
            
            # A. Service Analysis (Searchsploit)
            service = port.find("service")
            if service is not None:
                product = service.get("product", "")
                version = service.get("version", "")
                if product:
                    query = f"{product} {version}".strip()
                    exploits = get_exploits(query)
                    if not exploits: # Smart Fuzz Fallback
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
                        
                        ev_str = "\n".join(ev_list[:10]) # Top 10
                        if count > 10: ev_str += f"\n...and {count-10} more."
                        safe_ev = f"Found {count} exploits for {query}:\n{ev_str}".replace("\n", "\\n")
                        print(f"HIGH|Vulnerable Service: {query}|{safe_ev}|Update {product}.")

            # B. Nmap Script Analysis (NSE)
            # We look for <script> tags inside the port
            for script in port.findall("script"):
                sid = script.get("id")
                output = script.get("output", "")
                
                # Skip "vulners" script
                if sid == "vulners": continue
                
                # FIX 1: Explicitly ignore false positives
                if "NOT VULNERABLE" in output: continue

                # Detect if script found a vuln
                is_vuln = False
                severity = "HIGH"
                title = f"Nmap Script: {sid}"
                
                # Logic: Check for "VULNERABLE" keyword or specific dangerous scripts
                if "State: VULNERABLE" in output or "VULNERABLE:" in output or "Vulnerable" in output:
                    is_vuln = True
                
                # Extract CVEs from the output text for cleaner titles
                cves_found = re.findall(r"CVE-\d{4}-\d+", output)
                cve_tag = f" [{cves_found[0]}]" if cves_found else ""

                # Special handling for known criticals
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
                elif "rmi-vuln" in sid and is_vuln:
                    title = "Java RMI Remote Code Execution"
                    severity = "CRITICAL"
                
                if is_vuln:
                    # FIX 2: Better Remediation Advice
                    remediation = "Consult vendor documentation for patches."
                    if severity == "CRITICAL":
                        remediation = "Immediate Action: Patch service, remove backdoor, or firewall port."
                    elif "ssl" in sid:
                        remediation = "Disable weak SSL/TLS protocols (SSLv3) in configuration."
                    elif "backdoor" in sid:
                        remediation = "Reinstall a clean version of the service immediately."

                    # Clean output for report (limit lines)
                    lines = output.splitlines()
                    clean_output = "\n".join(lines[:15]) 
                    if len(lines) > 15: clean_output += "\n..."
                    
                    # Sanitize for pipe
                    safe_out = clean_output.replace("\n", "\\n")
                    print(f"{severity}|{title}{cve_tag} (Port {port_id})|{safe_out}|{remediation}")

except Exception as e:
    pass
' | while IFS='|' read -r sev fin evi rem; do
    evi_decoded=$(echo -e "$evi")
    # Filter out duplicates
    if ! grep -q "$fin" "$USER_REPORT"; then
        add_finding "$sev" "$fin" "$evi_decoded" "$rem"
    fi
done

# --- Fallback for Critical Manual Checks (Safety Net) ---
if grep -q "1524/tcp.*open" "$NMAP_DISCOVERY"; then
    add_finding "CRITICAL" "Root Shell Backdoor" "Port 1524 (Ingreslock) is open." "Direct root access detected. Firewall immediately."
fi

echo "[+] Deep Scan Finished."
exit 0
