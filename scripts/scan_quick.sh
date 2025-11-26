#!/bin/bash

# ==============================================================================
# Vulnix - Quick Network Scan (scan_quick.sh)
#
# GOAL: Complete in < 2.5 minutes.
# FIX: "Smart Fuzzing" Logic. If exact search fails, it cleans the service name
#      (removes 'httpd', 'ubuntu', etc.) and retries to find ALL vulnerabilities.
# ==============================================================================

set -e
set -o pipefail

if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <target_ip> <output_directory>" >&2
  exit 1
fi

TARGET_IP="$1"
OUTPUT_DIR="$2"

# Output Files
NMAP_XML="$OUTPUT_DIR/nmap_quick.xml"
NMAP_TXT="$OUTPUT_DIR/nmap_quick.txt"
ENUM_JSON="$OUTPUT_DIR/enum4linux.json"

GUI_SUMMARY="$OUTPUT_DIR/summary.json"
USER_REPORT="$OUTPUT_DIR/report.txt"

# Top ports list (Optimized for speed + coverage)
TARGET_PORTS="21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,1099,1433,1521,1524,2049,2121,3306,3389,5432,5900,5985,6000,6379,6667,8000,8009,8080,8180,8443,9000"

# --- Reporting Helper ---
add_finding() {
  local severity="$1"
  local finding="$2"
  local evidence="$3"
  local remediation="$4"

  # Text Report
  echo "-----------------------------------------------------------------" >> "$USER_REPORT"
  printf "[%-8s] %s\n" "$severity" "$finding" >> "$USER_REPORT"
  echo "Evidence:" >> "$USER_REPORT"
  echo -e "$evidence" >> "$USER_REPORT"
  echo "Remediation: $remediation" >> "$USER_REPORT"
  echo "" >> "$USER_REPORT"

  # JSON Summary (Safe Append)
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
echo "Vulnix Quick Scan Report - Target: $TARGET_IP" > "$USER_REPORT"
echo "Date: $(date)" >> "$USER_REPORT"
echo "-----------------------------------------------------------------" >> "$USER_REPORT"

# --- Phase 1: Fast Nmap Scan ---
echo "[*] Phase 1/3: Service Detection..."
sudo nmap -sV --version-light --open -p "$TARGET_PORTS" -oX "$NMAP_XML" -oN "$NMAP_TXT" "$TARGET_IP"

echo "[+] Nmap complete."

# --- Phase 2: Enumeration ---
if grep -E "445/tcp.*open|139/tcp.*open" "$NMAP_TXT" > /dev/null; then
    echo "[*] Phase 2/3: SMB Open. Running Enum4linux..."
    timeout 60s enum4linux-ng -U -S -o -oJ "$ENUM_JSON" "$TARGET_IP" > /dev/null 2>&1 || true
    if [ -f "$ENUM_JSON" ]; then
        add_finding "INFO" "SMB Enumeration Data" "SMB Services detected." "Review enum4linux.json for details."
    fi
else
    echo "[*] Phase 2/3: No SMB detected."
fi

# --- Phase 3: Smart Exploit Mapping ---
echo "[*] Phase 3/3: Mapping Exploits (Smart Fuzzing Mode)..."

# Python Logic:
# 1. Parses Nmap XML.
# 2. Tries EXACT search (e.g., "Apache httpd 2.2.8").
# 3. If 0 results -> CLEANS string (e.g., "Apache 2.2.8") and RETRIES.
python3 -c '
import xml.etree.ElementTree as ET
import subprocess
import json
import sys
import re

xml_file = "'"$NMAP_XML"'"

def get_exploits(query):
    """Runs searchsploit and returns list of dicts"""
    try:
        cmd = ["searchsploit", "-j", query]
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout
        json_start = output.find("{")
        if json_start == -1: return []
        data = json.loads(output[json_start:])
        return data.get("RESULTS_EXPLOIT", [])
    except:
        return []

def clean_query(product, version):
    """Smart cleaning for better matches"""
    # Remove noise words
    p = re.sub(r" httpd| smbd| ftpd| daemon", "", product, flags=re.IGNORECASE)
    # Remove content in parens (e.g., " (Ubuntu)")
    v = re.sub(r"\(.*?\)", "", version)
    # Remove trailing junk
    v = v.strip()
    p = p.strip()
    # Handle complex ranges like "3.X - 4.X" -> just take "3.X"
    if " - " in v:
        v = v.split(" - ")[0]
    return f"{p} {v}".strip()

try:
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    for host in root.findall("host"):
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open": continue
            
            service = port.find("service")
            if service is None: continue
            
            product = service.get("product", "")
            version = service.get("version", "")
            if not product: continue
            
            # Attempt 1: Exact Match
            query = f"{product} {version}".strip()
            exploits = get_exploits(query)
            
            # Attempt 2: Smart Fallback
            if not exploits:
                new_query = clean_query(product, version)
                if new_query != query and len(new_query) > 3:
                    exploits = get_exploits(new_query)
                    query = new_query # Update query name for report
            
            if exploits:
                count = len(exploits)
                evidence_list = []
                for exp in exploits:
                    title = exp.get("Title", "Unknown")
                    codes = exp.get("Codes", "")
                    cves = re.findall(r"CVE-\d{4}-\d+", codes)
                    cve_str = ", ".join(cves) if cves else "EDB-ID"
                    evidence_list.append(f"- {title} [{cve_str}]")
                
                # Format for Report
                display_limit = 20
                evidence_str = "\n".join(evidence_list[:display_limit])
                if count > display_limit: evidence_str += f"\n...and {count - display_limit} more."
                
                safe_evidence = f"Found {count} exploits for \"{query}\":\n{evidence_str}".replace("\n", "\\n")
                print(f"HIGH|Vulnerable Service: {query}|{safe_evidence}|Update {product} to the latest version.")

except Exception as e:
    pass
' | while IFS='|' read -r sev fin evi rem; do
    evi_decoded=$(echo -e "$evi")
    add_finding "$sev" "$fin" "$evi_decoded" "$rem"
done

# --- Fallback for Critical Manual Checks ---
# These ensure we NEVER miss the absolute criticals, even if searchsploit is offline
if grep -q "21/tcp.*open" "$NMAP_TXT" && grep -q "vsftpd 2.3.4" "$NMAP_TXT"; then
    add_finding "CRITICAL" "VSFTPD Backdoor" "vsftpd 2.3.4 detected on Port 21." "This is a known backdoor. Update immediately."
fi
if grep -q "1524/tcp.*open" "$NMAP_TXT"; then
    add_finding "CRITICAL" "Root Shell Backdoor" "Port 1524 (Ingreslock) is open." "This is a direct root backdoor."
fi

echo "[+] Quick Scan Finished."
exit 0
