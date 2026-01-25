#!/bin/bash

# Network vulnerability scanner wrapper.
# Performs service detection, SMB enumeration, and exploit mapping via searchsploit.

set -e
set -o pipefail

# Validate command line arguments
if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <target_ip> <output_directory>" >&2
  exit 1
fi

TARGET_IP="$1"
OUTPUT_DIR="$2"

# Define output file paths
NMAP_XML="$OUTPUT_DIR/nmap_quick.xml"
NMAP_TXT="$OUTPUT_DIR/nmap_quick.txt"
ENUM_JSON="$OUTPUT_DIR/enum4linux.json"

GUI_SUMMARY="$OUTPUT_DIR/summary.json"
USER_REPORT="$OUTPUT_DIR/report.txt"

# Define target ports for rapid scanning
TARGET_PORTS="21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,1099,1433,1521,1524,2049,2121,3306,3389,5432,5900,5985,6000,6379,6667,8000,8009,8080,8180,8443,9000"

# Helper function to append findings to text report and JSON summary
add_finding() {
  local severity="$1"
  local finding="$2"
  local evidence="$3"
  local remediation="$4"

  # Update text report
  echo "-----------------------------------------------------------------" >> "$USER_REPORT"
  printf "[%-8s] %s\n" "$severity" "$finding" >> "$USER_REPORT"
  echo "Evidence:" >> "$USER_REPORT"
  echo -e "$evidence" >> "$USER_REPORT"
  echo "Remediation: $remediation" >> "$USER_REPORT"
  echo "" >> "$USER_REPORT"

  # Update JSON summary safely
  if [ ! -s "$GUI_SUMMARY" ] || [ "$(cat "$GUI_SUMMARY")" == "[]" ]; then
      jq -n --arg s "$severity" --arg f "$finding" --arg e "$evidence" --arg r "$remediation" \
        '[{severity: $s, finding: $f, evidence: $e, remediation: $r}]' > "$GUI_SUMMARY.tmp"
  else
      jq --arg s "$severity" --arg f "$finding" --arg e "$evidence" --arg r "$remediation" \
        '. + [{severity: $s, finding: $f, evidence: $e, remediation: $r}]' "$GUI_SUMMARY" > "$GUI_SUMMARY.tmp"
  fi
  mv "$GUI_SUMMARY.tmp" "$GUI_SUMMARY"
}

# Initialize report files
echo "[]" > "$GUI_SUMMARY"
echo "Vulnix Quick Scan Report - Target: $TARGET_IP" > "$USER_REPORT"
echo "Date: $(date)" >> "$USER_REPORT"
echo "-----------------------------------------------------------------" >> "$USER_REPORT"

# Phase 1: Service detection scan using Nmap
echo "[*] Phase 1/3: Service Detection..."
sudo nmap -Pn -sV --version-light --open -p "$TARGET_PORTS" -oX "$NMAP_XML" -oN "$NMAP_TXT" "$TARGET_IP"

echo "[+] Nmap complete."

# Phase 2: Conditional SMB enumeration based on Nmap results
if grep -E "445/tcp.*open|139/tcp.*open" "$NMAP_TXT" > /dev/null; then
    echo "[*] Phase 2/3: SMB Open. Running Enum4linux..."
    timeout 60s enum4linux-ng -U -S -o -oJ "$ENUM_JSON" "$TARGET_IP" > /dev/null 2>&1 || true
    if [ -f "$ENUM_JSON" ]; then
        add_finding "INFO" "SMB Enumeration Data" "SMB Services detected." "Review enum4linux.json for details."
    fi
else
    echo "[*] Phase 2/3: No SMB detected."
fi

# Phase 3: Map services to exploits using embedded Python logic
echo "[*] Phase 3/3: Mapping Exploits (Smart Fuzzing Mode)..."

python3 -c '
import xml.etree.ElementTree as ET
import subprocess
import json
import sys
import re

xml_file = "'"$NMAP_XML"'"

def get_exploits(query):
    """Query searchsploit and return results as a list of dictionaries."""
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
    """Normalize service strings to improve search match accuracy."""
    # Remove noise words
    p = re.sub(r" httpd| smbd| ftpd| daemon", "", product, flags=re.IGNORECASE)
    # Remove parenthetical content
    v = re.sub(r"\(.*?\)", "", version)
    # Trim whitespace
    v = v.strip()
    p = p.strip()
    # Simplify version ranges
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
            
            # Attempt 1: Search using exact product and version
            query = f"{product} {version}".strip()
            exploits = get_exploits(query)
            
            # Attempt 2: Fallback to cleaned query if no results found
            if not exploits:
                new_query = clean_query(product, version)
                if new_query != query and len(new_query) > 3:
                    exploits = get_exploits(new_query)
                    query = new_query # Update query for reporting
            
            if exploits:
                count = len(exploits)
                evidence_list = []
                for exp in exploits:
                    title = exp.get("Title", "Unknown")
                    codes = exp.get("Codes", "")
                    cves = re.findall(r"CVE-\d{4}-\d+", codes)
                    cve_str = ", ".join(cves) if cves else "EDB-ID"
                    evidence_list.append(f"- {title} [{cve_str}]")
                
                # Format findings for output
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

echo "[+] Quick Scan Finished."
exit 0
