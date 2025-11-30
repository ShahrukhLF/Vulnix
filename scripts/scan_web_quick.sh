#!/bin/bash

# ==============================================================================
# Vulnix - Quick Web Scan (scan_web_quick.sh)
#
# GOAL: Complete in < 2.5 minutes.
# STRATEGY:
#   1. Clean Target Parsing (Fixes Nmap crashes).
#   2. Nmap: Version detection on common web ports.
#   3. Searchsploit: Map versions to public exploits.
#   4. Nikto: Tuned scan for XSS/SQLi (with noise filtering).
# ==============================================================================

set -e
set -o pipefail

if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <target_url_or_ip> <output_directory>" >&2
  exit 1
fi

TARGET="$1"
OUTPUT_DIR="$2"

# FIX 1: Extract Clean Host for Nmap (Remove http://, https://, and :port)
# This ensures Nmap gets "192.168.1.1" instead of "http://192.168.1.1:3000"
NMAP_HOST=$(echo "$TARGET" | sed 's#^.*://##' | cut -d':' -f1 | cut -d'/' -f1)

# Output Files
NMAP_XML="$OUTPUT_DIR/nmap_web_quick.xml"
NIKTO_JSON="$OUTPUT_DIR/nikto_quick.json"
NIKTO_TXT="$OUTPUT_DIR/nikto_raw.txt"
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
echo "Vulnix Quick Web Report - Target: $TARGET" > "$USER_REPORT"
echo "Date: $(date)" >> "$USER_REPORT"
echo "-----------------------------------------------------------------" >> "$USER_REPORT"

# --- Phase 1: Service Version Detection (Nmap) ---
echo "[*] Phase 1/3: Identifying Web Technologies on $NMAP_HOST..."
# Scan standard web ports only
sudo nmap -sV --version-light -p 80,443,8080,8443,3000,8000,8008 -oX "$NMAP_XML" "$NMAP_HOST" > /dev/null

# --- Phase 2: Exploit Mapping (Searchsploit) ---
echo "[*] Phase 2/3: Mapping Public Exploits..."

python3 -c '
import xml.etree.ElementTree as ET
import subprocess
import json
import re

try:
    tree = ET.parse("'"$NMAP_XML"'")
    root = tree.getroot()
    
    for port in root.findall(".//port"):
        service = port.find("service")
        if service is None: continue
        
        product = service.get("product", "")
        version = service.get("version", "")
        
        if product and version:
            # Clean query for Searchsploit
            query = f"{product} {version}".strip()
            cmd = ["searchsploit", "-j", query]
            res = subprocess.run(cmd, capture_output=True, text=True)
            
            if "RESULTS_EXPLOIT" in res.stdout:
                start = res.stdout.find("{")
                if start != -1:
                    data = json.loads(res.stdout[start:])
                    exploits = data.get("RESULTS_EXPLOIT", [])
                    
                    if exploits:
                        count = len(exploits)
                        ev_list = []
                        for e in exploits[:5]: # Top 5 only for Quick Scan
                            title = e.get("Title", "")
                            cves = re.findall(r"CVE-\d{4}-\d+", e.get("Codes", ""))
                            cve = cves[0] if cves else "EDB-ID"
                            ev_list.append(f"- {title} [{cve}]")
                        
                        ev_text = "\n".join(ev_list)
                        safe_ev = f"Found {count} exploits for {product} {version}:\n{ev_text}".replace("\n", "\\n")
                        print(f"HIGH|Vulnerable Software: {product} {version}|{safe_ev}|Upgrade {product} immediately.")

except: pass
' | while IFS='|' read -r sev fin evi rem; do
    add_finding "$sev" "$fin" "$evi" "$rem"
done

# --- Phase 3: Targeted Vulnerability Scan (Nikto) ---
echo "[*] Phase 3/3: Scanning for Critical Flaws (Nikto)..."
# -Tuning 489: XSS(4), Flash(8), SQL Injection(9) - Criticals Only
# -maxtime 90s: Strict time limit
nikto -h "$TARGET" -o "$NIKTO_JSON" -Format json -Tuning 489 -maxtime 90s -nointeractive > "$NIKTO_TXT" 2>&1 || true

# Parse Nikto JSON (With Noise Filtering)
python3 -c '
import json, re

try:
    with open("'"$NIKTO_JSON"'", "r") as f:
        content = f.read()
        start = content.find("{")
        if start != -1:
            data = json.loads(content[start:])
            
            backup_count = 0
            
            for item in data.get("vulnerabilities", []):
                msg = item.get("msg", "Unknown")
                url = item.get("url", "/")
                method = item.get("method", "GET")
                
                # FIX 2: Filter Noise (Soft 404s common in SPAs like Juice Shop)
                if "backup" in msg or "cert" in msg:
                    backup_count += 1
                    if backup_count > 3: continue 
                
                # Severity Logic
                severity = "MEDIUM"
                if "SQL" in msg or "Injection" in msg: severity = "CRITICAL"
                elif "XSS" in msg or "Scripting" in msg: severity = "HIGH"
                elif "Travers" in msg or "shell" in msg: severity = "CRITICAL"
                elif "cookie" in msg.lower(): severity = "LOW"

                # Format
                title = msg.split(".")[0]
                if len(title) > 60: title = title[:60] + "..."
                evidence = f"URL: {url}\\nMethod: {method}\\nDetails: {msg}".replace("\n", "\\n")
                
                print(f"{severity}|{title}|{evidence}|Check application code.")

except: pass
' | while IFS='|' read -r sev fin evi rem; do
    add_finding "$sev" "$fin" "$evi" "$rem"
done

echo "[+] Quick Web Scan Finished."
exit 0
