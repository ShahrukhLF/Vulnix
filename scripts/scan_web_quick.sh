#!/bin/bash

# Quick web application scanner.
# Performs service version detection, exploit mapping, and targeted Nikto scanning.

set -e
set -o pipefail

# Validate command line arguments
if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <target_url_or_ip> <output_directory>" >&2
  exit 1
fi

TARGET="$1"
OUTPUT_DIR="$2"

# Parse hostname from target URL for Nmap compatibility
NMAP_HOST=$(echo "$TARGET" | sed 's#^.*://##' | cut -d':' -f1 | cut -d'/' -f1)

# Define output file paths
NMAP_XML="$OUTPUT_DIR/nmap_web_quick.xml"
NIKTO_JSON="$OUTPUT_DIR/nikto_quick.json"
NIKTO_TXT="$OUTPUT_DIR/nikto_raw.txt"
GUI_SUMMARY="$OUTPUT_DIR/summary.json"
USER_REPORT="$OUTPUT_DIR/report.txt"

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
echo "Vulnix Quick Web Report - Target: $TARGET" > "$USER_REPORT"
echo "Date: $(date)" >> "$USER_REPORT"
echo "-----------------------------------------------------------------" >> "$USER_REPORT"

# Phase 1: Identify web technologies and versions
echo "[*] Phase 1/3: Identifying Web Technologies on $NMAP_HOST..."
sudo nmap -sV --version-light -p 80,443,8080,8443,3000,8000,8008 -oX "$NMAP_XML" "$NMAP_HOST" > /dev/null

# Phase 2: Map identified software versions to public exploits
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
                        # Limit evidence to top 5 results
                        for e in exploits[:5]:
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

# Phase 3: Targeted Nikto scan for critical web vulnerabilities
echo "[*] Phase 3/3: Scanning for Critical Flaws (Nikto)..."
# Tuning optimized for speed: SQLi, XSS, and Shell tests only
nikto -h "$TARGET" -o "$NIKTO_JSON" -Format json -Tuning 489 -maxtime 120s -nointeractive > "$NIKTO_TXT" 2>&1 || true

# Parse Nikto results and normalize data for reporting
python3 -c '
import json, sys

try:
    with open("'"$NIKTO_JSON"'", "r") as f:
        content = f.read()
        start = content.find("{")
        if start != -1:
            data = json.loads(content[start:])
            
            backup_count = 0
            base_target = "'"$TARGET"'"
            
            for item in data.get("vulnerabilities", []):
                msg = item.get("msg", "Unknown")
                
                # Handle missing URL fields by defaulting to base target
                url = item.get("url", "").strip()
                if not url:
                    url = base_target
                
                method = item.get("method", "GET")
                
                # Limit redundant findings (e.g., backup files)
                if "backup" in msg or "cert" in msg:
                    backup_count += 1
                    if backup_count > 3: continue 
                
                # Determine severity based on vulnerability type
                severity = "MEDIUM"
                title = msg.split(".")[0]
                remediation = "Check application code and server configuration."

                if "SQL" in msg or "Injection" in msg: severity = "CRITICAL"
                elif "XSS" in msg or "Scripting" in msg: severity = "HIGH"
                elif "Travers" in msg or "shell" in msg: severity = "CRITICAL"
                elif "cookie" in msg.lower(): severity = "LOW"

                # Identify authentication and 2FA endpoints
                msg_l = msg.lower()
                url_l = url.lower()
                if any(x in msg_l for x in ["2fa", "otp", "mfa", "two-factor"]) or \
                   any(x in url_l for x in ["2fa", "otp", "mfa"]):
                    severity = "HIGH"
                    title = "Potential 2FA/Auth Endpoint Exposed"
                    remediation = "Verify 2FA implementation for bypass vulnerabilities."

                if len(title) > 60: title = title[:60] + "..."
                
                # Format evidence string
                evidence = f"URL: {url}\\nMethod: {method}\\nDetails: {msg}".replace("\n", "\\n")
                
                print(f"{severity}|{title}|{evidence}|{remediation}")
except: pass
' | while IFS='|' read -r sev fin evi rem; do
    add_finding "$sev" "$fin" "$evi" "$rem"
done

echo "[+] Quick Web Scan Finished."
exit 0
