#!/bin/bash

# ==============================================================================
# Vulnix - Deep Web Scan (scan_web_deep.sh)
#
# GOAL: Complete in < 5 minutes.
# FIXES:
#   1. Fixed 'unexpected operator' crash by removing fragile JSON string checks.
#   2. Fixed '-e' artifacts in text report by using printf.
#   3. Nmap Target Cleaning & Nikto Noise Filtering included.
#   4. Added 2FA/MFA Endpoint Detection.
# ==============================================================================

set -e
set -o pipefail

if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <target_url_or_ip> <output_directory>" >&2
  exit 1
fi

TARGET="$1"
OUTPUT_DIR="$2"

# FIX: Extract Clean Host for Nmap
# Removes http://, https://, and :port so Nmap gets a raw IP/Hostname
NMAP_HOST=$(echo "$TARGET" | sed 's#^.*://##' | cut -d':' -f1 | cut -d'/' -f1)

# Output Files
NMAP_XML="$OUTPUT_DIR/nmap_web_deep.xml"
NIKTO_JSON="$OUTPUT_DIR/nikto_deep.json"
NIKTO_TXT="$OUTPUT_DIR/nikto_raw.txt"
GUI_SUMMARY="$OUTPUT_DIR/summary.json"
USER_REPORT="$OUTPUT_DIR/report.txt"

# --- Reporting Helper (Fixed) ---
add_finding() {
  local severity="$1"
  local finding="$2"
  local evidence="$3"
  local remediation="$4"

  # Text Report (Using printf to avoid -e artifacts)
  echo "-----------------------------------------------------------------" >> "$USER_REPORT"
  printf "[%-8s] %s\n" "$severity" "$finding" >> "$USER_REPORT"
  echo "Evidence:" >> "$USER_REPORT"
  printf "%b\n" "$evidence" >> "$USER_REPORT"
  echo "Remediation: $remediation" >> "$USER_REPORT"
  echo "" >> "$USER_REPORT"

  # JSON Summary (Simplified Logic: Always Append)
  # We assume the file is initialized with [] at start of script
  jq --arg s "$severity" --arg f "$finding" --arg e "$evidence" --arg r "$remediation" \
     '. += [{severity: $s, finding: $f, evidence: $e, remediation: $r}]' "$GUI_SUMMARY" > "$GUI_SUMMARY.tmp" && mv "$GUI_SUMMARY.tmp" "$GUI_SUMMARY"
}

# --- Initialization ---
# Initialize valid JSON array so we can append safely without reading the file first
echo "[]" > "$GUI_SUMMARY"

echo "Vulnix Deep Web Report - Target: $TARGET" > "$USER_REPORT"
echo "Date: $(date)" >> "$USER_REPORT"
echo "-----------------------------------------------------------------" >> "$USER_REPORT"

# --- Phase 1: Active Nmap Scripting ---
echo "[*] Phase 1/3: Deep Script Scanning on $NMAP_HOST..."
# http-enum: Finds hidden folders
# http-config-backup: Finds backups
# http-passwd: Checks for accessible password files
# http-headers: Checks for security headers
# http-methods: Checks for dangerous methods (PUT/DELETE)
sudo nmap -sV --script="http-enum,http-config-backup,http-passwd,http-headers,http-methods" -p 80,443,8080,8443,3000,8000 -oX "$NMAP_XML" "$NMAP_HOST" > /dev/null

# Parse Nmap Scripts & Searchsploit
python3 -c '
import xml.etree.ElementTree as ET
import subprocess, json, re

def get_exploits(query):
    try:
        cmd = ["searchsploit", "-j", query]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if "RESULTS_EXPLOIT" in res.stdout:
            start = res.stdout.find("{")
            return json.loads(res.stdout[start:]).get("RESULTS_EXPLOIT", [])
    except: return []
    return []

try:
    tree = ET.parse("'"$NMAP_XML"'")
    root = tree.getroot()
    
    for port in root.findall(".//port"):
        # 1. Script Results
        for script in port.findall("script"):
            sid = script.get("id")
            output = script.get("output", "")
            
            sev = "MEDIUM"
            if "passwd" in sid: sev = "CRITICAL"
            if "backup" in sid: sev = "HIGH"
            if "methods" in sid and "PUT" in output: sev = "HIGH"
            
            title = f"Nmap Script: {sid}"
            evidence = output[:300].replace("\n", "\\n")
            
            print(f"{sev}|{title}|{evidence}|Review web server configuration.")

        # 2. Searchsploit Mapping
        service = port.find("service")
        if service is not None:
            p = service.get("product", "")
            v = service.get("version", "")
            if p and v:
                exploits = get_exploits(f"{p} {v}")
                if exploits:
                    count = len(exploits)
                    ev_list = []
                    for e in exploits[:5]:
                        t = e.get("Title", "")
                        c = re.findall(r"CVE-\d{4}-\d+", e.get("Codes", ""))
                        ev_list.append(f"- {t} [{c[0] if c else "EDB"}]")
                    
                    ev = "\\n".join(ev_list)
                    safe_ev = f"Found {count} exploits:\\n{ev}"
                    print(f"HIGH|Vulnerable Service: {p} {v}|{safe_ev}|Patch {p}.")
except: pass
' | while IFS='|' read -r sev fin evi rem; do
    add_finding "$sev" "$fin" "$evi" "$rem"
done

# --- Phase 2: Nikto Deep Scan ---
echo "[*] Phase 2/3: Nikto Deep Scan (3.5 min limit)..."
# Reverse Tuning (x): Scan everything EXCEPT Denial of Service (6)
nikto -h "$TARGET" -o "$NIKTO_JSON" -Format json -Tuning x6 -maxtime 210s -nointeractive > "$NIKTO_TXT" 2>&1 || true

# Parse Nikto with Noise Filter & 2FA Detection
python3 -c '
import json
try:
    with open("'"$NIKTO_JSON"'", "r") as f:
        content = f.read()
        start = content.find("{")
        if start != -1:
            data = json.loads(content[start:])
            backup_count = 0
            for item in data.get("vulnerabilities", []):
                msg = item.get("msg", "")
                url = item.get("url", "/")
                method = item.get("method", "")
                
                # Filter Noise: Detect Soft 404 behavior on backup files
                if "backup" in msg or "cert" in msg:
                    backup_count += 1
                    if backup_count > 5: continue

                # Dynamic Severity Assignment
                sev = "LOW"
                remediation = "Check server config."
                title = msg[:60] + "..."

                if "XSS" in msg or "SQL" in msg: sev = "HIGH"
                if "Shell" in msg or "Execution" in msg: sev = "CRITICAL"
                if "Configuration" in msg or "header" in msg: sev = "MEDIUM"

                # 2FA / AUTH Logic (Requested by Evaluator)
                msg_lower = msg.lower()
                url_lower = url.lower()
                if any(x in msg_lower for x in ["2fa", "otp", "mfa", "two-factor", "authenticator"]) or \
                   any(x in url_lower for x in ["2fa", "otp", "mfa"]):
                    sev = "HIGH"
                    title = "Potential 2FA/Auth Endpoint Exposed"
                    remediation = "Manual Verification Required: Check for 2FA bypass vulnerabilities (Logic/Race Conditions)."

                
                evidence = f"URL: {url}\\nMethod: {method}\\nDetails: {msg}".replace("\n", "\\n")
                print(f"{sev}|{title}|{evidence}|{remediation}")
except: pass
' | while IFS='|' read -r sev fin evi rem; do
    add_finding "$sev" "$fin" "$evi" "$rem"
done

echo "[+] Deep Web Scan Finished."
exit 0
