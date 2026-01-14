#!/bin/bash

# ==============================================================================
# Vulnix - Deep Web Scan (scan_web_deep.sh)
#
# GOAL: Deep Enumeration ~5-10 Minutes.
# TARGETS: OWASP Juice Shop, Mutillidae, DVWA.
# FIX: Added URL "Sanity Check" to prevent descriptions from appearing in URL field.
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
NMAP_HOST=$(echo "$TARGET" | sed 's#^.*://##' | cut -d':' -f1 | cut -d'/' -f1)

# FIX: Calculate Root URL (Protocol + Host + Port)
ROOT_URL=$(echo "$TARGET" | awk -F/ '{print $1"//"$3}')

# Output Files
NMAP_XML="$OUTPUT_DIR/nmap_web_deep.xml"
NIKTO_CSV="$OUTPUT_DIR/nikto_deep.csv"
NIKTO_TXT="$OUTPUT_DIR/nikto_raw.txt"
GUI_SUMMARY="$OUTPUT_DIR/summary.json"
USER_REPORT="$OUTPUT_DIR/report.txt"

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
  printf "%b\n" "$evidence" >> "$USER_REPORT"
  echo "Remediation: $remediation" >> "$USER_REPORT"
  echo "" >> "$USER_REPORT"

  # JSON Summary
  jq --arg s "$severity" --arg f "$finding" --arg e "$evidence" --arg r "$remediation" \
      '. += [{severity: $s, finding: $f, evidence: $e, remediation: $r}]' "$GUI_SUMMARY" > "$GUI_SUMMARY.tmp" && mv "$GUI_SUMMARY.tmp" "$GUI_SUMMARY"
}

# --- Initialization ---
echo "[]" > "$GUI_SUMMARY"
echo "Vulnix Deep Web Report - Target: $TARGET" > "$USER_REPORT"
echo "Date: $(date)" >> "$USER_REPORT"
echo "-----------------------------------------------------------------" >> "$USER_REPORT"

# --- Phase 1: Deep Nmap Enumeration (Limit: 3 Mins) ---
echo "[*] Phase 1/3: Deep Script Scanning on $NMAP_HOST (Limit: 3m)..."
sudo nmap -sV -T4 --host-timeout 3m \
  --script="http-config-backup,http-passwd,http-headers,http-methods,http-git,http-svn-enum" \
  -p 80,443,8080,8443,3000,8000,8008 \
  -oX "$NMAP_XML" "$NMAP_HOST" > /dev/null || true

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
        for script in port.findall("script"):
            sid = script.get("id")
            output = script.get("output", "")
            
            sev = "MEDIUM"
            if "passwd" in sid: sev = "CRITICAL"
            if "backup" in sid or "git" in sid: sev = "HIGH"
            if "methods" in sid and "PUT" in output: sev = "HIGH"
            
            title = f"Nmap Script: {sid}"
            evidence = output[:300].replace("\n", "\\n")
            print(f"{sev}|{title}|{evidence}|Review web server configuration.")

        service = port.find("service")
        if service is not None:
            p = service.get("product", "")
            v = service.get("version", "")
            if p and v:
                exploits = get_exploits(f"{p} {v}")
                if exploits:
                    count = len(exploits)
                    ev_list = []
                    for e in exploits[:8]:
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

# --- Phase 2: Nikto Deep Scan (Limit: 6 Mins) ---
echo "[*] Phase 2/3: Nikto Deep Scan (Limit: 6m)..."
nikto -h "$TARGET" -o "$NIKTO_CSV" -Format csv -Tuning x6 -maxtime 360s -nointeractive > "$NIKTO_TXT" 2>&1 || true

# Parse Nikto CSV (With URL Sanity Check)
python3 -c '
import csv, sys, os

if not os.path.exists("'"$NIKTO_CSV"'") or os.path.getsize("'"$NIKTO_CSV"'") == 0:
    sys.exit(0)

try:
    with open("'"$NIKTO_CSV"'", "r") as f:
        lines = f.readlines()
        clean_lines = [l for l in lines if l.count(",") >= 6]
        reader = csv.reader(clean_lines)
        
        backup_count = 0
        root_url = "'"$ROOT_URL"'"
        base_target = "'"$TARGET"'"
        
        for row in reader:
            if len(row) < 7: continue
            
            # SMART COLUMN DETECTION
            uri = "/"
            msg = row[-2] if len(row) > 8 else row[-1]
            method = "GET"

            # Find the URI column
            found_uri = False
            for i in range(4, len(row)-1):
                if row[i].startswith("/"):
                    uri = row[i]
                    if i > 0 and row[i-1].isupper():
                        method = row[i-1]
                    found_uri = True
                    break
            
            if not found_uri and len(row) > 6:
                uri = row[6]

            if "Description" in msg or "URI" in uri: continue

            # --- SANITY CHECK: If URI has spaces, it is NOT a URL ---
            if " " in uri:
                uri = ""

            # --- URL CONSTRUCTION ---
            if uri.startswith("http"):
                 url = uri
            elif not uri or uri == "/":
                 url = base_target
            else:
                 url = f"{root_url}{uri}"

            # Noise Filtering
            if "backup" in msg or "cert" in msg:
                backup_count += 1
                if backup_count > 5: continue

            # Severity Logic
            sev = "LOW"
            remediation = "Check server configuration."
            title = msg.split(".")[0][:60] + "..."

            if "SQL" in msg or "Injection" in msg: sev = "HIGH"
            if "XSS" in msg or "Scripting" in msg: sev = "HIGH"
            if "Shell" in msg or "Execution" in msg: sev = "CRITICAL"
            if "Configuration" in msg or "header" in msg: sev = "MEDIUM"
            if "include" in msg or "Inclusion" in msg: sev = "HIGH"

            # 2FA Detection
            keywords = ["2fa", "otp", "mfa", "two-factor"]
            if any(x in msg.lower() for x in keywords):
                sev = "HIGH"
                title = "Potential 2FA Endpoint"

            evidence = f"URL: {url}\\nMethod: {method}\\nDetails: {msg}".replace("\n", "\\n")
            
            # Prevent printing empty findings
            if len(msg) > 5:
                print(f"{sev}|{title}|{evidence}|{remediation}")
except Exception as e:
    pass
' | while IFS='|' read -r sev fin evi rem; do
    add_finding "$sev" "$fin" "$evi" "$rem"
done

echo "[+] Deep Web Scan Finished."
exit 0
