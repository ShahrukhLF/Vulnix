#!/bin/bash

# Vulnix OWASP ZAP Automated Wrapper (The "Shotgun")
# Uses native ZAP headless mode for generalized web application scanning.

set -e
set -o pipefail

if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <target_url> <output_directory> [optional_cookie]" >&2
  exit 1
fi

TARGET="$1"
OUTPUT_DIR="$2"
COOKIE="$3"
ZAP_JSON="$OUTPUT_DIR/zap_report.json"
GUI_SUMMARY="$OUTPUT_DIR/summary.json"
USER_REPORT="$OUTPUT_DIR/report.txt"

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

if [ ! -f "$GUI_SUMMARY" ]; then echo "[]" > "$GUI_SUMMARY"; fi
echo "Vulnix OWASP ZAP Assessment - Target: $TARGET" >> "$USER_REPORT"
echo "Date: $(date)" >> "$USER_REPORT"
echo "-----------------------------------------------------------------" >> "$USER_REPORT"

echo "[*] Phase 1/3: Preparing Environment (Killing zombie processes)..."
pkill -f zaproxy || true
sleep 2

echo "[*] Phase 2/3: Running Native OWASP ZAP Active Scan on $TARGET..."
echo "    -> Spidering and testing generalized vulnerabilities. This may take a few minutes..."

# CRITICAL FIX: Using Native Bash Arrays to completely prevent syntax crashes
ZAP_ARGS=(-cmd -port 8081 -quickurl "$TARGET" -quickprogress -quickout "$ZAP_JSON")

# Force ZAP to crawl aggressively and take its time
ZAP_ARGS+=(-config "spider.maxDepth=5")
ZAP_ARGS+=(-config "spider.maxDuration=3")
ZAP_ARGS+=(-config "scanner.maxScanDurationInMins=10")

if [ ! -z "$COOKIE" ]; then
    echo "    -> Using Authenticated Session Cookie!"
    ZAP_ARGS+=(-config "replacer.full_list(0).description=auth")
    ZAP_ARGS+=(-config "replacer.full_list(0).enabled=true")
    ZAP_ARGS+=(-config "replacer.full_list(0).matchtype=REQ_HEADER")
    ZAP_ARGS+=(-config "replacer.full_list(0).matchstr=Cookie")
    ZAP_ARGS+=(-config "replacer.full_list(0).regex=false")
    ZAP_ARGS+=(-config "replacer.full_list(0).replacement=$COOKIE")
fi

# Launch ZAP using the array (immune to word-splitting)
timeout 900 zaproxy "${ZAP_ARGS[@]}" > /dev/null 2>&1 || true

echo "[*] Phase 3/3: Parsing ZAP Vulnerability Data..."

python3 -c '
import json, sys, os
import re

report_file = "'"$ZAP_JSON"'"

if not os.path.exists(report_file):
    sys.exit(0)

try:
    with open(report_file, "r") as f:
        data = json.load(f)
        
    sites = data.get("site", [])
    for site in sites:
        alerts = site.get("alerts", [])
        
        for alert in alerts:
            name = alert.get("alert", alert.get("name", "Unknown Vulnerability"))
            risk_desc = alert.get("riskdesc", "Low")
            
            raw_solution = alert.get("solution", "Review security best practices.")
            solution = re.sub(r"<[^>]+>", "", raw_solution).replace("\n", " ").strip()
            
            instances = alert.get("instances", [])
            
            severity = "LOW"
            if "High" in risk_desc: severity = "HIGH"
            elif "Medium" in risk_desc: severity = "MEDIUM"
            elif "Informational" in risk_desc: severity = "INFO"
            
            evidence = ""
            if instances:
                first_instance = instances[0]
                uri = first_instance.get("uri", "")
                method = first_instance.get("method", "GET")
                param = first_instance.get("param", "N/A")
                
                evidence = f"URL: {uri}\\nMethod: {method}\\nParameter: {param}"
                
                if len(instances) > 1:
                    evidence += f"\\n...and {len(instances) - 1} other vulnerable endpoints found."
            
            print(f"{severity}|{name}|{evidence}|{solution}")
            
except Exception as e:
    pass
' | while IFS='|' read -r sev fin evi rem; do
    evi_decoded=$(echo -e "$evi")
    add_finding "$sev" "$fin" "$evi_decoded" "$rem"
done

echo "[+] OWASP ZAP Scan Finished."
exit 0
