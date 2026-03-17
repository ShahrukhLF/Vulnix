#!/bin/bash

# Vulnix OWASP ZAP (Quick Passive Scan)
# Performs generalized spidering and passive vulnerability detection in under 2 minutes.

set -e
set -o pipefail

if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <target_url> <output_directory>" >&2
  exit 1
fi

TARGET="$1"
OUTPUT_DIR="$2"
ZAP_PORT=8081
ZAP_JSON="$OUTPUT_DIR/zap_quick_alerts.json"
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
echo "Vulnix OWASP ZAP Quick Assessment - Target: $TARGET" >> "$USER_REPORT"
echo "Date: $(date)" >> "$USER_REPORT"
echo "-----------------------------------------------------------------" >> "$USER_REPORT"

# STEP 1: CLEANUP
echo "[*] Phase 1/3: Preparing Environment (Killing zombie processes)..."
pkill -f "zaproxy" > /dev/null 2>&1 || true
sleep 2

# STEP 2: BOOT DAEMON
echo "[*] Starting ZAP Engine in background on Port $ZAP_PORT..."
zaproxy -daemon -port $ZAP_PORT -config api.disablekey=true > /dev/null 2>&1 &
ZAP_PID=$!

echo "[+] Waiting for ZAP API to come online (This can take up to 45 seconds)..."
# Dynamic wait loop (polls every 2 seconds until curl succeeds)
MAX_WAIT=60
WAIT_COUNT=0
while ! curl -s "http://localhost:$ZAP_PORT/" > /dev/null; do
  sleep 2
  WAIT_COUNT=$((WAIT_COUNT + 2))
  if [ $WAIT_COUNT -ge $MAX_WAIT ]; then
    echo "[!] CRITICAL: ZAP failed to start in time. Aborting."
    kill $ZAP_PID 2>/dev/null || true
    exit 1
  fi
done
echo "[+] ZAP Engine is fully booted!"

# STEP 3: EXECUTE SCAN
echo "[*] Phase 2/3: Running Fast Spider & Passive Scan..."

# We temporarily disable set -e here so a minor curl network glitch doesn't crash everything
set +e

curl -s "http://localhost:$ZAP_PORT/JSON/spider/action/scan/?url=$TARGET" > /dev/null
echo "    -> Spider running for 45 seconds to gather passive vulnerabilities..."
sleep 45

echo "[*] Phase 3/3: Extracting Vulnerabilities & Shutting Down..."
curl -s "http://localhost:$ZAP_PORT/JSON/core/view/alerts/?baseurl=$TARGET" > "$ZAP_JSON"
curl -s "http://localhost:$ZAP_PORT/JSON/core/action/shutdown/" > /dev/null

# Turn strict error checking back on for the Python parser
set -e 

python3 -c '
import json, sys, os, re

report_file = "'"$ZAP_JSON"'"
if not os.path.exists(report_file): sys.exit(0)

try:
    with open(report_file, "r") as f:
        data = json.load(f)
        
    alerts = data.get("alerts", [])
    
    # Deduplicate alerts by name to keep the quick report clean
    unique_alerts = {}
    for alert in alerts:
        name = alert.get("alert", "Unknown Vulnerability")
        if name not in unique_alerts:
            unique_alerts[name] = alert
            
    for name, alert in unique_alerts.items():
        risk_desc = alert.get("risk", "Low")
        raw_solution = alert.get("solution", "Review security configuration.")
        solution = re.sub(r"<[^>]+>", "", raw_solution).replace("\n", " ").strip()
        
        severity = "LOW"
        if "High" in risk_desc: severity = "HIGH"
        elif "Medium" in risk_desc: severity = "MEDIUM"
        elif "Informational" in risk_desc: severity = "INFO"
        
        uri = alert.get("url", "")
        param = alert.get("param", "N/A")
        evidence = f"URL: {uri}\\nParameter: {param}"
        
        print(f"{severity}|{name}|{evidence}|{solution}")
        
except Exception as e: pass
' | while IFS='|' read -r sev fin evi rem; do
    evi_decoded=$(echo -e "$evi")
    add_finding "$sev" "$fin" "$evi_decoded" "$rem"
done

echo "[+] ZAP Quick Scan Finished."
exit 0
