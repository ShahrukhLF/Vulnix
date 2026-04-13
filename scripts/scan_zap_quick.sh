#!/bin/bash
# Vulnix DAST Orchestrator
# Module: OWASP ZAP Quick Assessment
# Performs generalized spidering and passive vulnerability detection via ZAP API.

set -e
set -o pipefail

if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <target_url> <output_directory> [optional_cookie]" >&2
  exit 1
fi

TARGET="$1"
OUTPUT_DIR="$2"
COOKIE="$3"
ZAP_PORT=8081
ZAP_JSON="$OUTPUT_DIR/zap_quick_alerts.json"
GUI_SUMMARY="$OUTPUT_DIR/summary.json"
USER_REPORT="$OUTPUT_DIR/report.txt"

# --- Report Formatting Module ---
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
if [ ! -f "$GUI_SUMMARY" ]; then echo "[]" > "$GUI_SUMMARY"; fi
echo "Vulnix OWASP ZAP Quick Assessment - Target: $TARGET" >> "$USER_REPORT"
echo "Date: $(date)" >> "$USER_REPORT"
echo "-----------------------------------------------------------------" >> "$USER_REPORT"

# --- Phase 1: Environment Preparation & API Boot ---
echo "[*] Phase 1/3: Preparing Environment (Terminating stray processes)..."
pkill -f "zaproxy" > /dev/null 2>&1 || true
sleep 2

echo "[*] Starting ZAP Engine in background on Port $ZAP_PORT..."
zaproxy -daemon -port $ZAP_PORT -config api.disablekey=true > /dev/null 2>&1 &
ZAP_PID=$!

echo "[+] Waiting for ZAP API to initialize (Timeout: 60s)..."
MAX_WAIT=60
WAIT_COUNT=0
while ! curl -s "http://localhost:$ZAP_PORT/" > /dev/null; do
  sleep 2
  WAIT_COUNT=$((WAIT_COUNT + 2))
  if [ $WAIT_COUNT -ge $MAX_WAIT ]; then
    echo "[!] CRITICAL: ZAP API failed to start in time. Aborting."
    kill $ZAP_PID 2>/dev/null || true
    exit 1
  fi
done
echo "[+] ZAP Engine initialized successfully."

# Authenticated Session Injection via API Replacer
if [ ! -z "$COOKIE" ]; then
    echo "[*] Injecting Authenticated Session Cookie into ZAP API..."
    curl -s --data-urlencode "description=auth_cookie" \
            --data-urlencode "enabled=true" \
            --data-urlencode "matchType=REQ_HEADER" \
            --data-urlencode "matchString=Cookie" \
            --data-urlencode "replacement=$COOKIE" \
            "http://localhost:$ZAP_PORT/JSON/replacer/action/addRule/" > /dev/null
fi

# --- Phase 2: Vulnerability Scanning ---
echo "[*] Phase 2/3: Executing Spider & Passive Scan..."
set +e

curl -s "http://localhost:$ZAP_PORT/JSON/spider/action/scan/?url=$TARGET" > /dev/null
echo "    -> Spider running for 45 seconds to map passive attack surface..."
sleep 45

# --- Phase 3: Data Extraction & Pipeline Integration ---
echo "[*] Phase 3/3: Extracting Vulnerabilities & Terminating Engine..."
curl -s "http://localhost:$ZAP_PORT/JSON/core/view/alerts/?baseurl=$TARGET" > "$ZAP_JSON"
curl -s "http://localhost:$ZAP_PORT/JSON/core/action/shutdown/" > /dev/null

set -e 

python3 -c '
import json, sys, os, re, base64

def b64(text):
    return base64.b64encode(str(text).encode("utf-8")).decode("utf-8")

report_file = "'"$ZAP_JSON"'"
if not os.path.exists(report_file): 
    sys.exit(0)

try:
    with open(report_file, "r") as f:
        data = json.load(f)
        
    alerts = data.get("alerts", [])
    
    # Deduplicate alerts by name
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
        
        # Base64 encoding prevents bash word-splitting on complex outputs
        print(f"{b64(severity)}|{b64(name)}|{b64(evidence)}|{b64(solution)}")
        
except Exception as e: 
    pass
' | while IFS='|' read -r sev fin evi rem; do
    # Decode Base64 payloads securely back into strings
    sev_dec=$(echo "$sev" | base64 -d)
    fin_dec=$(echo "$fin" | base64 -d)
    evi_dec=$(echo "$evi" | base64 -d)
    rem_dec=$(echo "$rem" | base64 -d)
    
    evi_decoded=$(echo -e "$evi_dec")
    add_finding "$sev_dec" "$fin_dec" "$evi_decoded" "$rem_dec"
done

echo "[+] ZAP Quick Scan finalized."
exit 0
