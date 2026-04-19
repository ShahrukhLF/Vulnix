#!/bin/bash
# ==============================================================================
# Vulnix DAST Orchestrator
# Module: SQLMap Deep Assessment (Level 3 / Risk 3)
# Description: Performs exhaustive database integrity testing. Utilizes aggressive
# heuristics (Time-based, Union, Boolean Blind) with a strict 7.5-minute SLA bound.
# ==============================================================================

set -e
set -o pipefail

if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <target_url> <output_directory> [optional_cookie]" >&2
  exit 1
fi

TARGET="$1"
OUTPUT_DIR="$2"
COOKIE="$3"
SQLMAP_RAW="$OUTPUT_DIR/sqlmap_raw.txt"
SQLMAP_DATA_DIR="$OUTPUT_DIR/sqlmap_data"
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

  # Dynamic JSON Injection for GUI rendering
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
echo "[*] Initializing SQLMap Deep Workspace..."
mkdir -p "$OUTPUT_DIR"
mkdir -p "$SQLMAP_DATA_DIR"

if [ ! -f "$GUI_SUMMARY" ]; then echo "[]" > "$GUI_SUMMARY"; fi
echo "Vulnix SQLMap Deep Assessment - Target: $TARGET" > "$USER_REPORT"
echo "Date: $(date)" >> "$USER_REPORT"
echo "-----------------------------------------------------------------" >> "$USER_REPORT"

# --- Phase 1: Vulnerability Scanning ---
echo "[*] Phase 1/2: Executing SQLMap Exhaustive Scan on $TARGET..."

COOKIE_FLAG=""
if [ ! -z "$COOKIE" ]; then
    echo "    -> Session cookie injected. Bypassing unauthenticated perimeter."
    COOKIE_FLAG="--cookie=$COOKIE"
fi

# SLA Timer: 7.5 Minutes (450 seconds) hard limit to ensure Orchestrator meets 15m global SLA.
# --level=3 & --risk=3: Forces deep HTTP header and OR-based blind injections.
timeout 450 sqlmap -u "$TARGET" \
  --batch \
  --crawl=3 \
  --crawl-exclude="logout|logoff|exit|quit|disconnect" \
  --forms \
  --threads=5 \
  --level=3 \
  --risk=3 \
  --random-agent \
  --flush-session \
  --fresh-queries \
  $COOKIE_FLAG \
  --output-dir="$SQLMAP_DATA_DIR" \
  > "$SQLMAP_RAW" 2>&1 || true

echo "[+] SQLMap execution bounded by SLA. Processing artifacts..."

# --- Phase 2: Data Extraction & Pipeline Integration ---
echo "[*] Phase 2/2: Extracting Vulnerability Signatures..."

python3 -c '
import re, sys, os, base64

def b64(text):
    return base64.b64encode(str(text).encode("utf-8")).decode("utf-8")

raw_file = "'"$SQLMAP_RAW"'"

if not os.path.exists(raw_file):
    sys.exit(0)

with open(raw_file, "r", encoding="utf-8", errors="ignore") as f:
    content = f.read()

blocks = content.split("---")
findings_count = 0

for block in blocks:
    if "Parameter:" in block and "Payload:" in block:
        param_match = re.search(r"Parameter:\s*(.+)", block)
        title_match = re.search(r"Title:\s*(.+)", block)
        payload_match = re.search(r"Payload:\s*(.+)", block)
        
        if param_match and payload_match:
            param = param_match.group(1).strip()
            title = title_match.group(1).strip() if title_match else "SQL Injection"
            payload = payload_match.group(1).strip()
            
            finding = f"SQL Injection Vulnerability on {param}"
            evidence = f"Type: {title}\\nPayload: {payload}"
            remediation = "Implement parameterized queries (prepared statements). Sanitize and validate all user inputs."
            
            # B64 Encoded to prevent bash word-splitting on complex SQL payloads
            print(f"{b64(\"CRITICAL\")}|{b64(finding)}|{b64(evidence)}|{b64(remediation)}")
            findings_count += 1

if findings_count == 0 and "sqlmap identified the following injection point(s)" in content:
    print(f"{b64(\"CRITICAL\")}|{b64(\"Potential SQL Injection Detected\")}|{b64(\"Review SQLMap raw logs for payload details.\")}|{b64(\"Implement parameterized queries.\")}")

' | while IFS='|' read -r sev fin evi rem; do
    sev_dec=$(echo "$sev" | base64 -d)
    fin_dec=$(echo "$fin" | base64 -d)
    evi_dec=$(echo "$evi" | base64 -d)
    rem_dec=$(echo "$rem" | base64 -d)
    
    evi_decoded=$(echo -e "$evi_dec")
    add_finding "$sev_dec" "$fin_dec" "$evi_decoded" "$rem_dec"
done

echo "[+] SQLMap Deep Scan finalized."
exit 0
