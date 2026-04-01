#!/bin/bash

# Vulnix SQLMap Automated Wrapper
# Performs automated SQL injection detection, crawling, and form testing.

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
echo "Vulnix SQLMap Assessment - Target: $TARGET" >> "$USER_REPORT"
echo "Date: $(date)" >> "$USER_REPORT"
echo "-----------------------------------------------------------------" >> "$USER_REPORT"

echo "[*] Phase 1/2: Running SQLMap Automated Scan on $TARGET..."

COOKIE_FLAG=""
if [ ! -z "$COOKIE" ]; then
    echo "    -> Using Authenticated Session Cookie!"
    COOKIE_FLAG="--cookie=$COOKIE"
fi

sqlmap -u "$TARGET" \
  --batch \
  --crawl=2 \
  --forms \
  --smart \
  --level=2 \
  --risk=2 \
  --random-agent \
  --flush-session \
  --fresh-queries \
  $COOKIE_FLAG \
  --output-dir="$SQLMAP_DATA_DIR" \
  > "$SQLMAP_RAW" 2>&1 || true

echo "[+] SQLMap execution complete. Processing results..."
echo "[*] Phase 2/2: Extracting Vulnerability Signatures..."

python3 -c '
import re, sys, os

raw_file = "'"$SQLMAP_RAW"'"

if not os.path.exists(raw_file):
    sys.exit(0)

with open(raw_file, "r") as f:
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
            
            print(f"CRITICAL|{finding}|{evidence}|{remediation}")
            findings_count += 1

if findings_count == 0 and "sqlmap identified the following injection point(s)" in content:
    print("CRITICAL|Potential SQL Injection Detected|Review SQLMap raw logs for payload details.|Implement parameterized queries.")

' | while IFS='|' read -r sev fin evi rem; do
    evi_decoded=$(echo -e "$evi")
    add_finding "$sev" "$fin" "$evi_decoded" "$rem"
done

echo "[+] SQLMap Scan Finished."
exit 0
