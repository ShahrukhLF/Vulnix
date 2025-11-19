#!/bin/bash

# ==============================================================================
# Vulnix - Deep Network Scan (scan_deep.sh)
#
# GOAL: Complete in 5-6 minutes.
# STRATEGY: Adaptive Deep Scan.
#           1. Discover ALL open ports.
#           2. Run intensive scripts (--script=vuln) ONLY on open ports.
# ==============================================================================

# --- Configuration ---
set -e
set -o pipefail

if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <target_ip> <output_directory>" >&2
  exit 1
fi

TARGET_IP="$1"
OUTPUT_DIR="$2"

# Files
NMAP_DISCOVERY="$OUTPUT_DIR/nmap_discovery.txt"
NMAP_VULN="$OUTPUT_DIR/nmap_vuln.txt"
NMAP_XML="$OUTPUT_DIR/nmap_vuln.xml"
EXPLOIT_JSON="$OUTPUT_DIR/searchsploit.json"
SEARCHSPLOIT_MESSY="$OUTPUT_DIR/searchsploit_messy.log"
EXPLOIT_LOG="$OUTPUT_DIR/searchsploit.log"
GUI_SUMMARY="$OUTPUT_DIR/summary.json"
USER_REPORT="$OUTPUT_DIR/report.txt"

# --- Reporting Function ---
add_finding() {
  local severity="$1"
  local finding="$2"
  local evidence="$3"
  local remediation="$4"

  echo "=================================================================" >> "$USER_REPORT"
  printf "| %-10s | %s\n" "SEVERITY" "$severity" >> "$USER_REPORT"
  echo "-----------------------------------------------------------------" >> "$USER_REPORT"
  echo "| FINDING:" >> "$USER_REPORT"
  printf "|   %s\n" "$finding" >> "$USER_REPORT"
  echo "| EVIDENCE:" >> "$USER_REPORT"
  printf "|   %s\n" "$evidence" >> "$USER_REPORT"
  echo "| REMEDIATION:" >> "$USER_REPORT"
  printf "|   %s\n" "$remediation" >> "$USER_REPORT"
  echo "=================================================================" >> "$USER_REPORT"
  echo "" >> "$USER_REPORT"

  local temp_json
  temp_json=$(jq --arg sev "$severity" --arg fin "$finding" --arg evi "$evidence" --arg rem "$remediation" \
    '. += [{"severity": $sev, "finding": $fin, "evidence": $evi, "remediation": $rem}]' "$GUI_SUMMARY")
  echo "$temp_json" > "$GUI_SUMMARY"
}

# --- Initialization ---
echo "[]" > "$GUI_SUMMARY"
echo "--- Vulnix Deep Assessment Report ---" > "$USER_REPORT"
echo "Target: $TARGET_IP" >> "$USER_REPORT"
echo "Date: $(date)" >> "$USER_REPORT"
echo -e "\n--- Deep Analysis Findings ---\n" >> "$USER_REPORT"

# --- Phase 1: Port Discovery (Adaptive) ---
echo "[*] Phase 1/3: Discovering all open ports..."
# Fast scan of top 2000 ports to define our attack surface
nmap -sS --top-ports 2000 --open -n "$TARGET_IP" -oG "$NMAP_DISCOVERY"

# Extract clean list of ports (e.g., "21,22,80")
OPEN_PORTS=$(grep "Ports:" "$NMAP_DISCOVERY" | grep -oE '[0-9]+/open' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')

if [ -z "$OPEN_PORTS" ]; then
    echo "[!] No open ports found. Aborting deep scan."
    exit 0
fi

echo "[*] Target Ports Identified: $OPEN_PORTS"

# --- Phase 2: Deep Script Scan ---
echo "[*] Phase 2/3: Running Vulnerability Scripts (This takes time)..."
# This is the "Heavy" lift. We run -sV and --script=vuln ONLY on valid ports.
# We set a timeout of 3 minutes per script to ensure we finish in time.
nmap -sV --script=vuln --script-timeout 3m -p "$OPEN_PORTS" -oN "$NMAP_VULN" -oX "$NMAP_XML" "$TARGET_IP"

echo "[+] Deep scan complete."

# --- Phase 3: Parsing Results ---
echo "[*] Phase 3/3: Analyzing Results..."

# 3a. Searchsploit Mapping (Fix applied)
searchsploit --nmap "$NMAP_XML" -j > "$SEARCHSPLOIT_MESSY" 2> "$EXPLOIT_LOG"
grep '^{' "$SEARCHSPLOIT_MESSY" > "$EXPLOIT_JSON" || true

while read -r service; do
  port=$(echo "$service" | jq -r '.Port')
  svc=$(echo "$service" | jq -r '.Title')
  exploit=$(echo "$service" | jq -r '.Exploits[0].Title')
  add_finding "HIGH" "Exploit Available: $svc" "Service on port $port matches exploit DB." "Reference: $exploit"
done < <(jq -c '.RESULTS_EXPLOIT[] | select(.Exploits | length > 0)' "$EXPLOIT_JSON" 2>/dev/null)

# 3b. Parse Nmap Script Output (The "Vuln" Scripts)
# If nmap found a CVE, we want to report it.
if grep -q "VULNERABLE:" "$NMAP_VULN"; then
    # We use a simple grep loop to find titles
    grep -B 1 "State: VULNERABLE" "$NMAP_VULN" | grep -v "State:" | grep -v "\-\-" | while read -r line; do
        # Clean up the line
        clean_line=$(echo "$line" | sed 's/|//g' | sed 's/_//g' | xargs)
        if [ ! -z "$clean_line" ]; then
            add_finding "CRITICAL" "Nmap Script: $clean_line" "Nmap --script=vuln confirmed this vulnerability." "See nmap_vuln.txt for full details."
        fi
    done
fi

# 3c. Manual Backups (Just in case scripts timed out)
if grep -q "vsftpd 2.3.4" "$NMAP_VULN"; then
    add_finding "CRITICAL" "VSFTPD Backdoor" "Port 21" "Remove backdoor."
fi
if grep -q "UnrealIRCd" "$NMAP_VULN"; then
    add_finding "CRITICAL" "UnrealIRCd Backdoor" "Port 6667" "Remove backdoor."
fi

echo "[+] Deep Scan Finished."
exit 0
