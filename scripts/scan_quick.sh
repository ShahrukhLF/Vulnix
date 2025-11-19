#!/bin/bash

# ==============================================================================
# Vulnix - Quick Network Scan (scan_quick.sh)
#
# GOAL: Complete in < 2.5 minutes.
# STRATEGY: Generalized scan of the "Top 50" most frequent ports + Criticals.
#           Works on Windows, Linux, or Network Devices.
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

# Output Files
NMAP_XML="$OUTPUT_DIR/nmap_quick.xml"
NMAP_TXT="$OUTPUT_DIR/nmap_quick.txt"
ENUM_JSON="$OUTPUT_DIR/enum4linux.json"
EXPLOIT_JSON="$OUTPUT_DIR/searchsploit.json"
EXPLOIT_LOG="$OUTPUT_DIR/searchsploit.log"
SEARCHSPLOIT_MESSY="$OUTPUT_DIR/searchsploit_messy.log"

GUI_SUMMARY="$OUTPUT_DIR/summary.json"
USER_REPORT="$OUTPUT_DIR/report.txt"

# --- "General + Safety Net" Port List ---
# 1. Standard: FTP(21), SSH(22), Telnet(23), SMTP(25), DNS(53), Web(80/443/8080), 
#              POP3(110), RPC(111), SMB(139/445), IMAP(143), HTTPS(443), 
#              RDP(3389), VNC(5900), MySQL(3306), Postgres(5432).
# 2. Demo Safety Net: High ports often found on vulnerable labs (Ingres, IRC, JavaRMI).
TARGET_PORTS="21,22,23,25,53,80,110,111,135,139,143,443,445,1099,1433,1521,1524,2049,2121,3306,3389,5432,5900,6000,6667,8080,8180"

# --- Reporting Function ---
add_finding() {
  local severity="$1"
  local finding="$2"
  local evidence="$3"
  local remediation="$4"

  # Text Report
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

  # JSON Summary (for GUI)
  local temp_json
  temp_json=$(jq --arg sev "$severity" --arg fin "$finding" --arg evi "$evidence" --arg rem "$remediation" \
    '. += [{"severity": $sev, "finding": $fin, "evidence": $evi, "remediation": $rem}]' "$GUI_SUMMARY")
  echo "$temp_json" > "$GUI_SUMMARY"
}

# --- Initialization ---
echo "[]" > "$GUI_SUMMARY"
echo "--- Vulnix Quick Assessment Report ---" > "$USER_REPORT"
echo "Target: $TARGET_IP" >> "$USER_REPORT"
echo "Date: $(date)" >> "$USER_REPORT"
echo -e "\n--- Summary of Findings ---\n" >> "$USER_REPORT"

# --- Phase 1: Fast Nmap Scan ---
echo "[*] Phase 1/3: Quick Service Scan..."
# -sV: Version detection
# --version-light: Faster version detection (2 vs 9 probes)
# --open: Only show open ports
nmap -sV --version-light --open -p "$TARGET_PORTS" -oX "$NMAP_XML" -oN "$NMAP_TXT" "$TARGET_IP"

echo "[+] Nmap complete."

# --- Phase 2: Adaptive Enumeration ---
# Only run Enum4linux if SMB (445) is actually open.
if grep -q "445/tcp open" "$NMAP_TXT"; then
    echo "[*] Phase 2/3: SMB Detected. Running Enum4linux..."
    enum4linux-ng -U -S -o -oJ "$ENUM_JSON" "$TARGET_IP" > /dev/null 2>&1 || true
else
    echo "[*] Phase 2/3: No SMB detected. Skipping enumeration."
fi

# --- Phase 3: Parsing & Mapping ---
echo "[*] Phase 3/3: Mapping Vulnerabilities..."

# 3a. Run Searchsploit (Clean Output Fix)
searchsploit --nmap "$NMAP_XML" -j > "$SEARCHSPLOIT_MESSY" 2> "$EXPLOIT_LOG"
grep '^{' "$SEARCHSPLOIT_MESSY" > "$EXPLOIT_JSON" || true

# 3b. Parse Searchsploit
while read -r service; do
  port=$(echo "$service" | jq -r '.Port')
  svc=$(echo "$service" | jq -r '.Title')
  # We just take the first exploit as an example for the quick report
  exploit=$(echo "$service" | jq -r '.Exploits[0].Title')

  add_finding "HIGH" "Vulnerable Service: $svc" "Port $port is running a version with known exploits." "Ref: $exploit. Update service immediately."
done < <(jq -c '.RESULTS_EXPLOIT[] | select(.Exploits | length > 0)' "$EXPLOIT_JSON" 2>/dev/null)

# 3c. Manual 'Demo Winners' (Guaranteed Findings)
# Even in a generalized script, these checks are safe because they look for specific TEXT signatures.
if grep -q "vsftpd 2.3.4" "$NMAP_TXT"; then
    add_finding "CRITICAL" "VSFTPD Backdoor" "Port 21: vsftpd 2.3.4 detected." "Remove this backdoor immediately."
fi
if grep -q "telnet" "$NMAP_TXT"; then
    add_finding "HIGH" "Insecure Telnet Service" "Port 23: Telnet is cleartext." "Replace with SSH."
fi
if grep -q "UnrealIRCd" "$NMAP_TXT"; then
    add_finding "CRITICAL" "UnrealIRCd Backdoor" "Port 6667: Malicious IRC version." "Reinstall clean version."
fi
if grep -q "java-rmi" "$NMAP_TXT"; then
    add_finding "CRITICAL" "Java RMI Vulnerability" "Port 1099: Java RMI Registry." "Firewall this port, highly vulnerable to RCE."
fi

echo "[+] Quick Scan Finished."
exit 0
