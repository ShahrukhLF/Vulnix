#!/bin/bash

# ==============================================================================
# Vulnix - Network Scanning Script (scan_network.sh)
#
# This script is tuned for a 5-minute FYP-I demonstration.
# It's designed to run quickly yet thoroughly against Metasploitable2
# to find and report its most critical vulnerabilities.
#
# ==============================================================================

# --- Script Configuration ---
set -e
set -o pipefail

# --- Input Validation ---
if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Error: Missing arguments." >&2
  echo "Usage: $0 <target_ip> <output_directory>" >&2
  exit 1
fi

# --- Variable Setup ---
TARGET_IP="$1"
OUTPUT_DIR="$2"

# Define the file paths for our raw tool output.
NMAP_XML="$OUTPUT_DIR/nmap_raw.xml"
NMAP_TXT="$OUTPUT_DIR/nmap_raw.txt"
NMAP_VULN_TXT="$OUTPUT_DIR/nmap_vuln_scan.txt"
ENUM_JSON="$OUTPUT_DIR/enum4linux_raw.json"

# We now use a temp file for searchsploit's messy output
SEARCHSPLOIT_MESSY="$OUTPUT_DIR/searchsploit_messy.log"
EXPLOIT_JSON="$OUTPUT_DIR/searchsploit_raw.json" # This will be clean JSON
EXPLOIT_LOG="$OUTPUT_DIR/searchsploit.log"

# These are the final, user-facing report files.
GUI_SUMMARY="$OUTPUT_DIR/summary.json" # For the GUI dashboard table
USER_REPORT="$OUTPUT_DIR/report.txt" # For the non-technical user

# The "Greatest Hits" port list for Metasploitable2.
TUNED_PORT_LIST="21,22,23,25,53,80,111,139,445,1099,1524,2049,2121,3306,5432,5900,6667,8180"

# --- Helper Function for Reporting ---
add_finding() {
  local severity="$1"
  local finding="$2"
  local evidence="$3"
  local remediation="$4"

  # 1. Add to the User's Text Report (using printf for formatted vars, echo for static lines)
  # This is the fix: Using 'echo' for static divider lines is safer.
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


  # 2. Add to the GUI's JSON Summary
  local temp_json
  temp_json=$(jq \
    --arg sev "$severity" \
    --arg fin "$finding" \
    --arg evi "$evidence" \
    --arg rem "$remediation" \
    '. += [{"severity": $sev, "finding": $fin, "evidence": $evi, "remediation": $rem}]' \
    "$GUI_SUMMARY")
  
  echo "$temp_json" > "$GUI_SUMMARY"
}

# --- Script Start ---
echo "--- Vulnix Network Scan Started ---"
echo "Target: $TARGET_IP"
echo "Output Directory: $OUTPUT_DIR"
echo "-----------------------------------"

echo "[]" > "$GUI_SUMMARY"
echo "--- VULNIX Network Assessment Report ---" > "$USER_REPORT"
echo "Target: $TARGET_IP" >> "$USER_REPORT"
echo "Date: $(date)" >> "$USER_REPORT"
echo -e "\n--- Summary of Findings ---\n" >> "$USER_REPORT"


# --- Phase 1/5: Fast Nmap Port Scan ---
echo "[*] Phase 1/5: Running Tuned Nmap Port Scan..."
nmap -sV -O --open \
  -p "$TUNED_PORT_LIST" \
  -oX "$NMAP_XML" \
  -oN "$NMAP_TXT" \
  "$TARGET_IP"
echo "[+] Nmap fast scan complete. (Saved to $NMAP_TXT)"


# --- Phase 2/5: Nmap Vulnerability Script Scan ---
echo "[*] Phase 2/5: Running Nmap Vulnerability Scripts..."
OPEN_PORTS=$(grep -oE '^[0-9]+/tcp open' "$NMAP_TXT" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')

if [ -n "$OPEN_PORTS" ]; then
  echo "[*] Found open ports: $OPEN_PORTS"
  echo "[*] Running --script=vuln on these ports. This will take 2-4 minutes..."
  
  nmap -sV --script=vuln \
    -p "$OPEN_PORTS" \
    -oN "$NMAP_VULN_TXT" \
    "$TARGET_IP"
    
  echo "[+] Nmap vulnerability scan complete. (Saved to $NMAP_VULN_TXT)"
else
  echo "[!] No open ports found in Phase 1. Skipping vulnerability scan."
fi


# --- Phase 3/5: Enum4Linux-ng Scan ---
echo "[*] Phase 3/5: Running Enum4Linux-ng Scan..."
enum4linux-ng -U -S -o -oJ "$ENUM_JSON" "$TARGET_IP" > /dev/null 2>&1 || true
echo "[+] Enum4Linux-ng scan complete. (Saved to $ENUM_JSON)"


# --- Phase 4/5: Exploit Mapping (Searchsploit) ---
echo "[*] Phase 4/5: Mapping exploits with Searchsploit..."

# 1. Run searchsploit and dump its *entire* output (JSON and text logs) to a messy file.
searchsploit --nmap "$NMAP_XML" -j > "$SEARCHSPLOIT_MESSY" 2> "$EXPLOIT_LOG"
# 2. Use 'grep' to find the line that starts with '{' (which is the JSON) and save it.
grep '^{' "$SEARCHSPLOIT_MESSY" > "$EXPLOIT_JSON" || true

echo "[+] Exploit mapping complete. (Logs in $EXPLOIT_LOG)"


# --- Phase 5/5: Parsing and Reporting ---
echo "[*] Phase 5/5: Parsing all results and generating reports..."

# --- 5a. Parse Searchsploit JSON ---
echo "[*] Parsing Searchsploit results..."
while read -r service; do
  port=$(echo "$service" | jq -r '.Port')
  svc=$(echo "$service" | jq -r '.Title')
  first_exploit=$(echo "$service" | jq -r '.Exploits[0].Title')

  add_finding \
    "HIGH" \
    "Exploit found for '$svc' on port $port" \
    "e.g., '$first_exploit'" \
    "Investigate and patch '$svc'. Update to the latest stable version."

done < <(jq -c '.RESULTS_EXPLOIT[] | select(.Exploits | length > 0)' "$EXPLOIT_JSON" 2>/dev/null)


# --- 5b. Parse Enum4Linux-ng JSON (for Samba 'usermap script') ---
echo "[*] Parsing Enum4Linux-ng results..."
if [ -f "$ENUM_JSON" ]; then
  usermap_finding=$(jq -r '.samba_info.policies | .[] | select(.name == "usermap_script") | .value' "$ENUM_JSON" 2>/dev/null)
  
  if [ -n "$usermap_finding" ] && [ "$usermap_finding" != "null" ]; then
    add_finding \
      "CRITICAL" \
      "Samba 'usermap script' Command Execution" \
      "Samba is configured with 'usermap script = $usermap_finding'" \
      "This is a critical backdoor. Remove the 'usermap script' line in smb.conf and restart Samba."
  fi
fi

# --- 5c. Parse Nmap Vuln Script Results ---
echo "[*] Parsing Nmap vulnerability script results..."
if [ -f "$NMAP_VULN_TXT" ] && grep -q "VULNERABLE:" "$NMAP_VULN_TXT"; then
  add_finding \
    "HIGH" \
    "Nmap Script Vulnerabilities Found" \
    "Nmap's --script=vuln found one or more vulnerabilities. See 'nmap_vuln_scan.txt' for details." \
    "Review the nmap_vuln_scan.txt file in the results folder and patch accordingly."
fi

# --- 5d. Manual Grep for "Demo Winners" ---
echo "[*] Running manual 'demo-winner' checks..."

if grep -q "21/tcp.*vsftpd 2.3.4" "$NMAP_TXT"; then
  add_finding \
    "CRITICAL" \
    "vsftpd 2.3.4 Backdoor" \
    "Service vsftpd 2.3.4 detected on port 21. This version is famously backdoored." \
    "Upgrade this FTP server immediately. (metasploit: exploit/unix/ftp/vsftpd_234_backdoor)."
fi

if grep -q "21/tcp.*Anonymous FTP login allowed" "$NMAP_TXT"; then
  add_finding \
    "HIGH" \
    "Anonymous FTP Login Enabled" \
    "Nmap scan on port 21 shows 'Anonymous FTP login allowed'" \
    "Disable anonymous FTP access unless absolutely required. Edit vsftpd.conf and set 'anonymous_enable=NO'."
fi

if grep -q "23/tcp.*telnet" "$NMAP_TXT"; then
  add_finding \
    "HIGH" \
    "Telnet Service Enabled" \
    "Telnet service detected on port 23." \
    "Telnet is insecure and transmits passwords in cleartext. Disable Telnet and use SSH instead."
fi

if grep -q "6667/tcp.*UnrealIRCd" "$NMAP_TXT"; then
  add_finding \
    "CRITICAL" \
    "UnrealIRCd Backdoor" \
    "Service UnrealIRCd detected on port 6667. This version is famously backdoored." \
    "Upgrade or remove this IRC server. (metasploit: exploit/unix/irc/unreal_ircd_3281_backdoor)."
fi

if grep -q "2121/tcp.*ProFTPD 1.3.1" "$NMAP_TXT"; then
  add_finding \
    "HIGH" \
    "ProFTPD 1.3.1 Command Execution" \
    "Service ProFTPD 1.3.1 detected on port 2121. This version has a known arbitrary code exec bug." \
    "Upgrade this FTP server immediately."
fi

if grep -q "1099/tcp.*java RMI" "$NMAP_TXT"; then
  add_finding \
    "CRITICAL" \
    "Java RMI Remote Code Execution" \
    "A Java RMI registry was detected on port 1099." \
    "This service is often misconfigured and allows remote code execution. (metasploit: exploit/multi/misc/java_rmi_server)."
fi

if grep -q "5900/tcp.*VNC" "$NMAP_TXT"; then
  add_finding \
    "MEDIUM" \
    "VNC Server Detected" \
    "A VNC server was found on port 5900. Metasploitable2's default password is 'password'." \
    "Ensure VNC is firewalled and uses a strong, unique password."
fi

if grep -q "5432/tcp.*PostgreSQL" "$NMAP_TXT"; then
  add_finding \
    "HIGH" \
    "PostgreSQL Database Open" \
    "PostgreSQL database detected on port 5432. The default 'postgres' user often has a weak password." \
    "Firewall this port. Ensure all database users have strong passwords."
fi


# --- Finalization ---
echo "[+] Parsing complete. Reports generated."
echo "--- Vulnix Network Scan Finished ---"

exit 0
