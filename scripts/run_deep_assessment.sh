#!/bin/bash
# ==============================================================================
# Vulnix DAST Master Orchestrator
# Module: Deep Assessment Master Pipeline
# Description: Chains ZAP (Active Perimeter) and SQLMap (Exhaustive DB Integrity)
# into a unified, framework-agnostic testing workflow. Globally bounded to 15m.
# ==============================================================================

set -e

if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <target_url> <output_directory> [username] [password]" >&2
  exit 1
fi

TARGET="$1"
OUTPUT_DIR="$2"
GUI_SUMMARY="$OUTPUT_DIR/summary.json"
USER_REPORT="$OUTPUT_DIR/report.txt"

# --- Workspace Initialization ---
echo "[*] Initializing Vulnix DEEP Assessment Workspace..."
mkdir -p "$OUTPUT_DIR"

echo "[]" > "$GUI_SUMMARY"
echo "=================================================================" > "$USER_REPORT"
echo "          VULNIX AUTOMATED DEEP ASSESSMENT REPORT                " >> "$USER_REPORT"
echo "=================================================================" >> "$USER_REPORT"
echo "Target: $TARGET" >> "$USER_REPORT"
echo "Date: $(date)" >> "$USER_REPORT"
echo "Mode: Deep Scan (15-Minute Bounded Orchestration)" >> "$USER_REPORT"
echo -e "=================================================================\n" >> "$USER_REPORT"

START_TIME=$(date +%s)

# --- Phase 0: Authentication Handshake ---
# Uses IPC to resolve credentials into a universal session token
AUTH_COOKIE=""
if [ ! -z "$3" ] && [ ! -z "$4" ]; then
    echo "[*] Credentials detected. Initiating Authentication Sequence..."
    LOGIN_URL="$TARGET" 
    USERNAME="$3"
    PASSWORD="$4"
    
    LOGIN_OUTPUT=$(python3 ./scripts/auto_login.py "$LOGIN_URL" "$USERNAME" "$PASSWORD")
    
    if [[ "$LOGIN_OUTPUT" == SUCCESS* ]]; then
        AUTH_COOKIE=$(echo "$LOGIN_OUTPUT" | cut -d'|' -f2)
        echo "[+] Authentication Successful. Session cookie captured."
    else
        echo "[-] Authentication Failed. Proceeding with unauthenticated scan..."
        echo "    Reason: $LOGIN_OUTPUT"
    fi
fi

# --- Phase 1: Structural Vulnerability Mapping (OWASP ZAP) ---
echo ""
echo "[*] ============================================================="
echo "[*] STAGE 1: Launching OWASP ZAP (Deep Active Scan)..."
echo "[*] ============================================================="
# Bounded to 7.5 minutes max execution
sudo ./scripts/scan_zap_deep.sh "$TARGET" "$OUTPUT_DIR" "$AUTH_COOKIE" || true
echo "[+] Stage 1 Complete. Deep vulnerability mapping finished."

# --- Phase 2: Database Integrity Testing (SQLMap) ---
echo ""
echo "[*] ============================================================="
echo "[*] STAGE 2: Launching SQLMap (Exhaustive Crawl & Injection)..."
echo "[*] ============================================================="
# Bounded to 7.5 minutes max execution
sudo ./scripts/scan_sqlmap_deep.sh "$TARGET" "$OUTPUT_DIR" "$AUTH_COOKIE" || true
echo "[+] Stage 2 Complete. Database integrity deeply tested."

# --- Phase 3: Telemetry & Finalization ---
echo ""
echo "[*] ============================================================="
echo "[*] DEEP ASSESSMENT COMPLETE"
echo "[*] ============================================================="

END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))
MINUTES=$((TOTAL_TIME / 60))
SECONDS=$((TOTAL_TIME % 60))

# Parse unified JSON array to calculate total findings gracefully
if [ -f "$GUI_SUMMARY" ]; then
  TOTAL_VULNS=$(jq '. | length' "$GUI_SUMMARY")
else
  TOTAL_VULNS=0
fi

echo "[+] Total Deep Scan Time: ${MINUTES}m ${SECONDS}s"
echo "[+] Total Vulnerabilities Found: $TOTAL_VULNS"
echo "[+] Unified Report saved to: $GUI_SUMMARY"
echo "[*] Ready for GUI ingestion."

exit 0
