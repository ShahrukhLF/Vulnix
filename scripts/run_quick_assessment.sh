#!/bin/bash

# =========================================================================
# Vulnix Orchestrator (Quick Assessment Mode)
# Chaining ZAP and SQLMap for a single-click, non-technical user experience.
# =========================================================================

set -e

# 1. Input Validation
if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <target_url> <output_directory>" >&2
  exit 1
fi

TARGET="$1"
OUTPUT_DIR="$2"
GUI_SUMMARY="$OUTPUT_DIR/summary.json"
USER_REPORT="$OUTPUT_DIR/report.txt"

# 2. Workspace Initialization
echo "[*] Initializing Vulnix Assessment Workspace..."
mkdir -p "$OUTPUT_DIR"

# Reset the summary JSON and text report so we start fresh
echo "[]" > "$GUI_SUMMARY"
echo "=================================================================" > "$USER_REPORT"
echo "             VULNIX AUTOMATED FULL ASSESSMENT REPORT             " >> "$USER_REPORT"
echo "=================================================================" >> "$USER_REPORT"
echo "Target: $TARGET" >> "$USER_REPORT"
echo "Date: $(date)" >> "$USER_REPORT"
echo "Mode: Quick Scan (Live Demo)" >> "$USER_REPORT"
echo -e "=================================================================\n" >> "$USER_REPORT"

# Capture start time for performance tracking
START_TIME=$(date +%s)

# =========================================================================
# PHASE 1: Generalized Vulnerability Mapping (OWASP ZAP)
# =========================================================================
echo ""
echo "[*] ============================================================="
echo "[*] STAGE 1: Launching OWASP ZAP (The Scout)..."
echo "[*] ============================================================="
# We use || true so if one tool fails, it doesn't crash the whole orchestrator
sudo ./scripts/scan_zap_quick.sh "$TARGET" "$OUTPUT_DIR" || true
echo "[+] Stage 1 Complete. Generalized vulnerabilities mapped."


# =========================================================================
# PHASE 2: Deep Database Injection Testing (SQLMap)
# =========================================================================
echo ""
echo "[*] ============================================================="
echo "[*] STAGE 2: Launching SQLMap (The Sniper)..."
echo "[*] ============================================================="
sudo ./scripts/scan_sqlmap_quick.sh "$TARGET" "$OUTPUT_DIR" || true
echo "[+] Stage 2 Complete. Database integrity tested."


# =========================================================================
# PHASE 3: Wrap-up & Output Generation
# =========================================================================
echo ""
echo "[*] ============================================================="
echo "[*] ASSESSMENT COMPLETE"
echo "[*] ============================================================="

# Calculate execution time
END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))
MINUTES=$((TOTAL_TIME / 60))
SECONDS=$((TOTAL_TIME % 60))

# Count the total vulnerabilities safely using jq
if [ -f "$GUI_SUMMARY" ]; then
  TOTAL_VULNS=$(jq '. | length' "$GUI_SUMMARY")
else
  TOTAL_VULNS=0
fi

echo "[+] Total Scan Time: ${MINUTES}m ${SECONDS}s"
echo "[+] Total Vulnerabilities Found: $TOTAL_VULNS"
echo "[+] Unified Report saved to: $GUI_SUMMARY"
echo "[*] Ready for GUI ingestion!"

exit 0
