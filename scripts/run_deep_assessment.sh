#!/bin/bash

# =========================================================================
# Vulnix Orchestrator (DEEP Assessment Mode)
# Chaining ZAP Active Scan and SQLMap Full Crawl for production-grade testing.
# =========================================================================

set -e

if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <target_url> <output_directory>" >&2
  exit 1
fi

TARGET="$1"
OUTPUT_DIR="$2"
GUI_SUMMARY="$OUTPUT_DIR/summary.json"
USER_REPORT="$OUTPUT_DIR/report.txt"

echo "[*] Initializing Vulnix DEEP Assessment Workspace..."
mkdir -p "$OUTPUT_DIR"

echo "[]" > "$GUI_SUMMARY"
echo "=================================================================" > "$USER_REPORT"
echo "          VULNIX AUTOMATED DEEP ASSESSMENT REPORT                " >> "$USER_REPORT"
echo "=================================================================" >> "$USER_REPORT"
echo "Target: $TARGET" >> "$USER_REPORT"
echo "Date: $(date)" >> "$USER_REPORT"
echo "Mode: Deep Scan (Production)" >> "$USER_REPORT"
echo -e "=================================================================\n" >> "$USER_REPORT"

START_TIME=$(date +%s)

# =========================================================================
# PHASE 1: Active Vulnerability Scanning (OWASP ZAP NATIVE)
# =========================================================================
echo ""
echo "[*] ============================================================="
echo "[*] STAGE 1: Launching OWASP ZAP DEEP (The Heavy Artillery)..."
echo "[*] ============================================================="
sudo ./scripts/scan_zap_deep.sh "$TARGET" "$OUTPUT_DIR" || true
echo "[+] Stage 1 Complete. Deep vulnerability mapping finished."

# =========================================================================
# PHASE 2: Deep Database Injection Testing (SQLMap)
# =========================================================================
echo ""
echo "[*] ============================================================="
echo "[*] STAGE 2: Launching SQLMap DEEP (Full Crawl & Time-Based)..."
echo "[*] ============================================================="
sudo ./scripts/scan_sqlmap_deep.sh "$TARGET" "$OUTPUT_DIR" || true
echo "[+] Stage 2 Complete. Database integrity deeply tested."

# =========================================================================
# PHASE 3: Wrap-up & Output Generation
# =========================================================================
echo ""
echo "[*] ============================================================="
echo "[*] DEEP ASSESSMENT COMPLETE"
echo "[*] ============================================================="

END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))
MINUTES=$((TOTAL_TIME / 60))
SECONDS=$((TOTAL_TIME % 60))

if [ -f "$GUI_SUMMARY" ]; then
  TOTAL_VULNS=$(jq '. | length' "$GUI_SUMMARY")
else
  TOTAL_VULNS=0
fi

echo "[+] Total Deep Scan Time: ${MINUTES}m ${SECONDS}s"
echo "[+] Total Vulnerabilities Found: $TOTAL_VULNS"
echo "[+] Unified Report saved to: $GUI_SUMMARY"
echo "[*] Ready for GUI ingestion!"

exit 0
