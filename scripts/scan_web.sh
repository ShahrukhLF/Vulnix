#!/bin/bash
# -------------------------------------------------------------------
# Vulnix Web Scanner
# Scans a target web app (e.g., OWASP Juice Shop) using:
# 1. Nmap (HTTP enumeration)
# 2. Nikto (web vuln scan)
# 3. OWASP ZAP (quick scan)
# 4. Lightweight 2FA keyword detection
# -------------------------------------------------------------------

set -e

if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root or with sudo"
  exit 1
fi

TARGET_RAW="$1"
if [ -z "$TARGET_RAW" ]; then
  echo "Usage: sudo ./scripts/scan_web.sh <target_url>"
  echo "Example: sudo ./scripts/scan_web.sh http://192.168.78.101:3000"
  exit 1
fi

# -------------------- Paths & Setup --------------------
ROOT_DIR=$(pwd)
OUTDIR="${ROOT_DIR}/results/web"
mkdir -p "$OUTDIR"

TS=$(date +"%Y%m%d_%H%M%S")

echo "[*] Starting Web Scan on: $TARGET_RAW"
echo "[*] Output Directory: $OUTDIR"

# -------------------- 1) Nmap Web Enumeration --------------------
echo "[*] Running Nmap HTTP enumeration (text + XML)..."
NMAP_TXT="${OUTDIR}/nmap_http_${TS}.txt"
NMAP_XML="${OUTDIR}/nmap_http_${TS}.xml"

# Extract host/IP from URL
TARGET_HOST=$(echo "$TARGET_RAW" | awk -F[/:] '{print $4}')

nmap -p 80,443,3000,8080 --script http-enum,http-title,http-methods,http-headers -oN "$NMAP_TXT" -oX "$NMAP_XML" "$TARGET_HOST"

# -------------------- 2) Nikto Web Scan --------------------
echo "[*] Running Nikto (webserver vulnerability checks; non-destructive)..."
NIKTO_OUT="${OUTDIR}/nikto_${TS}.txt"
nikto -h "$TARGET_RAW" -output "$NIKTO_OUT"

# -------------------- 3) OWASP ZAP CLI Quick Scan --------------------
echo "[*] Running OWASP ZAP (built-in CLI quick scan)..."
ZAP_OUT="${OUTDIR}/zap_${TS}.txt"

# Start ZAP in headless daemon mode (if not already)
if ! pgrep -x "zaproxy" >/dev/null; then
  echo "[*] Starting ZAP daemon..."
  nohup zaproxy -daemon -port 8090 -config api.disablekey=true >/dev/null 2>&1 &
  sleep 10
fi

# Run a quick scan with ZAP CLI
zap-cli --zap-url http://127.0.0.1 --zap-port 8090 quick-scan --self-contained "$TARGET_RAW" | tee "$ZAP_OUT" || echo "[!] ZAP quick scan completed with warnings."

# -------------------- 4) 2FA Misconfiguration Scan --------------------
echo "[*] Running lightweight 2FA presence check (non-intrusive)..."

TWOFA_FILE="${OUTDIR}/2fa_check_${TS}.txt"
touch "$TWOFA_FILE"

main_page=$(curl -s "$TARGET_RAW")
login_page=$(curl -s "${TARGET_RAW%/}/login")
account_page=$(curl -s "${TARGET_RAW%/}/account")

if echo "$main_page" | grep -Eqi "2fa|two[-_ ]?factor|authenticator|otp|verify"; then
  echo "[+] Possible 2FA feature or mention detected on main page." | tee -a "$TWOFA_FILE"
else
  echo "[-] No visible 2FA indicators found on main page." | tee -a "$TWOFA_FILE"
fi

if echo "$login_page" | grep -Eqi "2fa|two[-_ ]?factor|authenticator|otp|verify"; then
  echo "[+] Possible 2FA-related fields found on /login page." | tee -a "$TWOFA_FILE"
fi

if echo "$account_page" | grep -Eqi "2fa|authenticator|otp"; then
  echo "[+] Possible 2FA settings under /account page." | tee -a "$TWOFA_FILE"
fi

if [ ! -s "$TWOFA_FILE" ]; then
  echo "[-] No 2FA patterns detected across checked URLs." | tee -a "$TWOFA_FILE"
fi

# -------------------- 5) Wrap-Up --------------------
echo "[+] Web scan complete. Reports saved under: $OUTDIR"
