#!/usr/bin/env bash
################################################################################
# scan_web.sh
#
# Vulnix — Web app scanner for FYP-I (Nmap HTTP + Nikto + SearchSploit + 2FA check)
#
# Purpose:
#   - Run quick Nmap HTTP probes and Nikto (non-destructive) against a target web
#     application (e.g., Juice Shop). Attempt to detect 2FA presence automatically.
#   - Map findings to Exploit-DB via searchsploit when possible.
#   - Produce ONE single user-friendly TXT report (results/<target>/report_<ts>.txt).
#
# Usage:
#   sudo ./scripts/scan_web.sh <target-url-or-ip-with-port>
# Example:
#   sudo ./scripts/scan_web.sh http://192.168.78.101:3000
#
# Notes:
#   - Intended for authorized lab targets ONLY.
#   - Nikto is noisy but non-destructive by default; use in lab/demo environments.
################################################################################

set -euo pipefail
IFS=$'\n\t'

# ---------- args ----------
if [ "$#" -lt 1 ]; then
  echo "Usage: sudo $0 <target-url-or-ip-with-port>"
  exit 2
fi
TARGET_RAW="$1"

# ---------- require root ----------
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root (sudo)." >&2
  exit 1
fi

# ---------- prepare names & output dir ----------
SAFE="$(echo "${TARGET_RAW}" | sed -E 's#https?://##; s#[/:]#_##g')"
OUTDIR="results/${SAFE}"
mkdir -p "${OUTDIR}"
TS="$(date +"%Y%m%d_%H%M%S")"

NMAP_HTTP_TXT="${OUTDIR}/nmap_http_${TS}.txt"
NMAP_HTTP_XML="${OUTDIR}/nmap_http_${TS}.xml"
NIKTO_OUT="${OUTDIR}/nikto_${TS}.txt"
SS_OUT="${OUTDIR}/searchsploit_${TS}.txt"
CVES_NMAP_HTTP="${OUTDIR}/cves_from_nmap_http_${TS}.txt"
CVES_SS_HTTP="${OUTDIR}/cves_from_searchsploit_http_${TS}.txt"
TWOFA_OUT="${OUTDIR}/2fa_check_${TS}.txt"
REPORT="${OUTDIR}/report_${TS}.txt"

echo "[*] Vulnix web scan starting for: ${TARGET_RAW}"
echo "[*] Results directory: ${OUTDIR}"
echo ""

# ---------- 1) Nmap HTTP probes ----------
# Extract host for nmap (strip protocol)
TARGET_HOST="$(echo "${TARGET_RAW}" | awk -F[/:] '{print $4}')"
echo "[*] 1) Running Nmap HTTP probes (service/version + http-scripts)..."
sudo nmap -sV -p 80,443,3000,8080 --script "http-title,http-headers,http-enum" "${TARGET_HOST}" -oN "${NMAP_HTTP_TXT}" -oX "${NMAP_HTTP_XML}" || true
echo "[*] Nmap HTTP saved: ${NMAP_HTTP_TXT}"
echo ""

# ---------- 2) Nikto (non-destructive) ----------
echo "[*] 2) Running Nikto (webserver checks; non-destructive)..."
nikto -h "${TARGET_RAW}" -output "${NIKTO_OUT}" -Format txt || true
echo "[*] Nikto saved: ${NIKTO_OUT}"
echo ""

# ---------- 3) 2FA presence automated check (lightweight, non-intrusive) ----------
# This looks for textual indicators of 2FA presence (OTP, authenticator, 'two factor', 'verify', etc.)
echo "[*] 3) Running lightweight 2FA presence check (non-intrusive)..."
touch "${TWOFA_OUT}"
main_page="$(curl -s "${TARGET_RAW}" || true)"
login_page="$(curl -s "${TARGET_RAW%/}/login" || true)"
account_page="$(curl -s "${TARGET_RAW%/}/account" || true)"
# search common tokens
if echo "${main_page}" | grep -Eqi "2fa|two[-_ ]?factor|authenticator|otp|one-time|verify|mfa|google authent" >/dev/null; then
  echo "[+] 2FA-related text found on main page." | tee -a "${TWOFA_OUT}"
else
  echo "[-] No obvious 2FA text on main page." | tee -a "${TWOFA_OUT}"
fi
if echo "${login_page}" | grep -Eqi "2fa|two[-_ ]?factor|authenticator|otp|one-time|verify|mfa|google authent|sms" >/dev/null; then
  echo "[+] 2FA-related text found on /login page." | tee -a "${TWOFA_OUT}"
fi
if echo "${account_page}" | grep -Eqi "2fa|authenticator|otp|enable|two[-_ ]?factor|mfa" >/dev/null; then
  echo "[+] 2FA-related text found on /account or settings page." | tee -a "${TWOFA_OUT}"
fi
echo "[*] 2FA check saved: ${TWOFA_OUT}"
echo ""

# ---------- 4) Map HTTP findings to Exploit-DB (searchsploit) ----------
echo "[*] 4) Mapping http findings to Exploit-DB using searchsploit --nmap (if available)..."
if command -v searchsploit >/dev/null 2>&1 && [ -s "${NMAP_HTTP_XML}" ]; then
  searchsploit --nmap "${NMAP_HTTP_XML}" 2>/dev/null > "${SS_OUT}" || true
else
  # fallback: extract probable packages from nmap / nikto and run keyword search
  egrep -i 'apache|nginx|php|tomcat|wordpress|drupal|joomla|openssl|java|node|express' "${NMAP_HTTP_TXT}" "${NIKTO_OUT}" 2>/dev/null | sed -E 's/[^[:alnum:]._-]/ /g' | tr ' ' '\n' | egrep -i 'apache|nginx|php|tomcat|wordpress|drupal|joomla|openssl|java|node|express' | sort -u > "${OUTDIR}/http_prod_keywords_${TS}.txt" || true
  > "${SS_OUT}" || true
  if [ -s "${OUTDIR}/http_prod_keywords_${TS}.txt" ]; then
    while read -r p; do
      [ -z "${p}" ] && continue
      echo "==== searchsploit ${p} ====" >> "${SS_OUT}"
      searchsploit "${p}" 2>/dev/null | head -n 20 >> "${SS_OUT}" || true
      echo "" >> "${SS_OUT}"
    done < "${OUTDIR}/http_prod_keywords_${TS}.txt"
  else
    echo "[!] No product strings found for HTTP searchsploit fallback." > "${SS_OUT}"
  fi
fi
echo ""

# ---------- 5) Extract CVEs ----------
grep -Eo "CVE-[0-9]{4}-[0-9A-Za-z.-]{4,}" "${NMAP_HTTP_TXT}" 2>/dev/null | sort -u > "${CVES_NMAP_HTTP}" || true
grep -Eo "CVE-[0-9]{4}-[0-9A-Za-z.-]{4,}" "${SS_OUT}" 2>/dev/null | sort -u > "${CVES_SS_HTTP}" || true

# ---------- 6) Build single user-friendly TXT report ----------
echo "[*] 5) Building web report: ${REPORT}"
{
  echo "Vulnix — Web Scan Report"
  echo "Target: ${TARGET_RAW}"
  echo "Timestamp: ${TS}"
  echo ""
  echo "EXECUTIVE SUMMARY"
  echo "---------------"
  if [ -s "${CVES_SS_HTTP}" ]; then
    echo "Publicly-known vulnerabilities (CVE/exploit matches) were identified. See 'CVE/Exploit Matches' below."
  else
    echo "No direct Exploit-DB matches were automatically found. Manual verification may still be needed."
  fi
  echo ""
  echo "NON-TECHNICAL RECOMMENDATIONS"
  echo "- If this web app is public-facing, update all server and application components to the latest stable versions."
  echo "- Protect admin and debugging pages; add authentication and limit access via network controls."
  echo "- Ensure strong session cookie settings (HttpOnly, Secure), input validation, and avoid exposing sensitive files/backups."
  echo ""
  echo "DETAILED FINDINGS (evidence & plain explanation)"
  echo "-----------------------------------------------"
  echo ""
  echo "1) Nmap HTTP results (excerpt)"
  echo "-----------------------------"
  sed -n '1,60p' "${NMAP_HTTP_TXT}" || true
  echo ""
  echo "2) Nikto findings (selected highlights)"
  echo "---------------------------------------"
  if [ -s "${NIKTO_OUT}" ]; then
    # present Nikto interesting lines first
    grep -E "\+ /|Server:|X-Powered-By|cookie|Warning|Uncommon header|robots.txt" "${NIKTO_OUT}" | sed -n '1,160p' || head -n 160 "${NIKTO_OUT}"
  else
    echo "  (no nikto output)"
  fi
  echo ""
  echo "3) 2FA automated presence check"
  echo "-------------------------------"
  if [ -s "${TWOFA_OUT}" ]; then
    cat "${TWOFA_OUT}"
  else
    echo "  (no 2FA indicators found)"
  fi
  echo ""
  echo "4) CVE / Exploit Matches (excerpt)"
  echo "----------------------------------"
  if [ -s "${CVES_SS_HTTP}" ]; then
    cat "${CVES_SS_HTTP}"
    echo ""
  fi
  if [ -s "${SS_OUT}" ]; then
    sed -n '1,120p' "${SS_OUT}"
  else
    echo "  No searchsploit matches found."
  fi
  echo ""
  echo "PRIORITIZED REMEDIATION (plain language)"
  echo "---------------------------------------"
  if grep -iq "Server:" "${NIKTO_OUT}" 2>/dev/null; then
    echo "- Visible server banner: hide server banners or update the server to a supported, patched version."
  fi
  if grep -iq "robots.txt" "${NIKTO_OUT}" 2>/dev/null; then
    echo "- robots.txt reveals paths: ensure sensitive directories are not publicly accessible."
  fi
  if grep -iq "cookie" "${NIKTO_OUT}" 2>/dev/null; then
    echo "- Cookie flags: ensure cookies are HttpOnly and Secure where appropriate."
  fi
  if [ -s "${CVES_SS_HTTP}" ] || [ -s "${CVES_NMAP_HTTP}" ]; then
    echo "- Known CVEs were detected: prioritize patching the listed components."
  fi
  echo ""
  echo "HOW TO VERIFY (non-technical)"
  echo "-------------------------------"
  echo "- After applying updates, re-run this script. Fewer findings should appear in the top sections."
  echo ""
  echo "TECHNICAL EVIDENCE (raw excerpts)"
  echo "--------------------------------"
  echo "Nmap HTTP (top lines):"
  sed -n '1,120p' "${NMAP_HTTP_TXT}" || true
  echo ""
  echo "Nikto (top lines):"
  sed -n '1,160p' "${NIKTO_OUT}" || true
  echo ""
  echo "SearchSploit excerpt:"
  if [ -s "${SS_OUT}" ]; then
    sed -n '1,80p' "${SS_OUT}"
  else
    echo "  (no searchsploit matches)"
  fi
  echo ""
  echo "END OF REPORT"
  echo "=============="
} > "${REPORT}"

echo "[+] Web scan complete. Report: ${REPORT}"
echo "[*] Raw outputs are in: ${OUTDIR}"
exit 0
