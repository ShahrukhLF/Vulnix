#!/usr/bin/env bash
################################################################################
# scan_web.sh (FAST DEMO VERSION)
#
# Vulnix — Web app scanner for FYP-I (Nmap HTTP + Nikto + SearchSploit + 2FA check)
#
# Purpose:
#   - Execute FAST Nmap HTTP probes and TIME-LIMITED Nikto (non-destructive).
#   - Target: OWASP Juice Shop (or similar vulnerable web application).
#   - Map findings to Exploit-DB via searchsploit.
#   - Produce ONE single user-friendly TXT report.
#
# Usage:
#   sudo ./scripts/scan_web.sh <target-url-or-ip-with-port>
# Example:
#   sudo ./scripts/scan_web.sh http://192.168.78.101:3000
#
# NOTE FOR DEMO: Nikto is limited to 3 minutes to ensure a fast demonstration.
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

# Extract host for Nmap (strip protocol/path, keep host:port if present)
TARGET_HOST_PORT="$(echo "${TARGET_RAW}" | sed -E 's#^https?://##; s#/.*$##')"

# ---------- 1) Nmap HTTP probes (Optimized for Speed) ----------
echo "[*] 1) Running FAST Nmap HTTP probes (service/version + http-scripts)..."
# -T5 (Aggressive Timing) is key for speed.
# --open: Only show ports that are 'open'.
# -Pn: Treat host as online.
sudo nmap -sV -T5 --open -p 80,443,3000,8080,8443 --script "http-title,http-headers,http-enum,http-methods" \
    -Pn "${TARGET_HOST_PORT}" -oN "${NMAP_HTTP_TXT}" -oX "${NMAP_HTTP_XML}" || true
echo "[*] Nmap HTTP saved: ${NMAP_HTTP_TXT}"
echo ""

# ---------- 2) Nikto (Time-Limited for Demo) ----------
echo "[*] 2) Running TIME-LIMITED Nikto (webserver checks; max 3 minutes)..."
# --maxtime 180 forces Nikto to stop after 3 minutes, which is critical for a fast demo.
nikto -h "${TARGET_RAW}" -output "${NIKTO_OUT}" -Format txt --maxtime 180 || true
echo "[*] Nikto saved: ${NIKTO_OUT}"
echo ""

# ---------- 3) 2FA presence automated check (lightweight, non-intrusive) ----------
echo "[*] 3) Running lightweight 2FA presence check (non-intrusive)..."
touch "${TWOFA_OUT}"
MAIN_URL="${TARGET_RAW%/}"
# Assume common login/account paths for a modern app like Juice Shop
LOGIN_URL="${MAIN_URL}/#/login"
ACCOUNT_URL="${MAIN_URL}/#/account" 

# Function to check and report
check_2fa() {
    local url="$1"
    local page_name="$2"
    # curl -s: silent; -L: follow redirects; --max-time: timeout
    local content="$(curl -s -L --max-time 10 "${url}" || true)"
    
    # search common tokens (case-insensitive)
    if echo "${content}" | grep -Eqi "2fa|two[-_ ]?factor|authenticator|otp|one-time|verify|mfa|google authent|sms" >/dev/null; then
        echo "[+] SUCCESS: 2FA-related text found on ${page_name}." | tee -a "${TWOFA_OUT}"
    else
        echo "[-] NO INDICATOR: No obvious 2FA-related text found on ${page_name}." | tee -a "${TWOFA_OUT}"
    fi
}

check_2fa "${MAIN_URL}" "main/landing page (${MAIN_URL})"
check_2fa "${LOGIN_URL}" "login page (${LOGIN_URL})"
check_2fa "${ACCOUNT_URL}" "profile/account page (${ACCOUNT_URL})"

echo "[*] 2FA check saved: ${TWOFA_OUT}"
echo ""


# ---------- 4) Map HTTP findings to Exploit-DB (searchsploit) ----------
echo "[*] 4) Mapping http findings to Exploit-DB using searchsploit --nmap (if available)..."
if command -v searchsploit >/dev/null 2>&1 && [ -s "${NMAP_HTTP_XML}" ]; then
    searchsploit --nmap "${NMAP_HTTP_XML}" 2>/dev/null > "${SS_OUT}" || true
else
    echo "[!] Searchsploit command or Nmap XML failed. Skipping exploit mapping." > "${SS_OUT}"
fi
echo ""

# ---------- 5) Extract CVEs ----------
grep -Eo "CVE-[0-9]{4}-[0-9A-Za-z.-]{4,}" "${NMAP_HTTP_TXT}" 2>/dev/null | sort -u > "${CVES_NMAP_HTTP}" || true
grep -Eo "CVE-[0-9]{4}-[0-9A-Za-z.-]{4,}" "${SS_OUT}" 2>/dev/null | sort -u > "${CVES_SS_HTTP}" || true

# ---------- 6) Build single user-friendly TXT report ----------
echo "[*] 5) Building web report: ${REPORT}"
{
    echo "VULNIX AUTOMATED WEB APPLICATION SECURITY ASSESSMENT REPORT"
    echo "=========================================================="
    echo "Target: ${TARGET_RAW}"
    echo "Date/Time: $(date -d "@${TS:0:14}" +"%Y-%m-%d %H:%M:%S")"
    echo "Tool/Script: Vulnix scan_web.sh (FYP-I - Demo Mode)"
    echo ""
    
    echo "### EXECUTIVE SUMMARY (Web Application) ###"
    echo "-------------------------------------------"
    # Juice Shop is intentionally insecure, so we look for telltale signs of failure.
    if [ -s "${CVES_SS_HTTP}" ]; then
        echo "CRITICAL RISK: Known public exploits (CVE/Exploit-DB matches) were identified for the underlying web server or components. Immediate patching is mandatory."
    elif grep -Eqi 'Backup|XSS|Directory Listing|Sensitive file' "${NIKTO_OUT}" 2>/dev/null; then
        echo "HIGH RISK: The scan detected severe misconfigurations, exposed sensitive files/directories, or cross-site scripting (XSS) indicators. This indicates significant risk to the application data and users."
    else
        echo "MODERATE RISK: No immediate public exploits were found, but general findings like exposed paths or information leakage were noted. Hardening and security-focused development practices are recommended."
    fi
    echo ""
    
    echo "### KEY NON-TECHNICAL RECOMMENDATIONS ###"
    echo "-----------------------------------------"
    if grep -iq "Server:" "${NIKTO_OUT}" 2>/dev/null; then
        echo "* INFO LEAKAGE: Configure the web server to suppress the 'Server' and 'X-Powered-By' headers."
    fi
    if grep -iq "XSS" "${NIKTO_OUT}" 2>/dev/null; then
        echo "* INPUT VALIDATION: Implement input validation and encoding routines across the application to prevent Cross-Site Scripting (XSS)."
    fi
    if grep -iq "robots.txt|backup" "${NIKTO_OUT}" 2>/dev/null; then
        echo "* FILE EXPOSURE: Ensure sensitive files (e.g., source code, database dumps, admin panels) are protected via authentication or removed."
    fi
    if grep -iq "cookie" "${NIKTO_OUT}" 2>/dev/null; then
        echo "* SESSION SECURITY: Ensure all session cookies have the **Secure** (HTTPS only) and **HttpOnly** flags set."
    fi
    if grep -qi "no indicator" "${TWOFA_OUT}" 2>/dev/null; then
        echo "* AUTHENTICATION: Review the implementation of Multi-Factor Authentication (MFA/2FA) or implement it if not present, as the scan found no indicators."
    fi
    echo ""
    
    echo "### DETAILED FINDINGS ###"
    echo "-------------------------"
    
    echo "1) Automated Functionality Assessment (AFA): 2FA Presence"
    echo "---------------------------------------------------------"
    cat "${TWOFA_OUT}"
    echo ""
    
    echo "2) Nikto Key Findings (Misconfigurations & Info Leakage)"
    echo "------------------------------------------------------"
    # Filter for high-value Nikto results (misconfigurations, sensitive files, headers, XSS, etc.)
    grep -E "\+ /|Server:|X-Powered-By|cookie|Warning|Uncommon header|robots.txt|allowed method|XSS" "${NIKTO_OUT}" | head -n 20 || true
    echo ""
    
    echo "3) Vulnerable Components (CVE / Exploit Matches)"
    echo "------------------------------------------------"
    if [ -s "${CVES_SS_HTTP}" ]; then
        echo "CVEs with potential Exploit-DB match (HIGH CONFIDENCE):"
        cat "${CVES_SS_HTTP}"
        echo ""
    fi
    if [ ! -s "${CVES_SS_HTTP}" ]; then
        echo "No direct CVEs automatically detected by the scan."
    fi
    echo ""

    echo "4) Technical Evidence (Raw Nmap HTTP & SearchSploit Excerpts)"
    echo "-------------------------------------------------------------"
    echo "--- Nmap HTTP Results (Service/Version) ---"
    grep -E 'PORT|Service|open' "${NMAP_HTTP_TXT}" | head -n 10 || true
    echo ""
    echo "--- SearchSploit Excerpt ---"
    if [ -s "${SS_OUT}" ]; then
        sed -n '1,80p' "${SS_OUT}"
    else
        echo "No searchsploit matches were found."
    fi
    echo ""
    
    echo "END OF REPORT"
    echo "============="
} > "${REPORT}"

echo "[+] Web scan complete. Non-technical report: ${REPORT}"
echo "[*] Raw outputs are in: ${OUTDIR}"
exit 0
