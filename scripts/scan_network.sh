#!/usr/bin/env bash
################################################################################
# scan_network.sh
#
# Vulnix — Network scanner for FYP-I (Nmap + enum4linux-ng + searchsploit)
#
# Purpose:
#   - Fast-demo default: discover open services, versions, OS and run a small
#     set of high-value NSE scripts (safe) on a target host (e.g., Metasploitable2).
#   - Optional deep/full scan (all TCP ports and vuln NSE category) via --full-scan.
#   - If SMB found, run enum4linux-ng (or enum4linux fallback).
#   - Map results to public exploits via searchsploit (--nmap when available).
#   - Produce ONE single user-friendly TXT report (results/<target>/report_<ts>.txt)
#
# Usage:
#   sudo ./scripts/scan_network.sh <target-ip-or-host> [--full-scan]
#
# Notes:
#   - Intended for authorized lab targets ONLY.
#   - Default mode is fast for demo; use --full-scan in lab deep-testing.
################################################################################

set -euo pipefail
IFS=$'\n\t'

# ---------- args ----------
if [ "$#" -lt 1 ]; then
  echo "Usage: sudo $0 <target-ip-or-host> [--full-scan]"
  exit 2
fi
TARGET_RAW="$1"
FULL_SCAN=false
if [ "${2:-}" = "--full-scan" ]; then FULL_SCAN=true; fi

# ---------- require root ----------
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root (sudo)." >&2
  exit 1
fi

# ---------- prepare names & output dir ----------
SAFE_TARGET="$(echo "${TARGET_RAW}" | sed -E 's#[/:]#_##g')"
OUTDIR="results/${SAFE_TARGET}"
mkdir -p "${OUTDIR}"
TS="$(date +"%Y%m%d_%H%M%S")"

RAW_XML="${OUTDIR}/nmap_raw_${TS}.xml"
RAW_TXT="${OUTDIR}/nmap_raw_${TS}.txt"
TARGETED_TXT="${OUTDIR}/nmap_targeted_${TS}.txt"
ENUM_OUT="${OUTDIR}/enum4linux_${TS}.txt"
SS_OUT="${OUTDIR}/searchsploit_${TS}.txt"
CVES_NMAP="${OUTDIR}/cves_from_nmap_${TS}.txt"
CVES_SS="${OUTDIR}/cves_from_searchsploit_${TS}.txt"
REPORT="${OUTDIR}/report_${TS}.txt"

echo "[*] Vulnix network scan starting for: ${TARGET_RAW}"
echo "[*] Results directory: ${OUTDIR}"
echo ""

# ---------- 1) Quick ping discovery (lightweight) ----------
echo "[*] 1) Host discovery..."
nmap -sn "${TARGET_RAW}" -oG "${OUTDIR}/nmap_ping_${TS}.gnmap" >/dev/null 2>&1 || true
echo ""

# ---------- 2) Nmap scanning ----------
if [ "${FULL_SCAN}" = true ]; then
  echo "[*] 2) Running FULL Nmap scan (all TCP ports + vuln NSE) — slow but thorough..."
  sudo nmap -p- -sS -sV -O -T4 --script "default,safe,vuln" "${TARGET_RAW}" -oX "${RAW_XML}" -oN "${RAW_TXT}" || true
else
  echo "[*] 2) Running TARGETED Nmap scan (fast-demo): ports 1-2000 + common DB/web ports"
  # targeted scripts: default,safe plus high-value checks useful on Metasploitable-style lab VMs
  sudo nmap -sS -sV -O -T4 \
    --script "default,safe,http-enum,ftp-anon,ssl-heartbleed,smb-enum-shares,smb-enum-users" \
    -p 1-2000,3306,5432,8080,3000 \
    "${TARGET_RAW}" -oX "${RAW_XML}" -oN "${RAW_TXT}" || true
fi
echo "[*] Nmap scan saved: ${RAW_TXT}"
echo ""

# ---------- 3) Save concise open ports list ----------
grep -i "open" "${RAW_TXT}" | sed 's/^[[:space:]]*//' > "${OUTDIR}/nmap_ports_${TS}.txt" || true

# ---------- 4) Targeted quick Nmap (for quick reference) ----------
sudo nmap -sS -sV -p 22,21,23,25,53,80,139,443,445,3306,5432,8080,3000 --script "default,safe" "${TARGET_RAW}" -oN "${TARGETED_TXT}" >/dev/null 2>&1 || true

# ---------- 5) SMB enumeration (if SMB ports found) ----------
if grep -E "139/tcp|445/tcp" "${OUTDIR}/nmap_ports_${TS}.txt" >/dev/null 2>&1; then
  echo "[*] 5) SMB detected — running enum4linux-ng (or enum4linux fallback)..."
  if command -v enum4linux-ng >/dev/null 2>&1; then
    enum4linux-ng "${TARGET_RAW}" | tee "${ENUM_OUT}" || true
  elif command -v enum4linux >/dev/null 2>&1; then
    enum4linux -a "${TARGET_RAW}" | tee "${ENUM_OUT}" || true
  else
    echo "[!] enum4linux(-ng) not found — SMB enumeration skipped." | tee "${ENUM_OUT}"
  fi
else
  echo "[*] 5) SMB not detected — skipping SMB enumeration." > "${ENUM_OUT}"
fi
echo ""

# ---------- 6) Map to Exploit-DB via searchsploit ----------
echo "[*] 6) Mapping to Exploit-DB with searchsploit --nmap (if available)..."
if command -v searchsploit >/dev/null 2>&1 && [ -s "${RAW_XML}" ]; then
  searchsploit --nmap "${RAW_XML}" 2>/dev/null > "${SS_OUT}" || true
else
  # fallback: keyword extraction from nmap text output
  egrep -io 'Apache/[0-9.]+|nginx/[0-9.]+|Tomcat/[0-9.]+|OpenSSH|OpenSSL|vsftpd|ProFTPD|MySQL|PostgreSQL|PHP/[0-9.]+' "${RAW_TXT}" 2>/dev/null | sort -u > "${OUTDIR}/prod_keywords_${TS}.txt" || true
  > "${SS_OUT}" || true
  if [ -s "${OUTDIR}/prod_keywords_${TS}.txt" ]; then
    while read -r kw; do
      [ -z "${kw}" ] && continue
      echo "==== searchsploit ${kw} ====" >> "${SS_OUT}"
      searchsploit "${kw}" 2>/dev/null | head -n 20 >> "${SS_OUT}" || true
      echo "" >> "${SS_OUT}"
    done < "${OUTDIR}/prod_keywords_${TS}.txt"
  else
    echo "[!] No product/version keywords found for searchsploit fallback." > "${SS_OUT}"
  fi
fi
echo ""

# ---------- 7) Extract CVEs ----------
grep -Eo "CVE-[0-9]{4}-[0-9A-Za-z.-]{4,}" "${RAW_TXT}" 2>/dev/null | sort -u > "${CVES_NMAP}" || true
grep -Eo "CVE-[0-9]{4}-[0-9A-Za-z.-]{4,}" "${SS_OUT}" 2>/dev/null | sort -u > "${CVES_SS}" || true

# ---------- 8) Build user-friendly single TXT report ----------
echo "[*] 7) Building final report: ${REPORT}"
{
  echo "Vulnix — Network Scan Report"
  echo "Target: ${TARGET_RAW}"
  echo "Timestamp: ${TS}"
  echo ""
  echo "EXECUTIVE SUMMARY"
  echo "-----------------"
  if [ -s "${CVES_SS}" ]; then
    echo "Potential known public exploits were matched to services on this host. Manual verification required."
  elif [ -s "${CVES_NMAP}" ]; then
    echo "CVE references were found in the scan output. Review the CVE list below."
  else
    echo "No direct public exploit matches were automatically detected by this scan."
  fi
  echo ""
  echo "NON-TECHNICAL RECOMMENDATIONS"
  echo "- If this machine is internet-facing, isolate it until patched."
  echo "- Apply vendor updates/patches for services listed below; remove unused services."
  echo "- Disable anonymous services (FTP/SMB) and do not expose databases publicly."
  echo "- Use strong unique passwords; prefer SSH key auth and firewall rules."
  echo ""
  echo "DETAILED FINDINGS"
  echo "-----------------"
  echo ""
  echo "1) Open ports & services (excerpt)"
  echo "----------------------------------"
  if [ -s "${OUTDIR}/nmap_ports_${TS}.txt" ]; then
    cat "${OUTDIR}/nmap_ports_${TS}.txt"
  else
    echo "  (no open ports or nmap output missing)"
  fi
  echo ""
  echo "2) Nmap (service/version) excerpt"
  echo "---------------------------------"
  sed -n '1,80p' "${RAW_TXT}" || true
  echo ""
  echo "3) SMB / enum4linux excerpt (if run)"
  echo "------------------------------------"
  if [ -s "${ENUM_OUT}" ]; then
    sed -n '1,80p' "${ENUM_OUT}"
  else
    echo "  SMB enumeration not performed or no results."
  fi
  echo ""
  echo "4) CVEs found (SearchSploit & Nmap)"
  echo "------------------------------------"
  if [ -s "${CVES_SS}" ]; then
    echo "From SearchSploit:"
    cat "${CVES_SS}"
    echo ""
  fi
  if [ -s "${CVES_NMAP}" ]; then
    echo "From Nmap output:"
    cat "${CVES_NMAP}"
    echo ""
  fi
  if [ ! -s "${CVES_SS}" ] && [ ! -s "${CVES_NMAP}" ]; then
    echo "  None automatically detected."
  fi
  echo ""
  echo "5) SearchSploit (Exploit-DB) excerpt"
  echo "-------------------------------------"
  if [ -s "${SS_OUT}" ]; then
    sed -n '1,120p' "${SS_OUT}"
  else
    echo "  No searchsploit matches."
  fi
  echo ""
  echo "PRIORITIZED REMEDIATION (plain language)"
  echo "---------------------------------------"
  if grep -qi "ssh" "${OUTDIR}/nmap_ports_${TS}.txt" 2>/dev/null; then
    echo "- SSH detected: update OpenSSH, disable root password login, prefer key-based auth."
  fi
  if grep -Ei "21/tcp|ftp" "${OUTDIR}/nmap_ports_${TS}.txt" >/dev/null 2>&1; then
    echo "- FTP detected: disable anonymous FTP; prefer SFTP/FTPS or remove service."
  fi
  if grep -Eqi "139/tcp|445/tcp" "${OUTDIR}/nmap_ports_${TS}.txt" >/dev/null 2>&1; then
    echo "- SMB detected: restrict SMB to internal networks; remove anonymous shares and patch Samba."
  fi
  if grep -Eqi "3306|5432" "${OUTDIR}/nmap_ports_${TS}.txt" >/dev/null 2>&1; then
    echo "- Database service: bind to localhost if not needed remotely; use strong passwords."
  fi
  if [ -s "${CVES_SS}" ] || [ -s "${CVES_NMAP}" ]; then
    echo "- Known CVEs were detected: prioritize patching and consult vendor advisories."
  fi
  echo ""
  echo "HOW TO VERIFY (non-technical)"
  echo "-----------------------------"
  echo "- After patching or removing services, re-run this script to confirm the issues are gone."
  echo "- For web services, ensure admin/debug pages are not public."
  echo ""
  echo "TECHNICAL EVIDENCE (raw excerpts)"
  echo "--------------------------------"
  echo "Nmap full/top lines:"
  sed -n '1,120p' "${RAW_TXT}" || true
  echo ""
  echo "SearchSploit excerpt:"
  if [ -s "${SS_OUT}" ]; then
    sed -n '1,80p' "${SS_OUT}"
  else
    echo "  (no searchsploit matches)"
  fi
  echo ""
  echo "END OF REPORT"
  echo "============="
} > "${REPORT}"

echo "[+] Network scan complete. Report: ${REPORT}"
echo "[*] Raw outputs are in: ${OUTDIR}"
exit 0
