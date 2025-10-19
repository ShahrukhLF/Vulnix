#!/usr/bin/env bash
################################################################################
# scan_network.sh
#
# Vulnix — Network Scanner for FYP-I (Nmap + Enum4Linux-NG)
#
# Purpose:
#   - Execute an aggressive, fast Nmap port/service scan.
#   - Execute Enum4Linux-NG for SMB/Samba enumeration.
#   - Produce ONE single non-technical, human-readable TXT report.
#
# Usage:
#   sudo ./scripts/scan_network.sh <target-ip>
# Example:
#   sudo ./scripts/scan_network.sh 192.168.78.102
#
# NOTE FOR DEMO: The Nmap scan is optimized for speed (Top 100 ports, -T5).
################################################################################

set -euo pipefail
IFS=$'\n\t'

# --- Argument Validation ---
if [ "$#" -lt 1 ]; then
    echo "Usage: sudo $0 <target-ip>"
    exit 2
fi
TARGET_IP="$1"

# --- Require Root Check ---
if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run as root (sudo)." >&2
    exit 1
fi

# --- Setup Directories and File Names ---
SAFE="${TARGET_IP}"
OUTDIR="results/${SAFE}"
mkdir -p "${OUTDIR}"
TS="$(date +"%Y%m%d_%H%M%S")"

NMAP_OUT="${OUTDIR}/nmap_services_${TS}.txt"
NMAP_XML="${OUTDIR}/nmap_services_${TS}.xml"
ENUM_OUT="${OUTDIR}/enum4linuxng_${TS}.txt"
SS_OUT="${OUTDIR}/searchsploit_${TS}.txt"
CVES_NMAP="${OUTDIR}/cves_from_nmap_${TS}.txt"
REPORT="${OUTDIR}/report_${TS}.txt"

echo "[*] Vulnix network scan starting for: ${TARGET_IP}"
echo "[*] Results directory: ${OUTDIR}"

# --- 1) Nmap Scan (Optimized for Demo Speed) ---
echo "[*] 1) Running FAST DEMO Nmap scan: Top 100 ports, service version, aggressive timing..."
# -T5 (Aggressive Timing): The fastest mode, risking some packet drops. Ideal for a quick demo.
# -sV (Service Version): Crucial for Searchsploit mapping.
# --top-ports 100: Reduces scan from the default 1000 or custom 2000 down to the 100 most common ports.
# -Pn: Treat host as online (Metasploitable 2 is usually in a lab).
sudo nmap -sV -T5 --top-ports 100 -Pn "${TARGET_IP}" -oN "${NMAP_OUT}" -oX "${NMAP_XML}" || true
echo "[*] Nmap scan complete. Output saved: ${NMAP_OUT}"

# --- 2) Enum4Linux-NG (SMB/Samba Enumeration) ---
# Running this only if it's available, as it requires root privileges and is noisy.
echo "[*] 2) Running Enum4Linux-NG (SMB/Samba enumeration)..."
if command -v enum4linux-ng >/dev/null 2>&1; then
    # -a (all tests): quick and comprehensive for Metasploitable2
    sudo enum4linux-ng -a "${TARGET_IP}" 2>&1 > "${ENUM_OUT}" || true
    echo "[*] Enum4Linux-NG complete. Output saved: ${ENUM_OUT}"
else
    echo "[!] enum4linux-ng not found. Skipping enumeration." > "${ENUM_OUT}"
fi

# --- 3) Exploit-DB Mapping via Searchsploit ---
echo "[*] 3) Mapping network findings to Exploit-DB using searchsploit --nmap..."
if command -v searchsploit >/dev/null 2>&1 && [ -s "${NMAP_XML}" ]; then
    # Use Nmap XML for best results
    searchsploit --nmap "${NMAP_XML}" 2>/dev/null > "${SS_OUT}" || true
else
    echo "[!] Searchsploit command or Nmap XML failed. Skipping exploit mapping." > "${SS_OUT}"
fi

# --- 4) Extract and Aggregate CVEs ---
grep -Eo "CVE-[0-9]{4}-[0-9A-Za-z.-]{4,}" "${NMAP_OUT}" 2>/dev/null | sort -u > "${CVES_NMAP}" || true

# --- 5) Build User-Friendly Professional TXT Report ---
echo "[*] 4) Building network report: ${REPORT}"
{
    echo "VULNIX AUTOMATED NETWORK SECURITY ASSESSMENT REPORT"
    echo "=================================================="
    echo "Target: ${TARGET_IP}"
    echo "Date/Time: $(date -d "@${TS:0:14}" +"%Y-%m-%d %H:%M:%S")"
    echo "Tool/Script: Vulnix scan_network.sh (FYP-I - Demo Mode)"
    echo ""
    
    echo "### EXECUTIVE SUMMARY (Network Services) ###"
    echo "--------------------------------------------"
    
    # Simple check for critical open ports commonly found in Metasploitable2
    if grep -qE "21/tcp.*open|22/tcp.*open|23/tcp.*open|25/tcp.*open|139/tcp.*open" "${NMAP_OUT}" 2>/dev/null; then
        echo "CRITICAL RISK: Multiple high-risk, unauthenticated services (like FTP, Telnet, or vulnerable SMB) are exposed on the public network. Immediate review and securing of these services is mandatory."
    elif [ -s "${SS_OUT}" ]; then
        echo "HIGH RISK: The scan detected services with known public exploits (Exploit-DB matches). These services must be patched immediately."
    else
        echo "MODERATE RISK: Several common ports are open, indicating a potential for information leakage and a large attack surface. Review firewall policies and disable unnecessary services."
    fi
    echo ""
    
    echo "### KEY NON-TECHNICAL RECOMMENDATIONS ###"
    echo "-----------------------------------------"
    if grep -qE "21/tcp.*open" "${NMAP_OUT}" 2>/dev/null; then
        echo "* FTP SECURITY: Disable anonymous access on FTP (Port 21) and enforce secure protocols (SFTP/FTPS)."
    fi
    if grep -qE "23/tcp.*open" "${NMAP_OUT}" 2>/dev/null; then
        echo "* ENCRYPTION: Immediately disable Telnet (Port 23) and use SSH instead, as Telnet transmits credentials in plaintext."
    fi
    if grep -q "VULNERABLE" "${ENUM_OUT}" 2>/dev/null; then
        echo "* SMB/SAMBA: Secure or disable insecure SMB/Samba protocols (e.g., SMBv1) on ports 139/445, as they are often highly vulnerable to unauthenticated attacks."
    fi
    if grep -q "CVE" "${CVES_NMAP}" 2>/dev/null; then
        echo "* PATCHING: Apply vendor updates for services associated with the detected CVEs."
    fi
    echo ""
    
    echo "### DETAILED FINDINGS ###"
    echo "-------------------------"
    
    echo "1) Open Ports and Services (Nmap Top 100)"
    echo "-----------------------------------------"
    grep -E 'PORT|Service|open' "${NMAP_OUT}" || true
    echo ""
    
    echo "2) Vulnerable Components (Exploit Matches)"
    echo "------------------------------------------"
    if [ -s "${SS_OUT}" ]; then
        echo "Services with potential Exploit-DB match:"
        sed -n '1,15p' "${SS_OUT}"
    else
        echo "No searchsploit matches were found for the detected services."
    fi
    echo ""

    echo "3) Server Enumeration Findings (Enum4Linux-NG)"
    echo "---------------------------------------------"
    # Only show the key parts of the enumeration output
    grep -E 'RID|User|Domain|Share|Policy' "${ENUM_OUT}" | head -n 15 || true
    if ! [ -s "${ENUM_OUT}" ]; then
        echo "Enumeration tool not run or no useful data extracted."
    fi
    echo ""
    
    echo "END OF REPORT"
    echo "============="
} > "${REPORT}"

echo "[+] Network scan complete. Non-technical report: ${REPORT}"
echo "[*] Raw outputs are in: ${OUTDIR}"
exit 0
