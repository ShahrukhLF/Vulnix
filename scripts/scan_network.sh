#!/usr/bin/env bash

#

# scan_network.sh

# Final Vulnix FYP version — Network vulnerability scanner for Metasploitable2

# Usage (from project root): sudo ./scripts/scan_network.sh <target-ip>

#

# Saves outputs under: results/<target>/

#

# Tools used:

# - nmap

# - enum4linux-ng (or enum4linux)

# - searchsploit

#

set -euo pipefail
IFS=$'\n\t'

if [ "$#" -lt 1 ]; then
echo "Usage: sudo $0 <target-ip>"
exit 2
fi

TARGET="$1"                       # target IP (e.g., 192.168.78.102)
OUTDIR="results/${TARGET}"        # results path inside project results/
mkdir -p "${OUTDIR}"
TS="$(date +"%Y%m%d_%H%M%S")"

# -------------------- 1) Ping / host discovery (fast) --------------------

# nmap -sn performs a ping scan (no port scan). It's fast and safe.

echo "[*] Running host discovery (ping scan) against ${TARGET}..."
nmap -sn "${TARGET}" -oG "${OUTDIR}/nmap_ping_${TS}.gnmap" || true

# -------------------- 2) Full TCP port/service/version scan --------------------

# -p-    -> scan all TCP ports (1-65535)

# -sS    -> SYN scan (stealth; requires sudo)

# -sV    -> service/version detection

# -O     -> OS detection

# --script "default,safe,vuln" -> run safe NSE scripts + some vuln checks

# -oX    -> write XML (useful for searchsploit --nmap later)

# -oN    -> write human-readable text

echo "[*] Running full TCP port + service/version scan (this may take several minutes)..."
sudo nmap -p- -sS -sV -O -T4 --script "default,safe,vuln" "${TARGET}" 
-oX "${OUTDIR}/nmap_full_${TS}.xml" 
-oN "${OUTDIR}/nmap_full_${TS}.txt" || true

# Extract open ports / services for quick viewing

grep -i "open" "${OUTDIR}/nmap_full_${TS}.txt" | sed 's/^[[:space:]]*//' > "${OUTDIR}/nmap_ports_${TS}.txt" || true

# -------------------- 3) SMB enumeration (non-destructive) --------------------

# If ports 139 or 445 appear open, run enum4linux-ng for SMB/NetBIOS info.

if grep -E "139/tcp|445/tcp" "${OUTDIR}/nmap_ports_${TS}.txt" >/dev/null 2>&1; then
echo "[*] SMB ports detected — running enum4linux-ng..."

# enum4linux-ng prints to stdout; tee to save copy

enum4linux-ng "${TARGET}" | tee "${OUTDIR}/enum4linux_${TS}.txt" || true
else
echo "[*] No SMB ports detected — skipping enum4linux-ng."
fi

# -------------------- 4) Map discovered services to Exploit-DB using searchsploit --------------------

# searchsploit --nmap parses Nmap XML and suggests matching exploits (Exploit-DB).

echo "[*] Running searchsploit --nmap to map services to public exploits..."
if [ -s "${OUTDIR}/nmap_full_${TS}.xml" ]; then
searchsploit --nmap "${OUTDIR}/nmap_full_${TS}.xml" > "${OUTDIR}/searchsploit_${TS}.txt" || true
else
echo "[!] Nmap XML not present; skipping searchsploit mapping." > "${OUTDIR}/searchsploit_${TS}.txt"
fi

# -------------------- 5) Build a concise human-readable summary --------------------

SUMMARY="${OUTDIR}/summary_${TS}.txt"
{
echo "Target: ${TARGET}"
echo "Timestamp: ${TS}"
echo ""
echo "=== Open Ports & Services (excerpt) ==="
head -n 60 "${OUTDIR}/nmap_ports_${TS}.txt" || true
echo ""
echo "=== SearchSploit Results (excerpt) ==="
head -n 120 "${OUTDIR}/searchsploit_${TS}.txt" || true
echo ""
if [ -f "${OUTDIR}/enum4linux_${TS}.txt" ]; then
echo "=== Enum4linux (excerpt) ==="
sed -n '1,80p' "${OUTDIR}/enum4linux_${TS}.txt" || true
fi
} > "${SUMMARY}"

echo "[+] Network scan complete."
echo "    Results saved to: ${OUTDIR}"
echo "    Summary file:      ${SUMMARY}"
exit 0
