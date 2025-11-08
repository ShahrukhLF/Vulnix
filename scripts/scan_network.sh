#!/usr/bin/env bash
################################################################################
# scan_network.sh
# Vulnix — Compact Network Scanner (CLI only)
#
# - Tools used: nmap, enum4linux (or enum4linux-ng), searchsploit
# - Demo-friendly: bounded timeouts, focused checks, aims <~10 minutes on lab VMs
# - Produces: results/network_report_<timestamp>.txt (short, human-readable)
# - Usage: sudo ./scripts/scan_network.sh <target-ip>
################################################################################

set -euo pipefail
IFS=$'\n\t'

# ----------------- Arguments -----------------
if [ "$#" -lt 1 ]; then
  echo "Usage: sudo $0 <target-ip>"
  exit 2
fi
TARGET="$1"

# ----------------- Environment -----------------
TS="$(date +%Y%m%d_%H%M%S)"
OUTDIR="results"
mkdir -p "$OUTDIR"

REPORT="${OUTDIR}/network_report_${TS}.txt"
NMAP_OUT="${OUTDIR}/network_nmap_${TS}.txt"
NMAP_XML="${OUTDIR}/network_nmap_${TS}.xml"
ENUM_OUT="${OUTDIR}/network_enum_${TS}.txt"
SS_OUT="${OUTDIR}/network_searchsploit_${TS}.txt"

# ----------------- Prereq check -----------------
if [ "$EUID" -ne 0 ]; then
  echo "[!] This script should be run as root (sudo)."
  exit 1
fi

echo "PROGRESS:5"
echo "[*] Vulnix — Network quick scan starting for: $TARGET"
echo "[*] Report will be saved to: $REPORT"
echo ""

# ----------------- 1) Fast Nmap discovery -----------------
# -T4 (fast), --top-ports 100 (high-value ports), -sV for version detection
# timeout ensures demo won't exceed allocated time
echo "[*] 1) Running nmap (fast profile, service/version detection)..."
timeout 300 nmap -sS -sV -T4 --top-ports 100 -Pn \
  --script "safe,http-enum,ftp-anon,smb-enum-shares,smb-enum-users" \
  -oN "$NMAP_OUT" -oX "$NMAP_XML" "$TARGET" >/dev/null 2>&1 || echo "[WARN] nmap finished with warnings or timeout"

echo "PROGRESS:35"

# ----------------- 2) SMB enumeration (if needed) -----------------
if grep -qE "139/tcp|445/tcp" "$NMAP_OUT" 2>/dev/null; then
  echo "[*] 2) SMB detected — running enum4linux (quick mode)..."
  if command -v enum4linux-ng >/dev/null 2>&1; then
    timeout 150 enum4linux-ng -U -S -oA "${OUTDIR}/enum4linux_${TS}" "$TARGET" > "$ENUM_OUT" 2>&1 || echo "[WARN] enum4linux-ng timed out or errored"
  elif command -v enum4linux >/dev/null 2>&1; then
    timeout 150 enum4linux -a "$TARGET" > "$ENUM_OUT" 2>&1 || echo "[WARN] enum4linux timed out or errored"
  else
    echo "[WARN] enum4linux not installed; SMB enumeration skipped" > "$ENUM_OUT"
  fi
else
  echo "[*] 2) No SMB ports found — skipping SMB enumeration."
  echo "No SMB enumeration required." > "$ENUM_OUT"
fi

echo "PROGRESS:65"

# ----------------- 3) Map to public exploits (SearchSploit) -----------------
echo "[*] 3) Mapping findings to Exploit-DB (searchsploit)..."
if command -v searchsploit >/dev/null 2>&1 && [ -s "$NMAP_XML" ]; then
  # Use searchsploit's nmap parser for best automatic mapping
  searchsploit --nmap "$NMAP_XML" > "$SS_OUT" 2>/dev/null || true
else
  # Fallback: try a short search by service names
  grep -E "^[0-9]+/tcp" "$NMAP_OUT" | awk '{print $3}' | sort -u | while read -r svc; do
    [ -n "$svc" ] && searchsploit "$svc" | sed -n '1,6p'
  done > "$SS_OUT" 2>/dev/null || true
fi

echo "PROGRESS:85"

# ----------------- 4) Produce short human-friendly report -----------------
{
  echo "VULNIX — NETWORK REPORT"
  echo "Target: $TARGET"
  echo "Timestamp: $(date)"
  echo "----------------------------------------"
  echo ""
  echo "EXECUTIVE SUMMARY"
  echo "-----------------"

  # quick, human phrased risk evaluation
  if grep -qE "21/tcp.*open|23/tcp.*open|139/tcp.*open|445/tcp.*open|3306/tcp.*open" "$NMAP_OUT" 2>/dev/null; then
    echo "Critical: The host exposes high-risk services (FTP, Telnet, SMB, DBs). These are commonly exploited — isolate and patch."
  elif [ -s "$SS_OUT" ]; then
    echo "High: Services with known public exploits were detected (see 'Exploit matches')."
  else
    echo "Moderate: Open services found — review and harden services, apply updates."
  fi

  echo ""
  echo "HIGH PRIORITY FINDINGS (short)"
  echo "-----------------------------"
  # show a few notable lines from nmap
  grep -E "^[0-9]+/tcp" "$NMAP_OUT" | sed -n '1,20p' || echo "(no open ports detected)"

  echo ""
  if [ -s "$SS_OUT" ]; then
    echo "Exploit matches (top):"
    sed -n '1,40p' "$SS_OUT"
  else
    echo "Exploit matches: (none automatically found)"
  fi

  echo ""
  echo "SMB / ENUMERATION (excerpt)"
  echo "---------------------------"
  grep -E "Domain|Workgroup|Share|User|RID" "$ENUM_OUT" | sed -n '1,20p' || echo "(no SMB evidence)"

  echo ""
  echo "REMEDIATION (plain language)"
  echo "----------------------------"
  echo "1) If internet-facing, isolate until patched."
  echo "2) Disable unnecessary services (FTP, Telnet); use SSH with keys."
  echo "3) Patch OS and software; apply vendor updates."
  echo "4) Restrict services with firewall; do not expose databases or file shares publicly."
  echo "5) Remove backups/config files from public locations or shares."
  echo ""
  echo "END OF REPORT"
} > "$REPORT"

echo "PROGRESS:100"
echo "[+] Network report written: $REPORT"
echo "[+] Raw outputs: $NMAP_OUT, $NMAP_XML, $ENUM_OUT, $SS_OUT"
