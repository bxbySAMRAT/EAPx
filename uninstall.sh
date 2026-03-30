#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}"
echo "███████╗ █████╗ ██████╗ ██╗  ██╗"
echo "██╔════╝██╔══██╗██╔══██╗╚██╗██╔╝"
echo "█████╗  ███████║██████╔╝ ╚███╔╝ "
echo "██╔══╝  ██╔══██║██╔═══╝  ██╔██╗ "
echo "███████╗██║  ██║██║     ██╔╝ ██╗"
echo "╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "${RED}[!] EAPx Uninstaller${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Run as root: sudo bash uninstall.sh${NC}"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${YELLOW}[?] This will remove ALL EAPx data including:${NC}"
echo "    - Generated certificates (certs/)"
echo "    - Captured loot and credentials (loot/)"
echo "    - Generated reports (report/*.md)"
echo "    - Temporary files (/tmp/eapx*, /tmp/karma_*)"
echo "    - Python compiled caches (__pycache__/)"
echo "    - EAPx-specific Python packages (scapy, flask, netaddr, colorama)"
echo "    - EAPx-specific system packages (hostapd, dnsmasq, macchanger, hashcat)"
echo ""
echo -e "${RED}[!] System packages like aircrack-ng, openssl, python3 will NOT be removed${NC}"
echo -e "${RED}[!] as they may be used by other tools.${NC}"
echo ""

read -p "[?] Are you sure you want to uninstall EAPx? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
  echo -e "${GREEN}[+] Uninstall cancelled.${NC}"
  exit 0
fi

echo ""

# ── Remove generated certificates ──────────────────────────────
echo -e "${YELLOW}[*] Removing generated certificates...${NC}"
rm -rf "$SCRIPT_DIR/certs/"
echo "    Removed certs/"

# ── Remove captured loot ───────────────────────────────────────
echo -e "${YELLOW}[*] Removing captured loot and credentials...${NC}"
rm -rf "$SCRIPT_DIR/loot/"
echo "    Removed loot/"

# ── Remove generated reports ───────────────────────────────────
echo -e "${YELLOW}[*] Removing generated reports...${NC}"
rm -f "$SCRIPT_DIR"/report/pentest_*.md
echo "    Removed report/pentest_*.md"

# ── Remove Python cache ───────────────────────────────────────
echo -e "${YELLOW}[*] Removing Python caches...${NC}"
find "$SCRIPT_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
find "$SCRIPT_DIR" -name "*.pyc" -delete 2>/dev/null
find "$SCRIPT_DIR" -name "*.pyo" -delete 2>/dev/null
echo "    Removed __pycache__/, *.pyc, *.pyo"

# ── Remove temp files ─────────────────────────────────────────
echo -e "${YELLOW}[*] Removing temporary files...${NC}"
rm -f /tmp/eapx_*
rm -f /tmp/karma_*.conf
rm -f /tmp/eapx.eap_user
echo "    Removed /tmp/eapx*, /tmp/karma_*.conf"

# ── Remove EAPx-specific Python packages ──────────────────────
echo -e "${YELLOW}[*] Removing EAPx Python packages...${NC}"
pip3 uninstall -y scapy flask netaddr colorama 2>/dev/null
echo "    Uninstalled scapy, flask, netaddr, colorama"

# ── Remove EAPx-specific system packages ──────────────────────
echo -e "${YELLOW}[*] Removing EAPx-specific system packages...${NC}"
apt remove -y hostapd dnsmasq macchanger hashcat 2>/dev/null
apt autoremove -y 2>/dev/null
echo "    Removed hostapd, dnsmasq, macchanger, hashcat"

# ── Remove the EAPx directory itself ──────────────────────────
echo ""
read -p "[?] Also delete the entire EAPx source directory ($SCRIPT_DIR)? (yes/no): " del_src
if [ "$del_src" == "yes" ]; then
  echo -e "${YELLOW}[*] Removing EAPx source directory...${NC}"
  rm -rf "$SCRIPT_DIR"
  echo -e "${GREEN}[+] Source directory removed.${NC}"
else
  echo -e "${GREEN}[+] Source directory kept.${NC}"
fi

echo ""
echo -e "${GREEN}[+] ════════════════════════════════════════${NC}"
echo -e "${GREEN}[+] EAPx has been uninstalled successfully.${NC}"
echo -e "${GREEN}[+] ════════════════════════════════════════${NC}"
