#!/bin/bash
# ============================================================
# PasarGuard Route & WARP Health Manager — Install Script
# ============================================================
# Run as root on the same server as PasarGuard Panel
# (Zero scripts or agents required on remote nodes)
#
# Usage:
#   chmod +x install.sh
#   sudo ./install.sh
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

INSTALL_DIR="/opt/pasarguard-route-manager"
CONFIG_DIR="/etc/pasarguard-route-manager"
SERVICE_NAME="pasarguard-route-manager"
CLI_BIN="/usr/local/bin/pg-route-manager"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${GREEN}=== PasarGuard Route & WARP Health Manager Installer ===${NC}\n"

# 1. Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: Please run as root (sudo ./install.sh)${NC}"
    exit 1
fi

# 2. Clean up old installation (preserving /etc/pasarguard-route-manager)
echo -e "${YELLOW}Cleaning up old installation (preserving config & state)...${NC}"
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl stop "$SERVICE_NAME"
fi
if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl disable "$SERVICE_NAME"
fi
if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
fi

# 3. Install system dependencies
echo -e "${YELLOW}Installing system dependencies...${NC}"
apt-get update
apt-get install -y python3-full python3-venv

# 4. Create virtual environment and install httpx
echo -e "${YELLOW}Setting up virtual environment...${NC}"
mkdir -p "$INSTALL_DIR"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip httpx
echo -e "${GREEN}✓ Virtual environment and httpx ready${NC}"

# 5. Copy script and create CLI symlink
echo -e "${YELLOW}Installing route_manager.py...${NC}"
cp "$SCRIPT_DIR/route_manager.py" "$INSTALL_DIR/route_manager.py"
sed -i 's/\r$//' "$INSTALL_DIR/route_manager.py"
chmod 755 "$INSTALL_DIR/route_manager.py"
# Update shebang to use venv python
sed -i "1s|.*|#!$INSTALL_DIR/venv/bin/python3|" "$INSTALL_DIR/route_manager.py"
ln -sf "$INSTALL_DIR/route_manager.py" "$CLI_BIN"
echo -e "${GREEN}✓ Installed to $INSTALL_DIR and linked as $CLI_BIN${NC}"

# 6. Copy systemd service
echo -e "${YELLOW}Installing systemd service...${NC}"
cp "$SCRIPT_DIR/pasarguard-route-manager.service" "/etc/systemd/system/${SERVICE_NAME}.service"
sed -i 's/\r$//' "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
echo -e "${GREEN}✓ Service installed${NC}"

# 7. Run setup if no config exists
if [ ! -f "$CONFIG_DIR/config.json" ]; then
    echo -e "\n${YELLOW}No config found. Running first-time setup...${NC}\n"
    "$CLI_BIN" --setup
fi

# 8. Test connection
echo -e "\n${YELLOW}Testing connection (dry run)...${NC}"
if "$CLI_BIN" --dry-run --verbose; then
    echo -e "${GREEN}✓ Connection test passed${NC}"
else
    echo -e "${RED}✗ Connection test failed. Check your config at $CONFIG_DIR/config.json${NC}"
    exit 1
fi

# 9. Enable and start service
echo -e "\n${YELLOW}Starting service...${NC}"
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

echo -e "\n${GREEN}=== Installation Complete ===${NC}"
echo ""
echo "  CLI:       pg-route-manager ($CLI_BIN)"
echo "  Script:    $INSTALL_DIR/route_manager.py"
echo "  Config:    $CONFIG_DIR/config.json"
echo "  Service:   $SERVICE_NAME"
echo "  Logs:      journalctl -u $SERVICE_NAME -f"
echo ""
echo "One-time WARP HA & Observatory Setup (recommended):"
echo "  pg-route-manager --optimize-warp --dry-run   # Preview Core Config changes"
echo "  pg-route-manager --optimize-warp             # Enable Observatory, MTU=1280, KeepAlive=20 & HA"
echo ""
echo "Zero-Downtime WARP Commands:"
echo "  pg-route-manager --status                    # Live WARP latency & health across all nodes"
echo "  pg-route-manager --refresh warp2             # Refresh warp2 live (0 Xray restarts, 0 user drops)"
echo "  pg-route-manager --refresh all               # Refresh all warp* slots live"
echo "  pg-route-manager --compact                   # Prune retired *__rNNNN outbounds (maintenance)"
echo ""
echo "Service Commands:"
echo "  systemctl status $SERVICE_NAME               # Check daemon status"
echo "  systemctl reload $SERVICE_NAME               # Reload config & sync immediately (SIGHUP)"
echo "  systemctl restart $SERVICE_NAME              # Restart daemon"
echo "  journalctl -u $SERVICE_NAME -f               # Follow live logs"
echo ""
