#!/bin/bash
# ============================================================
# PasarGuard Route Manager — Install Script
# ============================================================
# Run as root on the same server as PasarGuard Panel
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
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${GREEN}=== PasarGuard Route Manager Installer ===${NC}\n"

# 1. Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: Please run as root (sudo ./install.sh)${NC}"
    exit 1
fi

# 2. Install system dependencies
echo -e "${YELLOW}Installing system dependencies...${NC}"
apt-get update
apt-get install -y python3-full python3-venv

# 3. Create virtual environment and install httpx
echo -e "${YELLOW}Setting up virtual environment...${NC}"
mkdir -p "$INSTALL_DIR"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install httpx
echo -e "${GREEN}✓ Virtual environment and httpx ready${NC}"

# 4. Copy script
echo -e "${YELLOW}Copying route_manager.py...${NC}"
cp "$SCRIPT_DIR/route_manager.py" "$INSTALL_DIR/route_manager.py"
chmod 755 "$INSTALL_DIR/route_manager.py"
# Update shebang to use venv python
sed -i "1s|.*|#!$INSTALL_DIR/venv/bin/python3|" "$INSTALL_DIR/route_manager.py"
echo -e "${GREEN}✓ Script installed to $INSTALL_DIR${NC}"

# 5. Copy systemd service
echo -e "${YELLOW}Installing systemd service...${NC}"
cp "$SCRIPT_DIR/pasarguard-route-manager.service" "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
echo -e "${GREEN}✓ Service installed${NC}"

# 6. Run setup if no config exists
if [ ! -f "$CONFIG_DIR/config.json" ]; then
    echo -e "\n${YELLOW}No config found. Running first-time setup...${NC}\n"
    "$INSTALL_DIR/venv/bin/python3" "$INSTALL_DIR/route_manager.py" --setup
fi

# 7. Test connection
echo -e "\n${YELLOW}Testing connection (dry run)...${NC}"
if "$INSTALL_DIR/venv/bin/python3" "$INSTALL_DIR/route_manager.py" --dry-run --verbose; then
    echo -e "${GREEN}✓ Connection test passed${NC}"
else
    echo -e "${RED}✗ Connection test failed. Check your config at $CONFIG_DIR/config.json${NC}"
    exit 1
fi

# 8. Enable and start service
echo -e "\n${YELLOW}Starting service...${NC}"
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

echo -e "\n${GREEN}=== Installation Complete ===${NC}"
echo ""
echo "  Script:    $INSTALL_DIR/route_manager.py"
echo "  Config:    $CONFIG_DIR/config.json"
echo "  Service:   $SERVICE_NAME"
echo "  Logs:      journalctl -u $SERVICE_NAME -f"
echo ""
echo "Commands:"
echo "  systemctl status $SERVICE_NAME    # Check status"
echo "  systemctl restart $SERVICE_NAME   # Restart"
echo "  systemctl stop $SERVICE_NAME      # Stop"
echo "  journalctl -u $SERVICE_NAME -f    # Live logs"
echo ""
echo "Manual run:"
echo "  $INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/route_manager.py --dry-run    # Preview"
echo "  $INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/route_manager.py              # Apply once"
echo ""
