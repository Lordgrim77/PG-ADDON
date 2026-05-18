# PasarGuard Route Manager

Automatically manages Xray routing rules based on user note directives in the PasarGuard Panel.

## Features
- **Auto-Routing**: Just add `node:NAME out:TAG` to a user's note.
- **Smart Merging**: Multiple users to one outbound = one rule.
- **Self-Healing**: Automatically cleans up rules for deleted users.
- **Service Ready**: Comes with a systemd service and automated installer.

## Installation

Run this one-liner on your PasarGuard Panel server:

```bash
git clone https://github.com/Lordgrim77/PG-ADDON.git
cd PG-ADDON
chmod +x install.sh
sudo ./install.sh
```

## Note Format
In the PasarGuard user note field:
`node:sg out:warp`

For multiple nodes:
`node:sg out:warp | node:us out:direct`

## Configuration
The installer will prompt for:
1. **Panel URL**: e.g., `https://your-panel.com:8000` (No `/dashboard` at the end!)
2. **Credentials**: Admin username and password.
3. **SSL**: Set to `N` if using a raw IP/self-signed cert.

## License
MIT
