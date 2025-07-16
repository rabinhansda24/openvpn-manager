#!/bin/bash

# OpenVPN Manager - Add Client Script
# Creates a new client certificate and configuration

set -e

# Configuration
OPENVPN_DIR="/etc/openvpn"
EASY_RSA_DIR="$OPENVPN_DIR/easy-rsa"
CLIENT_DIR="$OPENVPN_DIR/clients"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

# Check if client name is provided
if [ $# -eq 0 ]; then
    error "Usage: $0 <client_name>"
    exit 1
fi

CLIENT_NAME="$1"

# Validate client name
if [[ ! "$CLIENT_NAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]*[a-zA-Z0-9]$ ]] || [ ${#CLIENT_NAME} -lt 3 ] || [ ${#CLIENT_NAME} -gt 50 ]; then
    error "Invalid client name. Use 3-50 characters, alphanumeric with hyphens and underscores only."
    exit 1
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
   exit 1
fi

# Check if Easy-RSA is initialized
if [ ! -d "$EASY_RSA_DIR/pki" ]; then
    error "PKI not initialized. Run init-openvpn.sh first."
    exit 1
fi

# Check if client already exists
if [ -f "$EASY_RSA_DIR/pki/issued/$CLIENT_NAME.crt" ]; then
    error "Client '$CLIENT_NAME' already exists!"
    exit 1
fi

log "Creating client certificate for: $CLIENT_NAME"

# Change to Easy-RSA directory
cd $EASY_RSA_DIR

# Generate client certificate
log "Generating client certificate..."
./easyrsa build-client-full "$CLIENT_NAME" nopass

# Verify certificate was created
if [ ! -f "pki/issued/$CLIENT_NAME.crt" ]; then
    error "Failed to create client certificate"
    exit 1
fi

# Create client directory if it doesn't exist
mkdir -p $CLIENT_DIR

# Get server IP (try to detect automatically)
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")

# Create client configuration file
log "Creating client configuration..."
cat > $CLIENT_DIR/$CLIENT_NAME.ovpn << EOF
client
dev tun
proto udp
remote $SERVER_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3

<ca>
$(cat pki/ca.crt)
</ca>

<cert>
$(sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' pki/issued/$CLIENT_NAME.crt)
</cert>

<key>
$(cat pki/private/$CLIENT_NAME.key)
</key>

<tls-auth>
$(cat $OPENVPN_DIR/ta.key)
</tls-auth>
key-direction 1
EOF

# Set proper permissions
chmod 600 $CLIENT_DIR/$CLIENT_NAME.ovpn
chown root:root $CLIENT_DIR/$CLIENT_NAME.ovpn

log "Client '$CLIENT_NAME' created successfully!"
log "Configuration file: $CLIENT_DIR/$CLIENT_NAME.ovpn"
log ""
log "You can now:"
log "1. Download the .ovpn file for the client"
log "2. Import it into an OpenVPN client application"
log "3. Connect to the VPN server"

# Optionally create QR code for mobile clients
if command -v qrencode &> /dev/null; then
    log "Generating QR code for mobile setup..."
    qrencode -t PNG -o $CLIENT_DIR/$CLIENT_NAME.png < $CLIENT_DIR/$CLIENT_NAME.ovpn
    log "QR code saved: $CLIENT_DIR/$CLIENT_NAME.png"
fi

# Log the creation
echo "$(date): Created client '$CLIENT_NAME'" >> /var/log/openvpn/client-management.log
