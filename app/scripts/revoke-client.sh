#!/bin/bash

# OpenVPN Manager - Revoke Client Script
# Revokes a client certificate and updates the CRL

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

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
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

# Check if client certificate exists
if [ ! -f "$EASY_RSA_DIR/pki/issued/$CLIENT_NAME.crt" ]; then
    error "Client certificate for '$CLIENT_NAME' not found!"
    exit 1
fi

# Check if client is already revoked
if [ -f "$EASY_RSA_DIR/pki/revoked/certs_by_serial/$CLIENT_NAME.crt" ]; then
    warn "Client '$CLIENT_NAME' is already revoked!"
    exit 1
fi

log "Revoking client certificate for: $CLIENT_NAME"

# Change to Easy-RSA directory
cd $EASY_RSA_DIR

# Revoke the certificate
log "Revoking certificate..."
echo "yes" | ./easyrsa revoke "$CLIENT_NAME"

# Generate new CRL
log "Updating Certificate Revocation List..."
./easyrsa gen-crl

# Copy CRL to OpenVPN directory
cp pki/crl.pem $OPENVPN_DIR/

# Set proper permissions
chmod 644 $OPENVPN_DIR/crl.pem

# Remove client configuration file
if [ -f "$CLIENT_DIR/$CLIENT_NAME.ovpn" ]; then
    log "Removing client configuration file..."
    rm -f "$CLIENT_DIR/$CLIENT_NAME.ovpn"
fi

# Remove QR code if exists
if [ -f "$CLIENT_DIR/$CLIENT_NAME.png" ]; then
    rm -f "$CLIENT_DIR/$CLIENT_NAME.png"
fi

# Restart OpenVPN server to reload CRL
log "Restarting OpenVPN server to reload CRL..."
if systemctl is-active --quiet openvpn-server; then
    systemctl restart openvpn-server
    sleep 2
    
    if systemctl is-active --quiet openvpn-server; then
        log "OpenVPN server restarted successfully"
    else
        error "Failed to restart OpenVPN server"
        exit 1
    fi
else
    warn "OpenVPN server is not running"
fi

log "Client '$CLIENT_NAME' revoked successfully!"
log "The client will no longer be able to connect to the VPN"

# Log the revocation
echo "$(date): Revoked client '$CLIENT_NAME'" >> /var/log/openvpn/client-management.log
