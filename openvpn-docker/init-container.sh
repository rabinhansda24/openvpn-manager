#!/bin/bash

# OpenVPN Docker Container Initialization Script

set -e

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

# Configuration
OPENVPN_DIR="/etc/openvpn"
EASY_RSA_DIR="$OPENVPN_DIR/easy-rsa"
SERVER_NAME="server"
CA_NAME="OpenVPN-CA"

log "Starting OpenVPN container initialization..."

# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# Check if PKI exists
if [ ! -d "$EASY_RSA_DIR/pki" ]; then
    log "Initializing PKI..."
    cd $EASY_RSA_DIR
    
    # Initialize PKI
    ./easyrsa init-pki
    
    # Create CA (non-interactive)
    echo "$CA_NAME" | ./easyrsa build-ca nopass
    
    # Generate server certificate
    ./easyrsa build-server-full $SERVER_NAME nopass
    
    # Generate Diffie-Hellman parameters
    ./easyrsa gen-dh
    
    # Generate TLS auth key
    openvpn --genkey --secret $OPENVPN_DIR/ta.key
    
    # Copy certificates
    cp pki/ca.crt $OPENVPN_DIR/
    cp pki/issued/$SERVER_NAME.crt $OPENVPN_DIR/
    cp pki/private/$SERVER_NAME.key $OPENVPN_DIR/
    cp pki/dh.pem $OPENVPN_DIR/
    
    # Set permissions
    chmod 600 $OPENVPN_DIR/$SERVER_NAME.key
    chmod 600 $OPENVPN_DIR/ta.key
    
    log "PKI initialized successfully"
else
    log "PKI already exists, skipping initialization"
fi

# Create server configuration if it doesn't exist
if [ ! -f "$OPENVPN_DIR/server.conf" ]; then
    log "Creating default server configuration..."
    
    cat > $OPENVPN_DIR/server.conf << EOF
# OpenVPN Server Configuration
# Generated for Docker container

# Network settings
port 1194
proto udp
dev tun

# SSL/TLS settings
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key
dh dh.pem
tls-auth ta.key 0

# Network topology
topology subnet
server 10.8.0.0 255.255.255.0

# Push routes to clients
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

# Client settings
ifconfig-pool-persist /var/log/openvpn/ipp.txt
client-config-dir $OPENVPN_DIR/ccd

# Security settings
cipher AES-256-CBC
auth SHA512
tls-version-min 1.2

# Connection settings
keepalive 10 120
max-clients 100
persist-key
persist-tun

# Logging
status /var/log/openvpn/openvpn-status.log
log /var/log/openvpn/openvpn.log
verb 3
explicit-exit-notify 1

# Management interface
management 0.0.0.0 7505

# Run as nobody for security
user nobody
group nobody
EOF
    
    log "Server configuration created"
else
    log "Server configuration already exists"
fi

# Set up iptables for NAT
log "Setting up iptables rules..."

# Get the default route interface
DEFAULT_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)

if [ -n "$DEFAULT_INTERFACE" ]; then
    # Enable NAT for VPN traffic
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $DEFAULT_INTERFACE -j MASQUERADE
    iptables -A INPUT -i tun0 -j ACCEPT
    iptables -A FORWARD -i $DEFAULT_INTERFACE -o tun0 -j ACCEPT
    iptables -A FORWARD -i tun0 -o $DEFAULT_INTERFACE -j ACCEPT
    iptables -A INPUT -i $DEFAULT_INTERFACE -p udp --dport 1194 -j ACCEPT
    
    log "iptables rules configured for interface: $DEFAULT_INTERFACE"
else
    warn "Could not determine default interface for iptables rules"
fi

# Create log files
touch /var/log/openvpn/openvpn.log
touch /var/log/openvpn/openvpn-status.log

log "Starting OpenVPN server..."

# Start OpenVPN
exec openvpn --config $OPENVPN_DIR/server.conf
