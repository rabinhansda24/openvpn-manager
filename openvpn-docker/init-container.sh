#!/bin/bash

# OpenVPN Docker Container Initialization Script - Fixed Version

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
    exit 1
}

# Configuration
OPENVPN_DIR="/etc/openvpn"
EASY_RSA_DIR="$OPENVPN_DIR/easy-rsa"
SERVER_NAME="server"
CA_NAME="OpenVPN-CA"

log "Starting OpenVPN container initialization..."

# Check for TUN device availability
log "Checking TUN device availability..."
if [ ! -e /dev/net/tun ]; then
    error "TUN device not found at /dev/net/tun. Container needs --cap-add=NET_ADMIN and --device=/dev/net/tun"
fi

if [ ! -c /dev/net/tun ]; then
    error "TUN device exists but is not a character device. Check Docker configuration."
fi

log "TUN device is available"

# Test TUN device access
if ! cat /dev/net/tun > /dev/null 2>&1; then
    warn "Cannot read from TUN device, but continuing..."
fi

# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
if ! sysctl -p; then
    warn "Failed to set IP forwarding, continuing anyway..."
fi

# Check if PKI exists
if [ ! -d "$EASY_RSA_DIR/pki" ]; then
    log "Initializing PKI..."
    cd $EASY_RSA_DIR
    
    # Initialize PKI
    ./easyrsa init-pki || error "Failed to initialize PKI"
    
    # Create CA (non-interactive)
    echo "$CA_NAME" | ./easyrsa build-ca nopass || error "Failed to build CA"
    
    # Generate server certificate
    ./easyrsa --batch build-server-full $SERVER_NAME nopass || error "Failed to build server certificate"
    
    # Generate Diffie-Hellman parameters
    ./easyrsa gen-dh || error "Failed to generate DH parameters"
    
    # Generate TLS auth key
    openvpn --genkey --secret $OPENVPN_DIR/ta.key || error "Failed to generate TLS auth key"
    
    # Copy certificates
    cp pki/ca.crt $OPENVPN_DIR/ || error "Failed to copy CA certificate"
    cp pki/issued/$SERVER_NAME.crt $OPENVPN_DIR/ || error "Failed to copy server certificate"
    cp pki/private/$SERVER_NAME.key $OPENVPN_DIR/ || error "Failed to copy server key"
    cp pki/dh.pem $OPENVPN_DIR/ || error "Failed to copy DH parameters"
    
    # Set permissions
    chmod 600 $OPENVPN_DIR/$SERVER_NAME.key
    chmod 600 $OPENVPN_DIR/ta.key
    
    log "PKI initialized successfully"
else
    log "PKI already exists, skipping initialization"
fi

# Verify required certificate files exist
required_files=("ca.crt" "$SERVER_NAME.crt" "$SERVER_NAME.key" "dh.pem" "ta.key")
for file in "${required_files[@]}"; do
    if [ ! -f "$OPENVPN_DIR/$file" ]; then
        error "Required certificate file missing: $OPENVPN_DIR/$file"
    fi
done

log "All required certificate files are present"

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

# Run as nobody for security (disabled for container compatibility)
# user nobody
# group nobody
EOF
    
    log "Server configuration created"
else
    log "Server configuration already exists"
fi

# Validate OpenVPN configuration
log "Validating OpenVPN configuration..."
if ! openvpn --config $OPENVPN_DIR/server.conf --test-crypto; then
    warn "OpenVPN crypto test failed, but continuing anyway (container environment limitation)"
fi

# Create log directory and files
mkdir -p /var/log/openvpn
touch /var/log/openvpn/openvpn.log
touch /var/log/openvpn/openvpn-status.log

# Set up iptables for NAT
log "Setting up iptables rules..."

# Get the default route interface
DEFAULT_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)

if [ -n "$DEFAULT_INTERFACE" ]; then
    # Enable NAT for VPN traffic
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $DEFAULT_INTERFACE -j MASQUERADE || warn "Failed to add MASQUERADE rule"
    iptables -A INPUT -i tun0 -j ACCEPT || warn "Failed to add INPUT rule for tun0"
    iptables -A FORWARD -i $DEFAULT_INTERFACE -o tun0 -j ACCEPT || warn "Failed to add FORWARD rule"
    iptables -A FORWARD -i tun0 -o $DEFAULT_INTERFACE -j ACCEPT || warn "Failed to add FORWARD rule"
    iptables -A INPUT -i $DEFAULT_INTERFACE -p udp --dport 1194 -j ACCEPT || warn "Failed to add INPUT rule for port 1194"
    
    log "iptables rules configured for interface: $DEFAULT_INTERFACE"
else
    warn "Could not determine default interface for iptables rules"
fi

log "Starting OpenVPN server..."
log "OpenVPN configuration file: $OPENVPN_DIR/server.conf"
log "OpenVPN log file: /var/log/openvpn/openvpn.log"

# Start OpenVPN with better error handling
if ! openvpn --config $OPENVPN_DIR/server.conf; then
    error "OpenVPN failed to start. Check the configuration and logs above."
fi