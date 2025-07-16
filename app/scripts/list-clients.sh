#!/bin/bash

# OpenVPN Manager - List Clients Script
# Lists all client certificates (active and revoked)

set -e

# Configuration
OPENVPN_DIR="/etc/openvpn"
EASY_RSA_DIR="$OPENVPN_DIR/easy-rsa"
CLIENT_DIR="$OPENVPN_DIR/clients"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${GREEN}$1${NC}"
}

warn() {
    echo -e "${YELLOW}$1${NC}"
}

error() {
    echo -e "${RED}$1${NC}"
}

info() {
    echo -e "${BLUE}$1${NC}"
}

# Check if Easy-RSA is initialized
if [ ! -d "$EASY_RSA_DIR/pki" ]; then
    error "PKI not initialized. Run init-openvpn.sh first."
    exit 1
fi

cd $EASY_RSA_DIR

echo "================================================================"
echo "                    OpenVPN Client Certificates"
echo "================================================================"
echo

# List active certificates
info "ACTIVE CERTIFICATES:"
echo "--------------------"

if [ -d "pki/issued" ] && [ "$(ls -A pki/issued 2>/dev/null)" ]; then
    for cert_file in pki/issued/*.crt; do
        if [ -f "$cert_file" ]; then
            client_name=$(basename "$cert_file" .crt)
            
            # Skip server certificate
            if [ "$client_name" = "server" ]; then
                continue
            fi
            
            # Check if certificate is revoked
            if [ -f "pki/revoked/certs_by_serial/$client_name.crt" ]; then
                continue
            fi
            
            # Get certificate details
            issue_date=$(openssl x509 -in "$cert_file" -noout -startdate 2>/dev/null | cut -d= -f2)
            expire_date=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
            serial=$(openssl x509 -in "$cert_file" -noout -serial 2>/dev/null | cut -d= -f2)
            
            echo "Client: $client_name"
            echo "  Serial: $serial"
            echo "  Issued: $issue_date"
            echo "  Expires: $expire_date"
            
            # Check if config file exists
            if [ -f "$CLIENT_DIR/$client_name.ovpn" ]; then
                echo "  Config: Available"
            else
                warn "  Config: Missing"
            fi
            
            # Check expiration
            expire_timestamp=$(date -d "$expire_date" +%s 2>/dev/null || echo "0")
            current_timestamp=$(date +%s)
            days_left=$(( (expire_timestamp - current_timestamp) / 86400 ))
            
            if [ $days_left -lt 30 ] && [ $days_left -gt 0 ]; then
                warn "  Status: Expires in $days_left days"
            elif [ $days_left -le 0 ]; then
                error "  Status: EXPIRED"
            else
                log "  Status: Valid ($days_left days left)"
            fi
            
            echo
        fi
    done
else
    warn "No active client certificates found."
    echo
fi

# List revoked certificates
info "REVOKED CERTIFICATES:"
echo "---------------------"

revoked_found=false
if [ -d "pki/revoked" ]; then
    # Check CRL for revoked certificates
    if [ -f "pki/crl.pem" ]; then
        crl_content=$(openssl crl -in pki/crl.pem -noout -text 2>/dev/null)
        
        if echo "$crl_content" | grep -q "Revoked Certificates:"; then
            revoked_found=true
            
            # Parse revoked certificates from CRL
            echo "$crl_content" | awk '
                /Revoked Certificates:/{flag=1; next}
                /Signature Algorithm:/{flag=0}
                flag && /Serial Number:/ {
                    gsub(/Serial Number: /, "", $0)
                    gsub(/ \(.*\)/, "", $0)
                    serial = $0
                    getline
                    if(/Revocation Date:/) {
                        gsub(/Revocation Date: /, "", $0)
                        print "Serial: " serial
                        print "  Revoked: " $0
                        print ""
                    }
                }
            '
        fi
    fi
fi

if [ "$revoked_found" = false ]; then
    log "No revoked certificates found."
    echo
fi

# Summary
echo "================================================================"
info "SUMMARY:"

# Count active certificates
active_count=0
if [ -d "pki/issued" ]; then
    for cert_file in pki/issued/*.crt; do
        if [ -f "$cert_file" ]; then
            client_name=$(basename "$cert_file" .crt)
            if [ "$client_name" != "server" ] && [ ! -f "pki/revoked/certs_by_serial/$client_name.crt" ]; then
                active_count=$((active_count + 1))
            fi
        fi
    done
fi

# Count revoked certificates
revoked_count=0
if [ -f "pki/crl.pem" ]; then
    revoked_count=$(openssl crl -in pki/crl.pem -noout -text 2>/dev/null | grep -c "Serial Number:" || echo "0")
fi

echo "Active Certificates: $active_count"
echo "Revoked Certificates: $revoked_count"
echo "Total Certificates: $((active_count + revoked_count))"

# Check OpenVPN server status
echo
info "SERVER STATUS:"
if systemctl is-active --quiet openvpn-server; then
    log "OpenVPN Server: Running"
    
    # Show connected clients if status log exists
    if [ -f "/var/log/openvpn/openvpn-status.log" ]; then
        connected_count=$(grep -c "CLIENT_LIST" /var/log/openvpn/openvpn-status.log 2>/dev/null || echo "0")
        echo "Connected Clients: $connected_count"
        
        if [ $connected_count -gt 0 ]; then
            echo
            info "CONNECTED CLIENTS:"
            grep "CLIENT_LIST" /var/log/openvpn/openvpn-status.log | while IFS=',' read -r prefix name real_ip virtual_ip bytes_recv bytes_sent connected_since; do
                echo "  $name ($virtual_ip) - Connected since: $connected_since"
            done
        fi
    fi
else
    error "OpenVPN Server: Not Running"
fi

echo "================================================================"
