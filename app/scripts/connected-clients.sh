#!/bin/bash

# OpenVPN Manager - Connected Clients Script
# Shows currently connected VPN clients with detailed information

set -e

# Configuration
STATUS_LOG="/var/log/openvpn/openvpn-status.log"
OPENVPN_LOG="/var/log/openvpn/openvpn.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Function to format bytes
format_bytes() {
    local bytes=$1
    if command -v numfmt &> /dev/null; then
        numfmt --to=iec "$bytes" 2>/dev/null || echo "$bytes bytes"
    else
        if [ "$bytes" -ge 1073741824 ]; then
            echo "$(( bytes / 1073741824 )) GB"
        elif [ "$bytes" -ge 1048576 ]; then
            echo "$(( bytes / 1048576 )) MB"
        elif [ "$bytes" -ge 1024 ]; then
            echo "$(( bytes / 1024 )) KB"
        else
            echo "$bytes bytes"
        fi
    fi
}

# Function to calculate duration
calculate_duration() {
    local start_time="$1"
    local current_time=$(date +%s)
    
    # Try to parse the start time (OpenVPN uses different formats)
    local start_timestamp
    if [[ "$start_time" =~ ^[0-9]+$ ]]; then
        start_timestamp="$start_time"
    else
        start_timestamp=$(date -d "$start_time" +%s 2>/dev/null || echo "$current_time")
    fi
    
    local duration=$((current_time - start_timestamp))
    
    if [ $duration -ge 86400 ]; then
        echo "$((duration / 86400))d $((duration % 86400 / 3600))h $((duration % 3600 / 60))m"
    elif [ $duration -ge 3600 ]; then
        echo "$((duration / 3600))h $((duration % 3600 / 60))m"
    elif [ $duration -ge 60 ]; then
        echo "$((duration / 60))m $((duration % 60))s"
    else
        echo "${duration}s"
    fi
}

# Function to get client location (simplified)
get_client_location() {
    local ip="$1"
    # Remove port if present
    ip=$(echo "$ip" | cut -d':' -f1)
    
    # Skip private IPs
    if [[ "$ip" =~ ^10\. ]] || [[ "$ip" =~ ^192\.168\. ]] || [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; then
        echo "Private Network"
        return
    fi
    
    # Try to get location using curl (if available)
    if command -v curl &> /dev/null; then
        local location=$(curl -s "http://ip-api.com/line/$ip?fields=country,city" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
        if [ -n "$location" ] && [ "$location" != "," ]; then
            echo "$location"
        else
            echo "Unknown"
        fi
    else
        echo "Unknown"
    fi
}

echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}                  OpenVPN Connected Clients${NC}"
echo -e "${BLUE}================================================================${NC}"
echo

# Check if OpenVPN is running
if ! systemctl is-active --quiet openvpn-server; then
    echo -e "${RED}OpenVPN server is not running!${NC}"
    exit 1
fi

# Check if status log exists
if [ ! -f "$STATUS_LOG" ]; then
    echo -e "${RED}Status log not found: $STATUS_LOG${NC}"
    exit 1
fi

# Parse status log
connected_clients=()
total_clients=0

while IFS=',' read -r prefix name real_ip virtual_ip bytes_recv bytes_sent connected_since rest; do
    if [ "$prefix" = "CLIENT_LIST" ] && [ -n "$name" ]; then
        connected_clients+=("$name,$real_ip,$virtual_ip,$bytes_recv,$bytes_sent,$connected_since")
        total_clients=$((total_clients + 1))
    fi
done < "$STATUS_LOG"

# Display summary
echo -e "${GREEN}Server Status: Running${NC}"
echo -e "${GREEN}Connected Clients: $total_clients${NC}"
echo

if [ $total_clients -eq 0 ]; then
    echo -e "${YELLOW}No clients currently connected.${NC}"
    echo
    
    # Show recent connection activity
    if [ -f "$OPENVPN_LOG" ]; then
        echo -e "${BLUE}Recent Connection Activity:${NC}"
        recent_activity=$(tail -n 50 "$OPENVPN_LOG" | grep -E "(CLIENT_CONNECT|CLIENT_DISCONNECT)" | tail -n 5)
        if [ -n "$recent_activity" ]; then
            echo "$recent_activity"
        else
            echo "No recent activity found."
        fi
    fi
else
    # Display connected clients
    echo -e "${CYAN}Connected Clients Details:${NC}"
    echo "----------------------------------------"
    
    client_num=1
    total_recv=0
    total_sent=0
    
    for client_info in "${connected_clients[@]}"; do
        IFS=',' read -r name real_ip virtual_ip bytes_recv bytes_sent connected_since <<< "$client_info"
        
        echo -e "${YELLOW}[$client_num] Client: $name${NC}"
        echo "    Real IP: $real_ip"
        echo "    Virtual IP: $virtual_ip"
        echo "    Bytes Received: $(format_bytes "$bytes_recv")"
        echo "    Bytes Sent: $(format_bytes "$bytes_sent")"
        echo "    Connected Since: $connected_since"
        echo "    Duration: $(calculate_duration "$connected_since")"
        
        # Try to get location
        location=$(get_client_location "$real_ip")
        if [ "$location" != "Unknown" ] && [ "$location" != "Private Network" ]; then
            echo "    Location: $location"
        fi
        
        # Calculate total bandwidth
        total_recv=$((total_recv + bytes_recv))
        total_sent=$((total_sent + bytes_sent))
        
        echo
        client_num=$((client_num + 1))
    done
    
    # Display totals
    echo "----------------------------------------"
    echo -e "${GREEN}Total Bandwidth Usage:${NC}"
    echo "  Downloaded: $(format_bytes "$total_recv")"
    echo "  Uploaded: $(format_bytes "$total_sent")"
    echo "  Combined: $(format_bytes "$((total_recv + total_sent))")"
fi

echo
echo -e "${BLUE}================================================================${NC}"

# Show routing table if available
routing_info=$(grep "ROUTING_TABLE" "$STATUS_LOG" 2>/dev/null)
if [ -n "$routing_info" ]; then
    echo -e "${CYAN}Routing Table:${NC}"
    echo "$routing_info" | while IFS=',' read -r prefix virtual_ip name real_ip timestamp; do
        echo "  $virtual_ip -> $name ($real_ip)"
    done
    echo
fi

# Show server statistics if available
global_stats=$(grep "GLOBAL_STATS" "$STATUS_LOG" 2>/dev/null)
if [ -n "$global_stats" ]; then
    echo -e "${CYAN}Server Statistics:${NC}"
    echo "$global_stats"
    echo
fi

# Show last update time
if [ -f "$STATUS_LOG" ]; then
    last_update=$(stat -c %y "$STATUS_LOG" 2>/dev/null | cut -d'.' -f1)
    echo -e "${BLUE}Last Update: $last_update${NC}"
fi

echo -e "${BLUE}================================================================${NC}"

# Option to monitor in real-time
if [ "$1" = "--monitor" ] || [ "$1" = "-m" ]; then
    echo
    echo -e "${YELLOW}Monitoring mode activated. Press Ctrl+C to stop.${NC}"
    echo
    
    while true; do
        sleep 5
        clear
        exec "$0"
    done
fi
