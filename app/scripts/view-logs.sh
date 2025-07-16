#!/bin/bash

# OpenVPN Manager - View Logs Script
# Display OpenVPN server logs with filtering options

set -e

# Configuration
OPENVPN_LOG="/var/log/openvpn/openvpn.log"
STATUS_LOG="/var/log/openvpn/openvpn-status.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default values
LINES=50
LOG_TYPE="server"
FOLLOW=false
SEARCH=""

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  -n, --lines NUMBER    Number of lines to show (default: 50)"
    echo "  -t, --type TYPE       Log type: server, status, management (default: server)"
    echo "  -f, --follow          Follow log output (like tail -f)"
    echo "  -s, --search TEXT     Search for specific text"
    echo "  -h, --help            Show this help message"
    echo
    echo "Examples:"
    echo "  $0 -n 100                    # Show last 100 lines"
    echo "  $0 -f                        # Follow server log"
    echo "  $0 -t status                 # Show status log"
    echo "  $0 -s 'CLIENT_CONNECT'       # Search for client connections"
}

# Parse command line options
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--lines)
            LINES="$2"
            shift 2
            ;;
        -t|--type)
            LOG_TYPE="$2"
            shift 2
            ;;
        -f|--follow)
            FOLLOW=true
            shift
            ;;
        -s|--search)
            SEARCH="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Validate lines parameter
if ! [[ "$LINES" =~ ^[0-9]+$ ]]; then
    echo -e "${RED}Error: Lines must be a number${NC}"
    exit 1
fi

# Select log file based on type
case $LOG_TYPE in
    server)
        LOG_FILE="$OPENVPN_LOG"
        TITLE="OpenVPN Server Log"
        ;;
    status)
        LOG_FILE="$STATUS_LOG"
        TITLE="OpenVPN Status Log"
        ;;
    management)
        LOG_FILE="/var/log/openvpn/client-management.log"
        TITLE="Client Management Log"
        ;;
    *)
        echo -e "${RED}Error: Invalid log type. Use: server, status, or management${NC}"
        exit 1
        ;;
esac

# Check if log file exists
if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED}Error: Log file not found: $LOG_FILE${NC}"
    exit 1
fi

# Display header
echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}$TITLE${NC}"
if [ -n "$SEARCH" ]; then
    echo -e "${BLUE}Search: $SEARCH${NC}"
fi
echo -e "${BLUE}================================================================${NC}"

# Function to colorize log levels
colorize_log() {
    sed -E \
        -e "s/.*(ERROR|FATAL).*/$(printf "${RED}")&$(printf "${NC}")/g" \
        -e "s/.*(WARN|WARNING).*/$(printf "${YELLOW}")&$(printf "${NC}")/g" \
        -e "s/.*(INFO|NOTICE).*/$(printf "${GREEN}")&$(printf "${NC}")/g" \
        -e "s/.*(DEBUG|VERB).*/$(printf "${BLUE}")&$(printf "${NC}")/g"
}

# Function to filter and display logs
display_logs() {
    if [ -n "$SEARCH" ]; then
        if [ "$FOLLOW" = true ]; then
            tail -f "$LOG_FILE" | grep --line-buffered "$SEARCH" | colorize_log
        else
            tail -n "$LINES" "$LOG_FILE" | grep "$SEARCH" | colorize_log
        fi
    else
        if [ "$FOLLOW" = true ]; then
            tail -f "$LOG_FILE" | colorize_log
        else
            tail -n "$LINES" "$LOG_FILE" | colorize_log
        fi
    fi
}

# Special handling for status log
if [ "$LOG_TYPE" = "status" ]; then
    echo -e "${GREEN}Current OpenVPN Status:${NC}"
    echo
    
    if [ -s "$LOG_FILE" ]; then
        # Parse status log
        echo -e "${YELLOW}Connected Clients:${NC}"
        grep "CLIENT_LIST" "$LOG_FILE" 2>/dev/null | while IFS=',' read -r prefix name real_ip virtual_ip bytes_recv bytes_sent connected_since; do
            echo "  Client: $name"
            echo "    Real IP: $real_ip"
            echo "    Virtual IP: $virtual_ip"
            echo "    Bytes Received: $(numfmt --to=iec $bytes_recv 2>/dev/null || echo $bytes_recv)"
            echo "    Bytes Sent: $(numfmt --to=iec $bytes_sent 2>/dev/null || echo $bytes_sent)"
            echo "    Connected Since: $connected_since"
            echo
        done
        
        echo -e "${YELLOW}Routing Table:${NC}"
        grep "ROUTING_TABLE" "$LOG_FILE" 2>/dev/null | while IFS=',' read -r prefix virtual_ip name real_ip timestamp; do
            echo "  $virtual_ip -> $name ($real_ip) since $timestamp"
        done
        
        echo
        echo -e "${YELLOW}Global Stats:${NC}"
        grep "GLOBAL_STATS" "$LOG_FILE" 2>/dev/null || echo "  No global statistics available"
    else
        echo "  No status information available"
    fi
    echo
    
    if [ "$FOLLOW" = true ]; then
        echo -e "${BLUE}Following status updates... (Press Ctrl+C to stop)${NC}"
        tail -f "$LOG_FILE"
    fi
else
    # Display regular logs
    if [ "$FOLLOW" = true ]; then
        echo -e "${BLUE}Following log updates... (Press Ctrl+C to stop)${NC}"
        echo
    fi
    
    display_logs
fi

# If not following, show summary
if [ "$FOLLOW" = false ] && [ "$LOG_TYPE" = "server" ]; then
    echo
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE}Log Summary (last $LINES lines):${NC}"
    
    # Count log levels
    error_count=$(tail -n "$LINES" "$LOG_FILE" | grep -c -i "error\|fatal" || echo "0")
    warn_count=$(tail -n "$LINES" "$LOG_FILE" | grep -c -i "warn" || echo "0")
    info_count=$(tail -n "$LINES" "$LOG_FILE" | grep -c -i "info\|notice" || echo "0")
    
    echo "Errors: $error_count"
    echo "Warnings: $warn_count"
    echo "Info: $info_count"
    
    # Show recent client activity
    recent_connects=$(tail -n "$LINES" "$LOG_FILE" | grep -c "CLIENT_CONNECT" || echo "0")
    recent_disconnects=$(tail -n "$LINES" "$LOG_FILE" | grep -c "CLIENT_DISCONNECT" || echo "0")
    
    echo "Recent Connections: $recent_connects"
    echo "Recent Disconnections: $recent_disconnects"
fi
