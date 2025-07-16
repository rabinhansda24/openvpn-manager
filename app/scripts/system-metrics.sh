#!/bin/bash

# OpenVPN Manager - System Metrics Script
# Display comprehensive system performance metrics

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Function to get CPU usage
get_cpu_usage() {
    if command -v top &> /dev/null; then
        top -bn1 | grep "^%Cpu" | awk '{print $2}' | sed 's/%us,//'
    else
        # Fallback method
        grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$3+$4+$5)} END {print usage "%"}'
    fi
}

# Function to get memory usage
get_memory_usage() {
    free -h | awk 'NR==2{printf "Used: %s / Total: %s (%.1f%%)\n", $3, $2, $3*100/$2 }'
}

# Function to get disk usage
get_disk_usage() {
    df -h / | awk 'NR==2{printf "Used: %s / Total: %s (%s)\n", $3, $2, $5}'
}

# Function to get load average
get_load_average() {
    if [ -f /proc/loadavg ]; then
        cat /proc/loadavg | awk '{print "1min: " $1 ", 5min: " $2 ", 15min: " $3}'
    else
        uptime | awk -F'load average:' '{print $2}'
    fi
}

# Function to get network stats
get_network_stats() {
    if [ -f /proc/net/dev ]; then
        awk 'NR>2{
            rx_bytes += $2
            tx_bytes += $10
        }
        END {
            printf "RX: %.2f MB, TX: %.2f MB\n", rx_bytes/1024/1024, tx_bytes/1024/1024
        }' /proc/net/dev
    fi
}

# Function to format uptime
get_uptime() {
    if command -v uptime &> /dev/null; then
        uptime -p 2>/dev/null || uptime | awk -F', ' '{print $1}' | sed 's/.*up //'
    else
        cat /proc/uptime | awk '{print int($1/86400) "d " int($1%86400/3600) "h " int($1%3600/60) "m"}'
    fi
}

# Function to get process count
get_process_count() {
    ps aux | wc -l
}

# Function to check OpenVPN status
get_openvpn_status() {
    if systemctl is-active --quiet openvpn-server 2>/dev/null; then
        echo -e "${GREEN}Running${NC}"
        
        # Get connected clients count
        if [ -f "/var/log/openvpn/openvpn-status.log" ]; then
            client_count=$(grep -c "CLIENT_LIST" /var/log/openvpn/openvpn-status.log 2>/dev/null || echo "0")
            echo "  Connected clients: $client_count"
        fi
        
        # Get PID and memory usage
        openvpn_pid=$(pgrep openvpn 2>/dev/null || echo "")
        if [ -n "$openvpn_pid" ]; then
            openvpn_mem=$(ps -p $openvpn_pid -o rss= 2>/dev/null | awk '{print $1/1024 " MB"}' || echo "Unknown")
            echo "  Memory usage: $openvpn_mem"
        fi
    else
        echo -e "${RED}Not running${NC}"
    fi
}

# Function to get top processes
get_top_processes() {
    echo -e "${CYAN}Top 5 CPU consumers:${NC}"
    ps aux --sort=-%cpu | head -6 | tail -5 | awk '{printf "  %-20s %5s%% CPU %8s MB\n", $11, $3, $6/1024}'
    
    echo
    echo -e "${CYAN}Top 5 Memory consumers:${NC}"
    ps aux --sort=-%mem | head -6 | tail -5 | awk '{printf "  %-20s %5s%% MEM %8s MB\n", $11, $4, $6/1024}'
}

# Function to get disk I/O
get_disk_io() {
    if [ -f /proc/diskstats ]; then
        awk '
        BEGIN { sectors_read = 0; sectors_written = 0 }
        /sd[a-z]$/ { 
            sectors_read += $6
            sectors_written += $10
        }
        END {
            printf "Read: %.2f MB, Written: %.2f MB\n", 
                   sectors_read * 512 / 1024 / 1024,
                   sectors_written * 512 / 1024 / 1024
        }' /proc/diskstats
    fi
}

# Function to check service status
check_service_status() {
    local service=$1
    if systemctl is-active --quiet $service 2>/dev/null; then
        echo -e "${GREEN}Running${NC}"
    else
        echo -e "${RED}Not running${NC}"
    fi
}

# Main display function
show_metrics() {
    clear
    
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE}                    System Performance Metrics${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo
    
    # System Information
    echo -e "${MAGENTA}System Information:${NC}"
    echo "  Hostname: $(hostname)"
    echo "  Kernel: $(uname -r)"
    echo "  Uptime: $(get_uptime)"
    echo "  Processes: $(get_process_count)"
    echo
    
    # CPU Information
    echo -e "${YELLOW}CPU Usage:${NC}"
    echo "  Current: $(get_cpu_usage)"
    echo "  Load Average: $(get_load_average)"
    if [ -f /proc/cpuinfo ]; then
        cpu_count=$(grep -c ^processor /proc/cpuinfo)
        cpu_model=$(grep "model name" /proc/cpuinfo | head -1 | cut -d':' -f2 | sed 's/^ *//')
        echo "  Cores: $cpu_count"
        echo "  Model: $cpu_model"
    fi
    echo
    
    # Memory Information
    echo -e "${GREEN}Memory Usage:${NC}"
    echo "  $(get_memory_usage)"
    
    # Swap information
    if command -v free &> /dev/null; then
        swap_info=$(free -h | awk 'NR==3{printf "Swap Used: %s / Total: %s\n", $3, $2}')
        if [ -n "$swap_info" ]; then
            echo "  $swap_info"
        fi
    fi
    echo
    
    # Disk Information
    echo -e "${CYAN}Disk Usage:${NC}"
    echo "  Root: $(get_disk_usage)"
    
    disk_io=$(get_disk_io)
    if [ -n "$disk_io" ]; then
        echo "  I/O Total: $disk_io"
    fi
    echo
    
    # Network Information
    echo -e "${BLUE}Network Statistics:${NC}"
    network_stats=$(get_network_stats)
    if [ -n "$network_stats" ]; then
        echo "  Total: $network_stats"
    fi
    
    # Show network interfaces
    if command -v ip &> /dev/null; then
        active_interfaces=$(ip link show | grep "state UP" | awk -F': ' '{print $2}' | tr '\n' ' ')
        echo "  Active interfaces: $active_interfaces"
    fi
    echo
    
    # Service Status
    echo -e "${MAGENTA}Service Status:${NC}"
    echo -n "  OpenVPN Server: "
    get_openvpn_status
    
    echo -n "  SSH: "
    check_service_status ssh
    
    echo -n "  Firewall (UFW): "
    check_service_status ufw
    
    # Check if Docker is installed
    if command -v docker &> /dev/null; then
        echo -n "  Docker: "
        check_service_status docker
    fi
    echo
    
    # Process Information
    get_top_processes
    echo
    
    # Alerts/Warnings
    echo -e "${RED}System Alerts:${NC}"
    alerts_found=false
    
    # Check CPU usage
    cpu_usage=$(get_cpu_usage | sed 's/%//')
    if (( $(echo "$cpu_usage > 90" | bc -l 2>/dev/null || echo "0") )); then
        echo -e "  ${RED}⚠ High CPU usage: ${cpu_usage}%${NC}"
        alerts_found=true
    fi
    
    # Check memory usage
    mem_percent=$(free | awk 'NR==2{printf "%.1f", $3*100/$2 }')
    if (( $(echo "$mem_percent > 90" | bc -l 2>/dev/null || echo "0") )); then
        echo -e "  ${RED}⚠ High memory usage: ${mem_percent}%${NC}"
        alerts_found=true
    fi
    
    # Check disk usage
    disk_percent=$(df / | awk 'NR==2{print $5}' | sed 's/%//')
    if [ "$disk_percent" -gt 90 ]; then
        echo -e "  ${RED}⚠ High disk usage: ${disk_percent}%${NC}"
        alerts_found=true
    fi
    
    # Check load average
    load_1min=$(cat /proc/loadavg | awk '{print $1}')
    cpu_cores=$(nproc)
    if (( $(echo "$load_1min > $cpu_cores" | bc -l 2>/dev/null || echo "0") )); then
        echo -e "  ${RED}⚠ High system load: $load_1min (CPUs: $cpu_cores)${NC}"
        alerts_found=true
    fi
    
    if [ "$alerts_found" = false ]; then
        echo -e "  ${GREEN}✓ No alerts - system operating normally${NC}"
    fi
    
    echo
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE}Last updated: $(date)${NC}"
    echo -e "${BLUE}================================================================${NC}"
}

# Check command line arguments
case "${1:-}" in
    --monitor|-m)
        echo "Starting system monitoring... Press Ctrl+C to stop."
        while true; do
            show_metrics
            sleep 5
        done
        ;;
    --json)
        # Output JSON format for API consumption
        cat << EOF
{
    "timestamp": "$(date -Iseconds)",
    "cpu_usage": $(get_cpu_usage | sed 's/%//'),
    "memory": {
        $(free -b | awk 'NR==2{printf "\"total\": %s, \"used\": %s, \"free\": %s, \"percent\": %.1f", $2, $3, $4, $3*100/$2}')
    },
    "disk": {
        $(df -B1 / | awk 'NR==2{printf "\"total\": %s, \"used\": %s, \"free\": %s, \"percent\": %.1f", $2, $3, $4, $3*100/$2}')
    },
    "load_average": [$(cat /proc/loadavg | awk '{print $1 ", " $2 ", " $3}')],
    "uptime_seconds": $(cat /proc/uptime | awk '{print int($1)}'),
    "openvpn_running": $(systemctl is-active --quiet openvpn-server && echo "true" || echo "false")
}
EOF
        ;;
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo "Options:"
        echo "  --monitor, -m    Monitor in real-time"
        echo "  --json           Output in JSON format"
        echo "  --help, -h       Show this help"
        ;;
    *)
        show_metrics
        ;;
esac
