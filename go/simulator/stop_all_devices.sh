#!/bin/bash

# Network Device Simulator - Stop All Devices and Server
# This script stops the simulator server and cleans up all devices

set -e  # Exit on any error

# Configuration
SERVER_PORT="8080"
PID_FILE="simulator.pid"
LOG_FILE="startup.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}🛑 Network Device Simulator - Stopping All Devices${NC}"
echo "=================================================="

# Function to delete all devices via API
delete_all_devices() {
    echo -e "${YELLOW}🗑️  Deleting all devices via API...${NC}"
    
    if curl -s "http://localhost:$SERVER_PORT/health" > /dev/null 2>&1; then
        local response=$(curl -s -X DELETE "http://localhost:$SERVER_PORT/api/v1/devices" 2>/dev/null)
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ Successfully deleted all devices${NC}"
        else
            echo -e "${YELLOW}⚠️  Could not delete devices via API (server may be stopping)${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  Server not responding, skipping device deletion${NC}"
    fi
}

# Stop the simulator server
stop_server() {
    echo -e "${YELLOW}🛑 Stopping simulator server...${NC}"
    
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill "$pid" 2>/dev/null; then
            echo -e "${GREEN}✅ Stopped simulator server (PID: $pid)${NC}"
        else
            echo -e "${YELLOW}⚠️  Process $pid not found (may have already stopped)${NC}"
        fi
        rm -f "$PID_FILE"
    else
        echo -e "${YELLOW}⚠️  No PID file found${NC}"
    fi
}

# Kill any remaining processes on the port
cleanup_port() {
    echo -e "${YELLOW}🔄 Cleaning up port $SERVER_PORT...${NC}"
    
    if lsof -ti:$SERVER_PORT >/dev/null 2>&1; then
        kill $(lsof -ti:$SERVER_PORT) 2>/dev/null || true
        sleep 2
        echo -e "${GREEN}✅ Cleaned up port $SERVER_PORT${NC}"
    else
        echo -e "${GREEN}✅ Port $SERVER_PORT is already free${NC}"
    fi
}

# Cleanup TUN interfaces
cleanup_tun_interfaces() {
    echo -e "${YELLOW}🔧 Cleaning up TUN interfaces...${NC}"
    
    # Find and delete simulator TUN interfaces
    local tun_interfaces=$(ip link show | grep -o 'sim[0-9]*:' | tr -d ':' 2>/dev/null || true)
    
    if [ -n "$tun_interfaces" ]; then
        for interface in $tun_interfaces; do
            echo -e "${BLUE}  Deleting TUN interface: $interface${NC}"
            sudo ip link delete "$interface" 2>/dev/null || true
        done
        echo -e "${GREEN}✅ TUN interfaces cleaned up${NC}"
    else
        echo -e "${GREEN}✅ No TUN interfaces to clean up${NC}"
    fi
}

# Main cleanup sequence
echo -e "${BLUE}🧹 Starting cleanup sequence...${NC}"
echo ""

# Step 1: Delete all devices
delete_all_devices

# Step 2: Stop the server
stop_server

# Step 3: Cleanup the port
cleanup_port

# Step 4: Cleanup TUN interfaces
cleanup_tun_interfaces

# Step 5: Show final status
echo ""
echo "=================================================="
echo -e "${BLUE}📊 Final Status:${NC}"
echo "------------------"

# Check if server is still running
if curl -s "http://localhost:$SERVER_PORT/health" > /dev/null 2>&1; then
    echo -e "${RED}❌ Server is still running${NC}"
else
    echo -e "${GREEN}✅ Server is stopped${NC}"
fi

# Check port status
if lsof -ti:$SERVER_PORT >/dev/null 2>&1; then
    echo -e "${RED}❌ Port $SERVER_PORT is still in use${NC}"
else
    echo -e "${GREEN}✅ Port $SERVER_PORT is free${NC}"
fi

# Check for remaining TUN interfaces
remaining_tun=$(ip link show | grep -o 'sim[0-9]*:' | tr -d ':' 2>/dev/null | wc -l || echo 0)
if [ "$remaining_tun" -gt 0 ]; then
    echo -e "${RED}❌ $remaining_tun TUN interfaces still exist${NC}"
else
    echo -e "${GREEN}✅ No TUN interfaces remaining${NC}"
fi

echo ""
echo -e "${BLUE}🗂️  Cleanup Files:${NC}"
echo "-------------------"
if [ -f "$PID_FILE" ]; then
    echo -e "${YELLOW}⚠️  PID file still exists: $PID_FILE${NC}"
else
    echo -e "${GREEN}✅ PID file cleaned up${NC}"
fi

if [ -f "$LOG_FILE" ]; then
    echo -e "${BLUE}📝 Log file preserved: $LOG_FILE${NC}"
    echo -e "${YELLOW}   Use 'rm $LOG_FILE' to delete if needed${NC}"
fi

echo ""
echo -e "${GREEN}🎉 Cleanup complete!${NC}"
echo -e "${BLUE}💡 To start devices again, run: './start_all_devices.sh'${NC}"