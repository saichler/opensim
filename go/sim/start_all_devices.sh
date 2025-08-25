#!/bin/bash

# Network Device Simulator - Start All 19 Mock Devices
# This script starts the simulator server and creates all 19 devices from Devices.go mock data
# Starting IP: 10.20.30.1

set -e  # Exit on any error

# Configuration
SERVER_PORT="8080"
BASE_IP="10.20.30"
START_IP_LAST_OCTET=1
LOG_FILE="startup.log"
PID_FILE="simulator.pid"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Network Device Simulator - Starting All Mock Devices${NC}"
echo "=================================================="
echo "Server Port: $SERVER_PORT"
echo "Starting IP: ${BASE_IP}.${START_IP_LAST_OCTET}"
echo "Log File: $LOG_FILE"
echo ""

# Function to check if server is ready
wait_for_server() {
    echo -e "${YELLOW}⏳ Waiting for server to start...${NC}"
    for i in {1..30}; do
        if curl -s "http://localhost:$SERVER_PORT/health" > /dev/null 2>&1; then
            echo -e "${GREEN}✅ Server is ready!${NC}"
            return 0
        fi
        sleep 1
        echo -n "."
    done
    echo -e "${RED}❌ Server failed to start within 30 seconds${NC}"
    exit 1
}

# Function to create a device via API
create_device() {
    local device_name="$1"
    local ip_address="$2"  
    local resource_file="$3"
    local device_count="$4"
    
    echo -e "${BLUE}🔧 Creating device: $device_name ($ip_address)${NC}"
    
    local json_payload=$(cat <<EOF
{
    "start_ip": "$ip_address",
    "device_count": $device_count,
    "netmask": "24",
    "resource_file": "$resource_file"
}
EOF
)
    
    local response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$json_payload" \
        "http://localhost:$SERVER_PORT/api/v1/devices" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Successfully created: $device_name${NC}"
        return 0
    else
        echo -e "${RED}❌ Failed to create: $device_name${NC}"
        return 1
    fi
}

# Stop any existing simulator
echo -e "${YELLOW}🛑 Stopping any existing simulator...${NC}"
if [ -f "$PID_FILE" ]; then
    if kill $(cat "$PID_FILE") 2>/dev/null; then
        echo -e "${GREEN}✅ Stopped existing simulator${NC}"
    fi
    rm -f "$PID_FILE"
fi

# Kill any process using the port
if lsof -ti:$SERVER_PORT >/dev/null 2>&1; then
    echo -e "${YELLOW}🔄 Killing process on port $SERVER_PORT...${NC}"
    kill $(lsof -ti:$SERVER_PORT) 2>/dev/null || true
    sleep 2
fi

# Start the simulator server in background
echo -e "${BLUE}🌐 Starting simulator server on port $SERVER_PORT...${NC}"
sudo ./sim -port "$SERVER_PORT" > "$LOG_FILE" 2>&1 &
SIMULATOR_PID=$!
echo $SIMULATOR_PID > "$PID_FILE"

# Wait for server to be ready
wait_for_server

echo ""
echo -e "${BLUE}🏭 Creating all 19 mock devices...${NC}"
echo "=================================================="

# Create all 19 devices based on Devices.go mock data
# Each device gets a sequential IP address starting from 10.20.30.1

# Device 1: Core-Switch-01 (Cisco Catalyst 9500)
create_device "Core-Switch-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 0))" "cisco_catalyst_9500.json" 1

# Device 2: NY-CORE-01 (Juniper MX240)  
create_device "NY-CORE-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 1))" "juniper_mx240.json" 1

# Device 3: LA-CORE-02 (Cisco ASR 9000)
create_device "LA-CORE-02" "${BASE_IP}.$(($START_IP_LAST_OCTET + 2))" "asr9k.json" 1

# Device 4: CHI-SW-01 (Palo Alto PA-3220)
create_device "CHI-SW-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 3))" "palo_alto_pa3220.json" 1

# Device 5: TOR-FW-01 (Fortinet FortiGate 600E)
create_device "TOR-FW-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 4))" "fortinet_fortigate_600e.json" 1

# Device 6: LON-CORE-01 (Juniper MX960)
create_device "LON-CORE-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 5))" "juniper_mx960.json" 1

# Device 7: PAR-SW-01 (Cisco Nexus 9500)
create_device "PAR-SW-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 6))" "cisco_nexus_9500.json" 1

# Device 8: FRA-CORE-02 (Huawei NE8000 X16)  
create_device "FRA-CORE-02" "${BASE_IP}.$(($START_IP_LAST_OCTET + 7))" "huawei_ne8000.json" 1

# Device 9: AMS-SRV-01 (Dell PowerEdge R750)
create_device "AMS-SRV-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 8))" "dell_poweredge_r750.json" 1

# Device 10: TYO-CORE-01 (NEC IX3315)
create_device "TYO-CORE-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 9))" "nec_ix3315.json" 1

# Device 11: SIN-SW-01 (Arista 7280R3)
create_device "SIN-SW-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 10))" "arista_7280r3.json" 1

# Device 12: MUM-FW-01 (Check Point 15600) - OFFLINE
create_device "MUM-FW-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 11))" "check_point_15600.json" 1

# Device 13: SEO-SRV-01 (HPE ProLiant DL380 Gen10)  
create_device "SEO-SRV-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 12))" "hpe_proliant_dl380.json" 1

# Device 14: SYD-CORE-01 (Cisco CRS-X)
create_device "SYD-CORE-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 13))" "cisco_crs_x.json" 1

# Device 15: MEL-SW-01 (Extreme Networks VSP 4450)
create_device "MEL-SW-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 14))" "extreme_vsp4450.json" 1

# Device 16: SAO-CORE-01 (Nokia 7750 SR-12)
create_device "SAO-CORE-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 15))" "nokia_7750_sr12.json" 1

# Device 17: BOG-FW-01 (SonicWall NSa 6700)
create_device "BOG-FW-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 16))" "sonicwall_nsa6700.json" 1

# Device 18: CAI-SW-01 (D-Link DGS-3630-52TC)  
create_device "CAI-SW-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 17))" "dlink_dgs3630.json" 1

# Device 19: CPT-SRV-01 (IBM Power System S922)
create_device "CPT-SRV-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 18))" "ibm_power_s922.json" 1

echo ""
echo "=================================================="
echo -e "${GREEN}🎉 All devices created successfully!${NC}"
echo ""

# Show device status
echo -e "${BLUE}📊 Device Status:${NC}"
echo "------------------"
curl -s "http://localhost:$SERVER_PORT/api/v1/devices" | python3 -m json.tool 2>/dev/null || echo "Devices created (JSON formatting not available)"

echo ""
echo -e "${BLUE}🌐 Access Information:${NC}"
echo "======================"
echo "• Web UI: http://localhost:$SERVER_PORT/"
echo "• API: http://localhost:$SERVER_PORT/api/v1/devices" 
echo "• Health: http://localhost:$SERVER_PORT/health"
echo "• Server PID: $(cat $PID_FILE)"
echo "• Log File: $LOG_FILE"
echo ""

echo -e "${BLUE}📝 Device IP Range:${NC}" 
echo "==================="
echo "• ${BASE_IP}.1  - Core-Switch-01 (Cisco Catalyst 9500)"
echo "• ${BASE_IP}.2  - NY-CORE-01 (Juniper MX240)" 
echo "• ${BASE_IP}.3  - LA-CORE-02 (Cisco ASR 9000)"
echo "• ${BASE_IP}.4  - CHI-SW-01 (Palo Alto PA-3220) ⚠️  CRITICAL"
echo "• ${BASE_IP}.5  - TOR-FW-01 (Fortinet FortiGate 600E) ⚠️  WARNING"  
echo "• ${BASE_IP}.6  - LON-CORE-01 (Juniper MX960)"
echo "• ${BASE_IP}.7  - PAR-SW-01 (Cisco Nexus 9500)"
echo "• ${BASE_IP}.8  - FRA-CORE-02 (Huawei NE8000 X16)"
echo "• ${BASE_IP}.9  - AMS-SRV-01 (Dell PowerEdge R750)"
echo "• ${BASE_IP}.10 - TYO-CORE-01 (NEC IX3315)"
echo "• ${BASE_IP}.11 - SIN-SW-01 (Arista 7280R3)"
echo "• ${BASE_IP}.12 - MUM-FW-01 (Check Point 15600) ❌ OFFLINE"
echo "• ${BASE_IP}.13 - SEO-SRV-01 (HPE ProLiant DL380 Gen10) ⚠️  WARNING"
echo "• ${BASE_IP}.14 - SYD-CORE-01 (Cisco CRS-X)"
echo "• ${BASE_IP}.15 - MEL-SW-01 (Extreme Networks VSP 4450)"
echo "• ${BASE_IP}.16 - SAO-CORE-01 (Nokia 7750 SR-12)"
echo "• ${BASE_IP}.17 - BOG-FW-01 (SonicWall NSa 6700) ⚠️  WARNING"
echo "• ${BASE_IP}.18 - CAI-SW-01 (D-Link DGS-3630-52TC)"
echo "• ${BASE_IP}.19 - CPT-SRV-01 (IBM Power System S922)"
echo ""

echo -e "${BLUE}🧪 Test Commands:${NC}"
echo "=================="
echo "# SNMP Test Examples:"
echo "snmpwalk -v2c -c public ${BASE_IP}.1 1.3.6.1.2.1.1.1.0  # Cisco Catalyst 9500"
echo "snmpwalk -v2c -c public ${BASE_IP}.2 1.3.6.1.2.1.1.1.0  # Juniper MX240"
echo "snmpwalk -v2c -c public ${BASE_IP}.4 1.3.6.1.2.1.1.1.0  # Palo Alto PA-3220"
echo ""
echo "# SSH Test Examples (password: admin):"
echo "ssh admin@${BASE_IP}.1  # Cisco CLI"
echo "ssh admin@${BASE_IP}.2  # Juniper CLI"
echo "ssh admin@${BASE_IP}.4  # Palo Alto CLI" 
echo ""
echo "# API Examples:"
echo "curl http://localhost:$SERVER_PORT/api/v1/devices"
echo "curl http://localhost:$SERVER_PORT/api/v1/devices/export"
echo ""

echo -e "${GREEN}✅ Setup complete! All 19 mock devices are running.${NC}"
echo -e "${YELLOW}📋 Use './stop_all_devices.sh' to stop all devices and server.${NC}"