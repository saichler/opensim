package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// Web handlers for HTTP API endpoints

func createDevicesHandler(w http.ResponseWriter, r *http.Request) {
	var req CreateDevicesRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		sendErrorResponse(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.DeviceCount <= 0 {
		sendErrorResponse(w, "Device count must be greater than 0", http.StatusBadRequest)
		return
	}

	// Use CreateDevicesWithOptions if pre-allocation parameters are specified
	if req.PreAllocate || req.MaxWorkers > 0 {
		// If PreAllocate is not explicitly set but MaxWorkers is provided, enable pre-allocation
		preAllocate := req.PreAllocate || req.MaxWorkers > 0
		err = manager.CreateDevicesWithOptions(req.StartIP, req.DeviceCount, req.Netmask, req.ResourceFile, req.SNMPv3, preAllocate, req.MaxWorkers)
	} else {
		// Use default behavior (auto pre-allocates for 10+ devices)
		err = manager.CreateDevices(req.StartIP, req.DeviceCount, req.Netmask, req.ResourceFile, req.SNMPv3)
	}
	if err != nil {
		sendErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendSuccessResponse(w, fmt.Sprintf("Created %d devices starting from %s", req.DeviceCount, req.StartIP))
}

func listDevicesHandler(w http.ResponseWriter, r *http.Request) {
	devices := manager.ListDevices()
	sendDataResponse(w, devices)
}

func listResourcesHandler(w http.ResponseWriter, r *http.Request) {
	resources := manager.ListAvailableResources()
	sendDataResponse(w, resources)
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	status := manager.GetStatus()
	sendDataResponse(w, status)
}

func deleteDeviceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID := vars["id"]

	err := manager.DeleteDevice(deviceID)
	if err != nil {
		sendErrorResponse(w, err.Error(), http.StatusNotFound)
		return
	}

	sendSuccessResponse(w, fmt.Sprintf("Device %s deleted", deviceID))
}

func deleteAllDevicesHandler(w http.ResponseWriter, r *http.Request) {
	err := manager.DeleteAllDevices()
	if err != nil {
		sendErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendSuccessResponse(w, "All devices deleted")
}

func exportDevicesCSVHandler(w http.ResponseWriter, r *http.Request) {
	devices := manager.ListDevices()
	
	// Set headers for CSV download
	filename := fmt.Sprintf("devices_%s.csv", time.Now().Format("2006-01-02_15-04-05"))
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	
	// Create CSV writer
	writer := csv.NewWriter(w)
	defer writer.Flush()
	
	// Write CSV headers
	headers := []string{"Device ID", "IP Address", "Interface", "SNMP Port", "SSH Port", "Status"}
	if err := writer.Write(headers); err != nil {
		http.Error(w, "Failed to write CSV headers", http.StatusInternalServerError)
		return
	}
	
	// Write device data
	for _, device := range devices {
		status := "Stopped"
		if device.Running {
			status = "Running"
		}
		
		interfaceName := device.Interface
		if interfaceName == "" {
			interfaceName = "N/A"
		}
		
		record := []string{
			device.ID,
			device.IP,
			interfaceName,
			fmt.Sprintf("%d", device.SNMPPort),
			fmt.Sprintf("%d", device.SSHPort),
			status,
		}
		
		if err := writer.Write(record); err != nil {
			http.Error(w, "Failed to write CSV record", http.StatusInternalServerError)
			return
		}
	}
}

func generateRouteScriptHandler(w http.ResponseWriter, r *http.Request) {
	devices := manager.ListDevices()
	
	// Set headers for script download
	filename := fmt.Sprintf("add_simulator_routes_%s.sh", time.Now().Format("2006-01-02_15-04-05"))
	w.Header().Set("Content-Type", "application/x-sh")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	
	// Generate bash script content
	script := generateRouteScript(devices)
	w.Write([]byte(script))
}

func generateRouteScript(devices []DeviceInfo) string {
	if len(devices) == 0 {
		return `#!/bin/bash
# No devices found in simulator
echo "No devices found in simulator"
exit 1
`
	}

	// Collect unique subnets from devices
	subnets := make(map[string]bool)
	for _, device := range devices {
		ip := net.ParseIP(device.IP)
		if ip != nil {
			// Assume /24 subnet for route calculation
			subnet := fmt.Sprintf("%d.%d.%d.0/24", ip[12], ip[13], ip[14])
			subnets[subnet] = true
		}
	}

	var script strings.Builder
	script.WriteString(`#!/bin/bash
#
# Enhanced Static Route Configuration Script for Network Device Simulator
# Generated on: ` + time.Now().Format("2006-01-02 15:04:05") + `
#
# This script creates PERMANENT routes by default (persist after reboot)
# Usage: ./add_simulator_routes.sh <SIMULATOR_HOST_IP> [--temporary]
#
# Examples:
#   ./add_simulator_routes.sh 192.168.1.100              # Permanent routes (DEFAULT)
#   ./add_simulator_routes.sh 192.168.1.100 --temporary  # Temporary routes (until reboot)
#

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to show usage
show_usage() {
    echo "Usage: $0 <SIMULATOR_HOST_IP> [--temporary]"
    echo ""
    echo "Options:"
    echo "  --temporary    Add routes only until next reboot (optional)"
    echo "                 DEFAULT: Routes are made permanent"
    echo ""
    echo "Examples:"
    echo "  $0 192.168.1.100              # Add PERMANENT routes (default)"
    echo "  $0 192.168.1.100 --temporary  # Add temporary routes"
    echo ""
    echo "This script will configure routes for the following subnets:"
`)

	// Add subnet list to help text
	for subnet := range subnets {
		script.WriteString(fmt.Sprintf(`    echo "  - %s"`, subnet))
		script.WriteString("\n")
	}

	script.WriteString(`    echo ""
    echo "Supported operating systems for persistent routes:"
    echo "  - Ubuntu/Debian (via /etc/systemd/networkd/ or netplan)"
    echo "  - RHEL/CentOS/Fedora (via NetworkManager or network-scripts)"
    echo "  - openSUSE (via wicked)"
    echo ""
}

# Parse arguments
if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    show_usage
    exit 1
fi

SIMULATOR_HOST=$1
PERMANENT=true  # DEFAULT: Always create permanent routes

if [ "$2" = "--temporary" ]; then
    PERMANENT=false
    echo -e "${YELLOW}⚠️  Using temporary mode - routes will be lost after reboot${NC}"
fi

# Detect operating system
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VERSION=$VERSION_ID
    else
        OS=$(uname -s)
        VERSION=$(uname -r)
    fi

    # Normalize OS detection
    case "$OS" in
        *Ubuntu*|*Debian*)
            OS_TYPE="debian"
            ;;
        *"Red Hat"*|*CentOS*|*Fedora*|*Rocky*|*AlmaLinux*)
            OS_TYPE="rhel"
            ;;
        *openSUSE*|*SUSE*)
            OS_TYPE="suse"
            ;;
        *)
            OS_TYPE="unknown"
            ;;
    esac
}

# Function to add temporary routes
add_temporary_routes() {
    echo -e "${BLUE}📡 Adding temporary static routes to simulator subnets via $SIMULATOR_HOST${NC}"
    echo ""
`)

	// Add temporary route commands for each subnet
	for subnet := range subnets {
		script.WriteString(fmt.Sprintf(`    echo -e "${YELLOW}Adding temporary route: %s via $SIMULATOR_HOST${NC}"
    if sudo ip route add %s via $SIMULATOR_HOST 2>/dev/null; then
        echo -e "${GREEN}✅ Successfully added route for %s${NC}"
    else
        echo -e "${YELLOW}⚠️  Route %s already exists or failed to add${NC}"
    fi
    echo ""
`, subnet, subnet, subnet, subnet))
	}

	script.WriteString(`}

# Function to add permanent routes
add_permanent_routes() {
    echo -e "${BLUE}💾 Adding permanent static routes to simulator subnets via $SIMULATOR_HOST${NC}"
    echo -e "${YELLOW}⚠️  This requires root privileges and will modify system configuration files${NC}"
    echo ""

    detect_os

    case "$OS_TYPE" in
        "debian")
            add_permanent_routes_debian
            ;;
        "rhel")
            add_permanent_routes_rhel
            ;;
        "suse")
            add_permanent_routes_suse
            ;;
        *)
            echo -e "${RED}❌ Unsupported OS for permanent routes: $OS${NC}"
            echo -e "${YELLOW}💡 Falling back to temporary routes...${NC}"
            add_temporary_routes
            echo ""
            echo -e "${BLUE}📋 Manual permanent route configuration:${NC}"
            echo -e "${YELLOW}For your OS ($OS), manually add these routes to your system configuration:${NC}"
`)

	for subnet := range subnets {
		script.WriteString(fmt.Sprintf(`            echo "  Route: %s via $SIMULATOR_HOST"`, subnet))
		script.WriteString("\n")
	}

	script.WriteString(`            return
            ;;
    esac
}

# Function to add permanent routes on Debian/Ubuntu systems
add_permanent_routes_debian() {
    echo -e "${BLUE}🐧 Detected Debian/Ubuntu system${NC}"

    # Detect Ubuntu version if possible
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo -e "${BLUE}📋 System: $NAME $VERSION${NC}"
    fi

    # For Ubuntu Server 20.04+ and Ubuntu Desktop 18.04+, netplan is the default
    # Check if netplan is being used (it should be for Ubuntu 24.04)
    if [ -d "/etc/netplan" ] && [ "$(ls -A /etc/netplan/*.yaml /etc/netplan/*.yml 2>/dev/null)" ]; then
        echo -e "${YELLOW}📝 Using netplan configuration (recommended for Ubuntu 18.04+)${NC}"
        add_permanent_routes_netplan
    elif [ -d "/etc/netplan" ] && [ ! "$(ls -A /etc/netplan 2>/dev/null)" ]; then
        # Netplan directory exists but is empty - create a new config
        echo -e "${YELLOW}📝 Netplan directory exists but empty - creating new configuration${NC}"
        add_permanent_routes_netplan
    elif command -v systemctl >/dev/null 2>&1 && systemctl is-enabled systemd-networkd >/dev/null 2>&1; then
        echo -e "${YELLOW}📝 Using systemd-networkd configuration${NC}"
        add_permanent_routes_systemd_networkd
    else
        echo -e "${YELLOW}📝 Using traditional network interfaces${NC}"
        add_permanent_routes_interfaces
    fi
}

# Function for netplan-based systems (Ubuntu 18.04+)
add_permanent_routes_netplan() {
    local netplan_file="/etc/netplan/99-simulator-routes.yaml"

    # First check if there's an existing netplan configuration and detect the renderer
    local renderer="systemd-networkd"  # Default for Ubuntu Server
    local existing_netplan=$(ls /etc/netplan/*.yaml /etc/netplan/*.yml 2>/dev/null | head -1)

    if [ -n "$existing_netplan" ]; then
        # Check if NetworkManager is the renderer
        if grep -q "renderer.*NetworkManager" "$existing_netplan" 2>/dev/null; then
            renderer="NetworkManager"
            echo -e "${YELLOW}📝 Detected NetworkManager as netplan renderer${NC}"
        elif grep -q "renderer.*networkd" "$existing_netplan" 2>/dev/null; then
            renderer="systemd-networkd"
            echo -e "${YELLOW}📝 Detected systemd-networkd as netplan renderer${NC}"
        else
            # No explicit renderer, check what's actually running
            if systemctl is-active NetworkManager >/dev/null 2>&1; then
                renderer="NetworkManager"
                echo -e "${YELLOW}📝 NetworkManager is active, using it as renderer${NC}"
            else
                renderer="systemd-networkd"
                echo -e "${YELLOW}📝 Using systemd-networkd as default renderer${NC}"
            fi
        fi
    fi

    # Detect primary network interface
    local primary_interface=$(ip route show default | head -1 | awk '{print $5}')

    if [ -z "$primary_interface" ]; then
        echo -e "${RED}❌ Could not detect primary network interface${NC}"
        return 1
    fi

    echo -e "${BLUE}📡 Configuring routes for interface: $primary_interface${NC}"

    # Create the netplan file with proper structure
    echo "# Static routes for Network Device Simulator" | sudo tee "$netplan_file" > /dev/null
    echo "# Generated on $(date)" | sudo tee -a "$netplan_file" > /dev/null
    echo "# Interface: $primary_interface" | sudo tee -a "$netplan_file" > /dev/null
    echo "network:" | sudo tee -a "$netplan_file" > /dev/null
    echo "  version: 2" | sudo tee -a "$netplan_file" > /dev/null

    # Add renderer if needed
    if [ "$renderer" = "NetworkManager" ]; then
        echo "  renderer: NetworkManager" | sudo tee -a "$netplan_file" > /dev/null
    fi
    # systemd-networkd is default, so we don't need to specify it explicitly

    echo "  ethernets:" | sudo tee -a "$netplan_file" > /dev/null
    echo "    $primary_interface:" | sudo tee -a "$netplan_file" > /dev/null
    echo "      routes:" | sudo tee -a "$netplan_file" > /dev/null
`)

	for subnet := range subnets {
		script.WriteString(fmt.Sprintf(`    echo "        - to: %s" | sudo tee -a "$netplan_file" > /dev/null
    echo "          via: $SIMULATOR_HOST" | sudo tee -a "$netplan_file" > /dev/null
`, subnet))
	}

	script.WriteString(`
    echo -e "${GREEN}✅ Created netplan configuration: $netplan_file${NC}"

    # Test the configuration first
    echo -e "${YELLOW}🔍 Testing netplan configuration...${NC}"
    if sudo netplan generate 2>/dev/null; then
        echo -e "${GREEN}✅ Configuration syntax is valid${NC}"

        echo -e "${YELLOW}🔄 Applying netplan configuration...${NC}"
        if sudo netplan apply 2>&1 | grep -q "error\|Error\|ERROR"; then
            echo -e "${RED}❌ Failed to apply netplan configuration${NC}"
            echo -e "${YELLOW}💡 Trying alternative approach...${NC}"

            # Try to just restart the network service
            if [ "$renderer" = "NetworkManager" ]; then
                sudo systemctl restart NetworkManager
            else
                sudo systemctl restart systemd-networkd
            fi
        else
            echo -e "${GREEN}✅ Netplan configuration applied successfully${NC}"

            # For systemd-networkd, we might need to restart it explicitly
            if [ "$renderer" = "systemd-networkd" ]; then
                echo -e "${YELLOW}🔄 Ensuring systemd-networkd picks up the changes...${NC}"
                sudo systemctl restart systemd-networkd
            fi
        fi
    else
        echo -e "${RED}❌ Configuration syntax check failed${NC}"
        echo -e "${YELLOW}💡 Please check the generated file: $netplan_file${NC}"
        echo -e "${YELLOW}💡 You may need to run 'sudo netplan apply' manually after fixing${NC}"
    fi
}

# Function for systemd-networkd systems
add_permanent_routes_systemd_networkd() {
    local networkd_dir="/etc/systemd/network"
    local route_file="$networkd_dir/50-simulator-routes.network"

    # Create the networkd directory if it doesn't exist
    sudo mkdir -p "$networkd_dir"

    # Detect primary network interface
    local primary_interface=$(ip route show default | head -1 | awk '{print $5}')

    echo "# Static routes for Network Device Simulator" | sudo tee "$route_file" > /dev/null
    echo "# Generated on $(date)" | sudo tee -a "$route_file" > /dev/null
    echo "[Match]" | sudo tee -a "$route_file" > /dev/null
    echo "Name=$primary_interface" | sudo tee -a "$route_file" > /dev/null
    echo "" | sudo tee -a "$route_file" > /dev/null
    echo "[Network]" | sudo tee -a "$route_file" > /dev/null
`)

	for subnet := range subnets {
		script.WriteString(fmt.Sprintf(`    echo "Route=%s,$SIMULATOR_HOST" | sudo tee -a "$route_file" > /dev/null
`, subnet))
	}

	script.WriteString(`
    echo -e "${GREEN}✅ Created systemd-networkd configuration: $route_file${NC}"
    echo -e "${YELLOW}🔄 Restarting systemd-networkd...${NC}"

    sudo systemctl restart systemd-networkd
    echo -e "${GREEN}✅ systemd-networkd restarted${NC}"
}

# Function for traditional /etc/network/interfaces
add_permanent_routes_interfaces() {
    local interfaces_file="/etc/network/interfaces"
    local backup_file="/etc/network/interfaces.backup.$(date +%Y%m%d_%H%M%S)"

    # Backup original file
    sudo cp "$interfaces_file" "$backup_file"
    echo -e "${GREEN}✅ Backed up interfaces file to $backup_file${NC}"

    # Add routes to interfaces file
    echo "" | sudo tee -a "$interfaces_file" > /dev/null
    echo "# Static routes for Network Device Simulator - Added $(date)" | sudo tee -a "$interfaces_file" > /dev/null
`)

	for subnet := range subnets {
		script.WriteString(fmt.Sprintf(`    echo "up ip route add %s via $SIMULATOR_HOST" | sudo tee -a "$interfaces_file" > /dev/null
    echo "down ip route del %s via $SIMULATOR_HOST" | sudo tee -a "$interfaces_file" > /dev/null
`, subnet, subnet))
	}

	script.WriteString(`
    echo -e "${GREEN}✅ Added routes to $interfaces_file${NC}"
    echo -e "${YELLOW}💡 Routes will be active after next network restart or reboot${NC}"
}

# Function to add permanent routes on RHEL/CentOS/Fedora systems
add_permanent_routes_rhel() {
    echo -e "${BLUE}🎩 Detected RHEL/CentOS/Fedora system${NC}"

    # Check if NetworkManager is being used
    if command -v nmcli >/dev/null 2>&1 && systemctl is-active NetworkManager >/dev/null 2>&1; then
        echo -e "${YELLOW}📝 Using NetworkManager configuration${NC}"
        add_permanent_routes_networkmanager
    else
        echo -e "${YELLOW}📝 Using traditional network-scripts${NC}"
        add_permanent_routes_network_scripts
    fi
}

# Function for NetworkManager-based systems
add_permanent_routes_networkmanager() {
    # Get the active connection name
    local connection=$(nmcli -t -f NAME con show --active | head -1)

    if [ -z "$connection" ]; then
        echo -e "${RED}❌ No active NetworkManager connection found${NC}"
        return 1
    fi

    echo -e "${BLUE}📡 Adding routes to NetworkManager connection: $connection${NC}"
`)

	for subnet := range subnets {
		script.WriteString(fmt.Sprintf(`    if sudo nmcli con modify "$connection" +ipv4.routes "%s $SIMULATOR_HOST"; then
        echo -e "${GREEN}✅ Added route for %s${NC}"
    else
        echo -e "${RED}❌ Failed to add route for %s${NC}"
    fi
`, subnet, subnet, subnet))
	}

	script.WriteString(`
    echo -e "${YELLOW}🔄 Reactivating NetworkManager connection...${NC}"
    sudo nmcli con up "$connection"
    echo -e "${GREEN}✅ NetworkManager configuration applied${NC}"
}

# Function for traditional network-scripts
add_permanent_routes_network_scripts() {
    local route_file="/etc/sysconfig/network-scripts/route-$(ip route show default | head -1 | awk '{print $5}')"

    echo "# Static routes for Network Device Simulator" | sudo tee "$route_file" > /dev/null
    echo "# Generated on $(date)" | sudo tee -a "$route_file" > /dev/null
`)

	for subnet := range subnets {
		script.WriteString(fmt.Sprintf(`    echo "%s via $SIMULATOR_HOST" | sudo tee -a "$route_file" > /dev/null
`, subnet))
	}

	script.WriteString(`
    echo -e "${GREEN}✅ Created route file: $route_file${NC}"
    echo -e "${YELLOW}💡 Routes will be active after next network restart or reboot${NC}"
}

# Function to add permanent routes on openSUSE/SUSE systems
add_permanent_routes_suse() {
    echo -e "${BLUE}🦎 Detected openSUSE/SUSE system${NC}"

    local route_file="/etc/sysconfig/network/routes"
    local backup_file="/etc/sysconfig/network/routes.backup.$(date +%Y%m%d_%H%M%S)"

    # Backup original file if it exists
    if [ -f "$route_file" ]; then
        sudo cp "$route_file" "$backup_file"
        echo -e "${GREEN}✅ Backed up routes file to $backup_file${NC}"
    fi

    # Add routes
    echo "# Static routes for Network Device Simulator - Added $(date)" | sudo tee -a "$route_file" > /dev/null
`)

	for subnet := range subnets {
		script.WriteString(fmt.Sprintf(`    echo "%s $SIMULATOR_HOST - -" | sudo tee -a "$route_file" > /dev/null
`, subnet))
	}

	script.WriteString(`
    echo -e "${GREEN}✅ Added routes to $route_file${NC}"
    echo -e "${YELLOW}🔄 Restarting network service...${NC}"

    if sudo systemctl restart wicked; then
        echo -e "${GREEN}✅ Network service restarted${NC}"
    else
        echo -e "${YELLOW}⚠️  Network service restart failed, routes will be active after reboot${NC}"
    fi
}

# Function to show current routes
show_current_routes() {
    echo -e "${BLUE}📋 Current simulator routes:${NC}"
`)

	for subnet := range subnets {
		script.WriteString(fmt.Sprintf(`    if ip route show %s >/dev/null 2>&1; then
        echo -e "${GREEN}✅ %s: $(ip route show %s)${NC}"
    else
        echo -e "${RED}❌ %s: No route found${NC}"
    fi
`, subnet, subnet, subnet, subnet))
	}

	script.WriteString(`}

# Function to show removal instructions
show_removal_instructions() {
    echo ""
    echo -e "${BLUE}🗑️  Route Removal Instructions:${NC}"
    echo ""

    if [ "$PERMANENT" = true ]; then
        echo -e "${YELLOW}For permanent routes, you need to:${NC}"
        echo -e "${YELLOW}1. Remove the configuration files created by this script${NC}"
        echo -e "${YELLOW}2. Restart the network service${NC}"
        echo ""
        echo -e "${BLUE}Configuration files to remove:${NC}"
        case "$OS_TYPE" in
            "debian")
                echo "  - /etc/netplan/99-simulator-routes.yaml (if using netplan)"
                echo "  - /etc/systemd/network/50-simulator-routes.network (if using systemd-networkd)"
                echo "  - Lines in /etc/network/interfaces (if using traditional interfaces)"
                ;;
            "rhel")
                echo "  - NetworkManager connection routes (use nmcli con modify)"
                echo "  - /etc/sysconfig/network-scripts/route-* files"
                ;;
            "suse")
                echo "  - Lines in /etc/sysconfig/network/routes"
                ;;
        esac
        echo ""
    else
        echo -e "${YELLOW}For temporary routes, run these commands:${NC}"
`)

	for subnet := range subnets {
		script.WriteString(fmt.Sprintf(`        echo "  sudo ip route del %s"`, subnet))
		script.WriteString("\n")
	}

	script.WriteString(`    fi
}

# Function to verify persistent configuration
verify_persistent_configuration() {
    echo ""
    echo -e "${BLUE}🔍 Verifying persistent configuration...${NC}"

    local config_found=false

    # Check for netplan configuration
    if [ -f "/etc/netplan/99-simulator-routes.yaml" ]; then
        echo -e "${GREEN}✅ Found netplan configuration: /etc/netplan/99-simulator-routes.yaml${NC}"
        config_found=true
        echo -e "${YELLOW}📄 Configuration content:${NC}"
        sudo cat "/etc/netplan/99-simulator-routes.yaml" | head -20
        echo ""
    fi

    # Check for systemd-networkd configuration
    if [ -f "/etc/systemd/network/50-simulator-routes.network" ]; then
        echo -e "${GREEN}✅ Found systemd-networkd configuration: /etc/systemd/network/50-simulator-routes.network${NC}"
        config_found=true
    fi

    # Check for NetworkManager configuration
    if command -v nmcli >/dev/null 2>&1; then
        local connection=$(nmcli -t -f NAME con show --active | head -1)
        if [ -n "$connection" ]; then
            local routes=$(nmcli -g ipv4.routes con show "$connection" 2>/dev/null)
            if [ -n "$routes" ]; then
                echo -e "${GREEN}✅ Found NetworkManager routes in connection: $connection${NC}"
                config_found=true
            fi
        fi
    fi

    # Check for traditional interfaces file
    if grep -q "Network Device Simulator" /etc/network/interfaces 2>/dev/null; then
        echo -e "${GREEN}✅ Found routes in /etc/network/interfaces${NC}"
        config_found=true
    fi

    if [ "$config_found" = false ]; then
        echo -e "${RED}❌ No persistent configuration found!${NC}"
        echo -e "${YELLOW}💡 Routes may not persist after reboot${NC}"
        return 1
    fi

    return 0
}

# Main execution
echo -e "${BLUE}🚀 Network Device Simulator Route Configuration${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Check for additional flags (--temporary and --debug can be combined)
DEBUG=false
for arg in "$@"; do
    if [ "$arg" = "--debug" ]; then
        DEBUG=true
        echo -e "${YELLOW}🔧 Debug mode enabled${NC}"
        echo -e "${BLUE}System Information:${NC}"
        echo "  OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2)"
        echo "  Kernel: $(uname -r)"
        echo "  Netplan: $(which netplan 2>/dev/null || echo 'not found')"
        echo "  NetworkManager: $(systemctl is-active NetworkManager 2>/dev/null || echo 'inactive')"
        echo "  systemd-networkd: $(systemctl is-active systemd-networkd 2>/dev/null || echo 'inactive')"
        echo ""
    fi
done

if [ "$PERMANENT" = true ]; then
    echo -e "${BLUE}💾 Creating PERMANENT routes that will persist after reboot${NC}"
    echo -e "${YELLOW}📝 Note: To create temporary routes instead, use --temporary flag${NC}"
    echo ""
    add_permanent_routes

    # Verify the persistent configuration was created
    verify_persistent_configuration
else
    add_temporary_routes
fi

echo ""
show_current_routes

if [ "$PERMANENT" = true ]; then
    echo ""
    echo -e "${BLUE}💡 Testing persistence (for Ubuntu 24.04 Server):${NC}"
    echo -e "${YELLOW}1. Verify the configuration file exists:${NC}"
    echo "   ls -la /etc/netplan/99-simulator-routes.yaml"
    echo -e "${YELLOW}2. Test the configuration:${NC}"
    echo "   sudo netplan generate"
    echo "   sudo netplan apply"
    echo -e "${YELLOW}3. Verify routes are active:${NC}"
    echo "   ip route | grep $SIMULATOR_HOST"
    echo -e "${YELLOW}4. After reboot, check if routes persist:${NC}"
    echo "   ip route | grep $SIMULATOR_HOST"
fi

show_removal_instructions

echo ""
echo -e "${GREEN}🎉 Route configuration complete!${NC}"

if [ "$PERMANENT" = true ]; then
    echo -e "${GREEN}✅ Permanent routes are now configured and will persist across reboots${NC}"
    echo -e "${BLUE}💡 On Ubuntu 24.04, systemd-networkd should be enabled (usually is by default)${NC}"
    echo -e "${YELLOW}📝 To remove these routes later, see the removal instructions above${NC}"
else
    echo -e "${YELLOW}⚠️  Temporary routes are active only until next reboot${NC}"
    echo -e "${BLUE}💡 To make routes permanent, run without --temporary flag${NC}"
fi
`)

	return script.String()
}

// Helper functions for API responses
func sendSuccessResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: message,
	})
}

func sendDataResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "Success",
		Data:    data,
	})
}

func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(APIResponse{
		Success: false,
		Message: message,
	})
}

// Web UI handler - serves the index.html from web directory
func webUIHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "web/index.html")
}

// Setup REST API routes
func setupRoutes() *mux.Router {
	router := mux.NewRouter()

	// Web UI
	router.HandleFunc("/", webUIHandler).Methods("GET")
	router.HandleFunc("/ui", webUIHandler).Methods("GET")

	// Static web assets (CSS, JS)
	router.PathPrefix("/web/").Handler(http.StripPrefix("/web/", http.FileServer(http.Dir("web"))))

	// API routes
	api := router.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/devices", createDevicesHandler).Methods("POST")
	api.HandleFunc("/devices", listDevicesHandler).Methods("GET")
	api.HandleFunc("/devices/export", exportDevicesCSVHandler).Methods("GET")
	api.HandleFunc("/devices/routes", generateRouteScriptHandler).Methods("GET")
	api.HandleFunc("/devices/{id}", deleteDeviceHandler).Methods("DELETE")
	api.HandleFunc("/devices", deleteAllDevicesHandler).Methods("DELETE")
	api.HandleFunc("/resources", listResourcesHandler).Methods("GET")
	api.HandleFunc("/status", statusHandler).Methods("GET")

	// Static file for logo
	router.HandleFunc("/logo.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		http.ServeFile(w, r, "web/logo.png")
	}).Methods("GET", "HEAD")

	// Health check
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}).Methods("GET")

	return router
}