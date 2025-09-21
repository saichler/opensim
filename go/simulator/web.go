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

// Web UI handler
func webUIHandler(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Device Simulator</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #2d5016 0%, #4a7c59 35%, #8fbc8f 70%, #b8dab8 100%);
            min-height: 100vh; padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header {
            background: rgba(245, 245, 220, 0.18); backdrop-filter: blur(10px);
            border-radius: 20px; padding: 30px; margin-bottom: 30px;
            border: 1px solid rgba(139, 188, 139, 0.25);
            box-shadow: 0 8px 32px rgba(45, 80, 22, 0.15);
        }
        .header h1 { color: #f5f5dc; font-size: 2.5em; font-weight: 300; margin-bottom: 10px; text-align: center; text-shadow: 0 2px 4px rgba(45, 80, 22, 0.3); }
        .header p { color: rgba(245, 245, 220, 0.9); text-align: center; font-size: 1.1em; }
        .controls, .status, .devices {
            background: rgba(250, 250, 235, 0.95); backdrop-filter: blur(10px);
            border-radius: 20px; padding: 30px; margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(45, 80, 22, 0.1);
            border: 1px solid rgba(139, 188, 139, 0.2);
        }
        .controls h2, .devices h2 { color: #2d5016; margin-bottom: 20px; font-weight: 600; }
        .form-row { display: flex; gap: 20px; align-items: end; }
        .form-row .form-group { flex: 1; margin-bottom: 0; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: #4a7c59; font-weight: 500; }
        input, select {
            width: 100%; padding: 12px 16px; border: 2px solid rgba(107, 142, 35, 0.15);
            border-radius: 12px; font-size: 16px; transition: all 0.3s ease; 
            background: rgba(250, 250, 235, 0.9); color: #2d5016;
        }
        input:focus, select:focus {
            outline: none; border-color: #8fbc8f;
            box-shadow: 0 0 0 3px rgba(139, 188, 139, 0.2);
        }
        .btn {
            background: linear-gradient(135deg, #2d5016 0%, #4a7c59 35%, #8fbc8f 70%, #b8dab8 100%);
            color: white; border: none; padding: 12px 24px; border-radius: 12px;
            cursor: pointer; font-size: 16px; font-weight: 600;
            transition: all 0.3s ease; min-width: 120px;
        }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(107, 142, 35, 0.35); }
        .btn-danger { background: linear-gradient(135deg, #cd853f 0%, #a0522d 50%, #8b4513 100%); }
        .btn-danger:hover { box-shadow: 0 8px 25px rgba(205, 133, 63, 0.35); }
        .btn-small { padding: 8px 16px; font-size: 14px; min-width: auto; }
        .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
        .status-card {
            background: linear-gradient(135deg, #8fbc8f 0%, #6b8e23 50%, #556b2f 100%);
            color: white; padding: 20px; border-radius: 16px; text-align: center;
            box-shadow: 0 4px 15px rgba(45, 80, 22, 0.15);
        }
        .status-card h3 { font-size: 2em; margin-bottom: 5px; font-weight: 300; }
        .status-card p { opacity: 0.9; }
        .device-table {
            width: 100%; background: rgba(250, 250, 235, 0.95); border-radius: 16px; overflow: hidden;
            box-shadow: 0 4px 15px rgba(45, 80, 22, 0.1); border: 2px solid rgba(139, 188, 139, 0.2);
        }
        .device-table table { width: 100%; border-collapse: collapse; }
        .device-table thead {
            background: linear-gradient(135deg, #2d5016 0%, #4a7c59 35%, #8fbc8f 70%, #b8dab8 100%);
            color: white;
        }
        .device-table thead th {
            padding: 16px 12px; text-align: left; font-weight: 600; font-size: 14px;
            border-bottom: 2px solid rgba(255, 255, 255, 0.2);
        }
        .device-table tbody tr {
            transition: all 0.2s ease; border-bottom: 1px solid rgba(139, 188, 139, 0.15);
        }
        .device-table tbody tr:hover { background: rgba(139, 188, 139, 0.08); }
        .device-table tbody tr:last-child { border-bottom: none; }
        .device-table tbody td {
            padding: 16px 12px; vertical-align: middle; font-size: 14px;
        }
        .device-id { font-weight: 600; color: #2d5016; font-family: Monaco, monospace; }
        .device-ip { font-family: Monaco, monospace; color: #2d5016; }
        .device-interface { font-family: Monaco, monospace; color: #6b8e23; }
        .device-type { font-weight: 500; color: #4a7c59; font-size: 13px; }
        .device-ports { font-family: Monaco, monospace; color: #6b8e23; font-size: 13px; }
        .device-status { padding: 6px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; display: inline-block; }
        .status-running { background: linear-gradient(45deg, #8fbc8f, #6b8e23); color: white; box-shadow: 0 2px 8px rgba(107, 142, 35, 0.3); }
        .status-stopped { background: linear-gradient(45deg, #cd853f, #a0522d); color: white; box-shadow: 0 2px 8px rgba(205, 133, 63, 0.3); }
        .device-actions { display: flex; gap: 8px; flex-wrap: wrap; }
        .device-actions .btn { padding: 6px 12px; font-size: 12px; min-width: auto; }
        .pagination-controls {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 20px;
            padding: 15px 0;
            border-top: 1px solid #eee;
        }
        .pagination-info {
            color: #666;
            font-size: 0.9em;
        }
        .pagination-buttons {
            display: flex;
            gap: 10px;
        }
        .pagination-buttons .btn {
            min-width: 80px;
        }
        .pagination-buttons .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .filter-controls {
            margin-bottom: 15px;
        }
        .filter-table {
            width: 100%;
            border-collapse: collapse;
        }
        .filter-row th {
            padding: 8px;
            background: #f8f9fa;
            border-bottom: 2px solid #dee2e6;
        }
        .filter-input {
            width: 100%;
            padding: 6px 8px;
            border: 1px solid #ced4da;
            border-radius: 4px;
            font-size: 0.85em;
            background: white;
        }
        .filter-input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 2px rgba(102, 126, 234, 0.1);
        }
        .alert {
            padding: 16px 20px; border-radius: 12px; margin-bottom: 20px;
            border-left: 4px solid; animation: slideIn 0.3s ease;
        }
        .alert-success { background: #d4edda; color: #155724; border-left-color: #28a745; }
        .alert-error { background: #f8d7da; color: #721c24; border-left-color: #dc3545; }
        .alert-warning { background: #fff3cd; color: #856404; border-left-color: #ffc107; }
        .loading {
            display: inline-block; width: 20px; height: 20px; border: 2px solid #f3f3f3;
            border-top: 2px solid #667eea; border-radius: 50%;
            animation: spin 1s linear infinite; margin-left: 8px;
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        @keyframes slideIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
        .empty-state { text-align: center; padding: 60px 20px; color: #666; }
        .empty-state h3 { font-size: 1.5em; margin-bottom: 10px; color: #999; }
        @media (max-width: 768px) {
            .form-row { flex-direction: column; }
            .status-grid { grid-template-columns: repeat(2, 1fr); }
            .device-table table { font-size: 12px; }
            .device-table thead th { padding: 12px 8px; }
            .device-table tbody td { padding: 12px 8px; }
            .device-actions { flex-direction: column; gap: 4px; }
            .device-actions .btn { font-size: 11px; padding: 4px 8px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div style="position: relative; display: flex; align-items: center; justify-content: center;">
                <img src="/cr.gif" alt="Logo" style="position: absolute; left: 0; width: 200px; height: 120px;">
                <h1 style="margin: 0; text-align: center;">Network Device Simulator</h1>
            </div>
            <p>Manage virtual network devices with TUN/TAP interfaces, SNMP, and SSH services</p>
        </div>
        <div id="alerts"></div>
        <div class="controls">
            <h2>Create New Devices</h2>
            <form id="createForm">
                <div class="form-row">
                    <div class="form-group">
                        <label for="startIp">Start IP Address</label>
                        <input type="text" id="startIp" placeholder="192.168.100.1" required>
                    </div>
                    <div class="form-group">
                        <label for="deviceCount">Number of Devices</label>
                        <input type="number" id="deviceCount" min="1" value="1" required>
                    </div>
                    <div class="form-group">
                        <label for="netmask">Netmask</label>
                        <select id="netmask">
                            <option value="24">24 (/24 - 255.255.255.0)</option>
                            <option value="16">16 (/16 - 255.255.0.0)</option>
                            <option value="8">8 (/8 - 255.0.0.0)</option>
                            <option value="32">32 (/32 - 255.255.255.255)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="resourceFile">Device Type</label>
                        <select id="resourceFile">
                            <option value="">Default (Auto-detect)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <button type="submit" class="btn">
                            Create Devices
                            <span id="createLoading" class="loading" style="display: none;"></span>
                        </button>
                    </div>
                </div>
            </form>
        </div>
        <div class="status">
            <div class="status-grid">
                <div class="status-card"><h3 id="totalDevices">0</h3><p>Total Devices</p></div>
                <div class="status-card"><h3 id="runningDevices">0</h3><p>Running</p></div>
                <div class="status-card"><h3 id="stoppedDevices">0</h3><p>Stopped</p></div>
                <div class="status-card"><h3 id="tunInterfaces">0</h3><p>TUN Interfaces</p></div>
            </div>
        </div>
        <div class="devices">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2>Devices</h2>
                <div style="display: flex; gap: 10px;">
                    <button id="exportBtn" class="btn btn-small">
                        📊 Export CSV <span id="exportLoading" class="loading" style="display: none;"></span>
                    </button>
                    <button id="routeScriptBtn" class="btn btn-small">
                        🛤️ Permanent Route Script <span id="routeScriptLoading" class="loading" style="display: none;"></span>
                    </button>
                    <button id="refreshBtn" class="btn btn-small">
                        🔄 Refresh <span id="refreshLoading" class="loading" style="display: none;"></span>
                    </button>
                    <button id="deleteAllBtn" class="btn btn-danger btn-small">
                        🗑️ Delete All <span id="deleteAllLoading" class="loading" style="display: none;"></span>
                    </button>
                </div>
            </div>
            <div id="deviceList" class="device-table">
                <div id="filterControls" class="filter-controls">
                    <table class="filter-table">
                        <tr class="filter-row">
                            <th><input type="text" id="filterDeviceId" placeholder="Filter ID..." class="filter-input"></th>
                            <th><input type="text" id="filterIp" placeholder="Filter IP..." class="filter-input"></th>
                            <th><input type="text" id="filterInterface" placeholder="Filter interface..." class="filter-input"></th>
                            <th><input type="text" id="filterDeviceType" placeholder="Filter type..." class="filter-input"></th>
                            <th><input type="text" id="filterPorts" placeholder="Filter ports..." class="filter-input"></th>
                            <th><select id="filterStatus" class="filter-input"><option value="">All</option><option value="running">Running</option><option value="stopped">Stopped</option></select></th>
                            <th><button id="clearFiltersBtn" class="btn btn-small">Clear</button></th>
                        </tr>
                    </table>
                </div>
                <div id="deviceTable"></div>
            </div>
            <div id="paginationControls" class="pagination-controls" style="display: none;">
                <div class="pagination-info">
                    <span id="pageInfo">Page 1 of 1 (0 devices)</span>
                </div>
                <div class="pagination-buttons">
                    <button id="prevPageBtn" class="btn btn-small" disabled>‹ Previous</button>
                    <button id="nextPageBtn" class="btn btn-small" disabled>Next ›</button>
                </div>
            </div>
        </div>
    </div>
    <script>
        const API_BASE = '/api/v1';
        let devices = [];
        let resources = [];
        let isStatusPolling = false;
        
        // Pagination state
        const DEVICES_PER_PAGE = 50;
        let currentPage = 1;
        
        // Filter state
        let filters = {
            id: '',
            ip: '',
            interface: '',
            deviceType: '',
            ports: '',
            status: ''
        };
        
        const elements = {
            createForm: document.getElementById('createForm'),
            deviceList: document.getElementById('deviceList'),
            alerts: document.getElementById('alerts'),
            exportBtn: document.getElementById('exportBtn'),
            routeScriptBtn: document.getElementById('routeScriptBtn'),
            refreshBtn: document.getElementById('refreshBtn'),
            deleteAllBtn: document.getElementById('deleteAllBtn'),
            totalDevices: document.getElementById('totalDevices'),
            runningDevices: document.getElementById('runningDevices'),
            stoppedDevices: document.getElementById('stoppedDevices'),
            tunInterfaces: document.getElementById('tunInterfaces'),
            paginationControls: document.getElementById('paginationControls'),
            pageInfo: document.getElementById('pageInfo'),
            prevPageBtn: document.getElementById('prevPageBtn'),
            nextPageBtn: document.getElementById('nextPageBtn'),
            filterControls: document.getElementById('filterControls'),
            deviceTable: document.getElementById('deviceTable'),
            filterDeviceId: document.getElementById('filterDeviceId'),
            filterIp: document.getElementById('filterIp'),
            filterInterface: document.getElementById('filterInterface'),
            filterDeviceType: document.getElementById('filterDeviceType'),
            filterPorts: document.getElementById('filterPorts'),
            filterStatus: document.getElementById('filterStatus'),
            clearFiltersBtn: document.getElementById('clearFiltersBtn')
        };

        function showAlert(message, type = 'success') {
            const alertDiv = document.createElement('div');
            alertDiv.className = 'alert alert-' + type;
            alertDiv.textContent = message;
            elements.alerts.appendChild(alertDiv);
            setTimeout(() => {
                if (alertDiv.parentNode) alertDiv.parentNode.removeChild(alertDiv);
            }, 5000);
        }

        function setLoading(elementId, loading) {
            const element = document.getElementById(elementId);
            if (element) element.style.display = loading ? 'inline-block' : 'none';
        }

        async function apiCall(endpoint, options = {}) {
            try {
                const response = await fetch(API_BASE + endpoint, {
                    headers: { 'Content-Type': 'application/json', ...options.headers },
                    ...options
                });
                if (!response.ok) throw new Error('HTTP ' + response.status + ': ' + response.statusText);
                return await response.json();
            } catch (error) {
                console.error('API Error:', error);
                throw error;
            }
        }

        async function loadDevices() {
            try {
                setLoading('refreshLoading', true);
                const response = await apiCall('/devices');
                devices = response.data || [];
                renderDevices();
                updateStats();
            } catch (error) {
                showAlert('Failed to load devices: ' + error.message, 'error');
            } finally {
                setLoading('refreshLoading', false);
            }
        }

        async function checkStatus() {
            try {
                const response = await apiCall('/status');
                const status = response.data;
                updateStatusDisplay(status);

                // Start/stop status polling based on activity
                if ((status.is_pre_allocating || status.is_creating_devices) && !isStatusPolling) {
                    startStatusPolling();
                } else if (!status.is_pre_allocating && !status.is_creating_devices && isStatusPolling) {
                    stopStatusPolling();
                    // Refresh devices list when operations complete
                    await loadDevices();
                }
            } catch (error) {
                console.error('Failed to check status:', error);
            }
        }

        function startStatusPolling() {
            if (isStatusPolling) return;
            isStatusPolling = true;
            const pollInterval = setInterval(async () => {
                if (!isStatusPolling) {
                    clearInterval(pollInterval);
                    return;
                }
                await checkStatus();
            }, 1000); // Poll every second during operations
        }

        function stopStatusPolling() {
            isStatusPolling = false;
        }

        function updateStatusDisplay(status) {
            if (status.is_pre_allocating) {
                const progress = status.pre_alloc_total > 0 ? Math.round((status.pre_alloc_progress / status.pre_alloc_total) * 100) : 0;
                showAlert('Pre-allocating TUN interfaces: ' + status.pre_alloc_progress + '/' + status.pre_alloc_total + ' (' + progress + '%)', 'warning');
            } else if (status.is_creating_devices) {
                const progress = status.device_create_total > 0 ? Math.round((status.device_create_progress / status.device_create_total) * 100) : 0;
                showAlert('Creating devices: ' + status.device_create_progress + '/' + status.device_create_total + ' (' + progress + '%)', 'warning');
            }
        }

        async function loadResources() {
            try {
                const response = await apiCall('/resources');
                resources = response.data || [];
                populateResourceSelect();
            } catch (error) {
                console.error('Failed to load resources: ' + error.message);
                showAlert('Failed to load device types: ' + error.message, 'warning');
            }
        }

        function populateResourceSelect() {
            const select = document.getElementById('resourceFile');
            // Clear existing options except default
            select.innerHTML = '<option value="">Default (Auto-detect)</option>';
            
            // Add resource file options
            resources.forEach(resource => {
                const option = document.createElement('option');
                option.value = resource.filename;
                option.textContent = resource.name + ' (' + resource.type + ')';
                select.appendChild(option);
            });
        }

        async function createDevices(startIp, deviceCount, netmask, resourceFile) {
            try {
                setLoading('createLoading', true);
                const requestData = {
                    start_ip: startIp,
                    device_count: parseInt(deviceCount),
                    netmask: netmask
                };

                // Add resource file if selected
                if (resourceFile) {
                    requestData.resource_file = resourceFile;
                }

                const response = await apiCall('/devices', {
                    method: 'POST',
                    body: JSON.stringify(requestData)
                });
                showAlert(response.message, 'success');

                // Start status polling to track progress
                startStatusPolling();

                await loadDevices();
            } catch (error) {
                showAlert('Failed to create devices: ' + error.message, 'error');
            } finally {
                setLoading('createLoading', false);
            }
        }

        async function deleteDevice(deviceId) {
            try {
                const response = await apiCall('/devices/' + deviceId, { method: 'DELETE' });
                showAlert(response.message, 'success');
                await loadDevices();
            } catch (error) {
                showAlert('Failed to delete device: ' + error.message, 'error');
            }
        }

        async function deleteAllDevices() {
            if (!confirm('Are you sure you want to delete all devices?')) return;
            try {
                setLoading('deleteAllLoading', true);
                const response = await apiCall('/devices', { method: 'DELETE' });
                showAlert(response.message, 'success');
                await loadDevices();
            } catch (error) {
                showAlert('Failed to delete all devices: ' + error.message, 'error');
            } finally {
                setLoading('deleteAllLoading', false);
            }
        }

        function exportDevicesCSV() {
            try {
                setLoading('exportLoading', true);
                
                if (devices.length === 0) {
                    showAlert('No devices to export', 'warning');
                    return;
                }

                // Direct download from API endpoint
                const link = document.createElement('a');
                link.href = API_BASE + '/devices/export';
                link.download = 'devices.csv';
                link.style.display = 'none';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                
                showAlert('Device list exported successfully', 'success');
            } catch (error) {
                showAlert('Failed to export devices: ' + error.message, 'error');
            } finally {
                setLoading('exportLoading', false);
            }
        }

        function downloadRouteScript() {
            try {
                setLoading('routeScriptLoading', true);
                
                if (devices.length === 0) {
                    showAlert('No devices to generate routes for', 'warning');
                    return;
                }

                // Direct download from API endpoint
                const link = document.createElement('a');
                link.href = API_BASE + '/devices/routes';
                link.download = 'add_simulator_routes.sh';
                link.style.display = 'none';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                
                showAlert('Permanent route script downloaded successfully! Routes will persist after reboot.', 'success');
            } catch (error) {
                showAlert('Failed to download route script: ' + error.message, 'error');
            } finally {
                setLoading('routeScriptLoading', false);
            }
        }

        // Filter helper functions
        function getFilteredDevices() {
            return devices.filter(device => {
                const matchesId = !filters.id || device.id.toLowerCase().includes(filters.id.toLowerCase());
                const matchesIp = !filters.ip || device.ip.includes(filters.ip);
                const matchesInterface = !filters.interface || (device.interface && device.interface.toLowerCase().includes(filters.interface.toLowerCase()));
                const matchesDeviceType = !filters.deviceType || (device.device_type && device.device_type.toLowerCase().includes(filters.deviceType.toLowerCase()));
                const matchesPorts = !filters.ports || 
                    (device.snmp_port.toString().includes(filters.ports) || 
                     device.ssh_port.toString().includes(filters.ports));
                const matchesStatus = !filters.status || 
                    (filters.status === 'running' && device.running) ||
                    (filters.status === 'stopped' && !device.running);
                
                return matchesId && matchesIp && matchesInterface && matchesDeviceType && matchesPorts && matchesStatus;
            });
        }

        function updateFiltersFromInputs() {
            filters.id = elements.filterDeviceId.value;
            filters.ip = elements.filterIp.value;
            filters.interface = elements.filterInterface.value;
            filters.deviceType = elements.filterDeviceType.value;
            filters.ports = elements.filterPorts.value;
            filters.status = elements.filterStatus.value;
        }

        function clearAllFilters() {
            filters.id = '';
            filters.ip = '';
            filters.interface = '';
            filters.deviceType = '';
            filters.ports = '';
            filters.status = '';
            
            elements.filterDeviceId.value = '';
            elements.filterIp.value = '';
            elements.filterInterface.value = '';
            elements.filterDeviceType.value = '';
            elements.filterPorts.value = '';
            elements.filterStatus.value = '';
            
            currentPage = 1;
            renderDevices();
        }

        function applyFilters() {
            updateFiltersFromInputs();
            currentPage = 1; // Reset to first page when filtering
            renderDevices();
        }

        // Pagination helper functions
        function getTotalPages() {
            const filteredDevices = getFilteredDevices();
            return Math.ceil(filteredDevices.length / DEVICES_PER_PAGE);
        }

        function getCurrentPageDevices() {
            const filteredDevices = getFilteredDevices();
            const startIndex = (currentPage - 1) * DEVICES_PER_PAGE;
            const endIndex = startIndex + DEVICES_PER_PAGE;
            return filteredDevices.slice(startIndex, endIndex);
        }

        function updatePaginationControls() {
            const filteredDevices = getFilteredDevices();
            const totalPages = getTotalPages();
            const hasDevices = filteredDevices.length > 0;
            
            // Show/hide pagination controls
            elements.paginationControls.style.display = hasDevices ? 'flex' : 'none';
            
            if (hasDevices) {
                // Update page info
                const showingCount = getCurrentPageDevices().length;
                const totalFiltered = filteredDevices.length;
                const totalDevices = devices.length;
                
                let pageInfoText = 'Page ' + currentPage + ' of ' + totalPages + ' (' + showingCount + ' of ' + totalFiltered + ' devices';
                if (totalFiltered !== totalDevices) {
                    pageInfoText += ' filtered from ' + totalDevices + ' total';
                }
                pageInfoText += ')';
                
                elements.pageInfo.textContent = pageInfoText;
                
                // Update button states
                elements.prevPageBtn.disabled = currentPage <= 1;
                elements.nextPageBtn.disabled = currentPage >= totalPages;
            }
        }

        function goToPage(page) {
            const totalPages = getTotalPages();
            if (page >= 1 && page <= totalPages) {
                currentPage = page;
                renderDevices();
                updatePaginationControls();
            }
        }

        function goToPreviousPage() {
            if (currentPage > 1) {
                goToPage(currentPage - 1);
            }
        }

        function goToNextPage() {
            const totalPages = getTotalPages();
            if (currentPage < totalPages) {
                goToPage(currentPage + 1);
            }
        }

        function renderDevices() {
            // Filter controls are always visible
            
            if (devices.length === 0) {
                elements.deviceTable.innerHTML = '<div class="empty-state"><div style="font-size: 4em; margin-bottom: 20px;">📱</div><h3>No Devices Found</h3><p>Create your first simulated network device to get started</p></div>';
                updatePaginationControls();
                return;
            }

            const filteredDevices = getFilteredDevices();
            if (filteredDevices.length === 0) {
                elements.deviceTable.innerHTML = '<div class="empty-state"><div style="font-size: 4em; margin-bottom: 20px;">🔍</div><h3>No Devices Match Filters</h3><p>Try adjusting your filter criteria or clear filters to see all devices</p></div>';
                updatePaginationControls();
                return;
            }
            
            const tableHTML = '<table>' +
                '<thead>' +
                '<tr>' +
                '<th>Device ID</th>' +
                '<th>IP Address</th>' +
                '<th>Interface</th>' +
                '<th>Device Type</th>' +
                '<th>Ports</th>' +
                '<th>Status</th>' +
                '<th>Actions</th>' +
                '</tr>' +
                '</thead>' +
                '<tbody>' +
                getCurrentPageDevices().map(device => 
                    '<tr>' +
                    '<td><span class="device-id">' + device.id + '</span></td>' +
                    '<td><span class="device-ip">' + device.ip + '</span></td>' +
                    '<td><span class="device-interface">' + (device.interface || 'N/A') + '</span></td>' +
                    '<td><span class="device-type">' + (device.device_type || 'Unknown') + '</span></td>' +
                    '<td><span class="device-ports">SNMP:' + device.snmp_port + ' SSH:' + device.ssh_port + '</span></td>' +
                    '<td><span class="device-status ' + (device.running ? 'status-running' : 'status-stopped') + '">' +
                    (device.running ? '● RUNNING' : '● STOPPED') + '</span></td>' +
                    '<td><div class="device-actions">' +
                    '<button class="btn btn-small" data-action="test-ssh" data-ip="' + device.ip + '" data-port="' + device.ssh_port + '">🔗 SSH</button>' +
                    '<button class="btn btn-small" data-action="ping" data-ip="' + device.ip + '">📡 Ping</button>' +
                    '<button class="btn btn-danger btn-small" data-action="delete" data-device-id="' + device.id + '">🗑️ Delete</button>' +
                    '</div></td>' +
                    '</tr>'
                ).join('') +
                '</tbody>' +
                '</table>';
            
            elements.deviceTable.innerHTML = tableHTML;
            
            // Add event listeners for device actions
            document.querySelectorAll('[data-action]').forEach(button => {
                button.addEventListener('click', (e) => {
                    const action = e.target.getAttribute('data-action');
                    const ip = e.target.getAttribute('data-ip');
                    const port = e.target.getAttribute('data-port');
                    const deviceId = e.target.getAttribute('data-device-id');
                    
                    switch(action) {
                        case 'test-ssh':
                            testConnection(ip, parseInt(port));
                            break;
                        case 'ping':
                            pingDevice(ip);
                            break;
                        case 'delete':
                            deleteDevice(deviceId);
                            break;
                    }
                });
            });
            
            
            // Update pagination controls
            updatePaginationControls();
        }

        function updateStats() {
            const total = devices.length;
            const running = devices.filter(d => d.running).length;
            const stopped = total - running;
            const interfaces = devices.filter(d => d.interface).length;
            elements.totalDevices.textContent = total;
            elements.runningDevices.textContent = running;
            elements.stoppedDevices.textContent = stopped;
            elements.tunInterfaces.textContent = interfaces;
        }

        function testConnection(ip, port) {
            showAlert('SSH test: ssh simadmin@' + ip + ' (password: simadmin)', 'warning');
        }

        function pingDevice(ip) {
            showAlert('Ping test for ' + ip + '. Check your terminal: ping ' + ip, 'warning');
        }

        elements.createForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const startIp = document.getElementById('startIp').value;
            const deviceCount = document.getElementById('deviceCount').value;
            const netmask = document.getElementById('netmask').value;
            const resourceFile = document.getElementById('resourceFile').value;
            if (!startIp || !deviceCount) {
                showAlert('Please fill in all required fields', 'error');
                return;
            }
            await createDevices(startIp, deviceCount, netmask, resourceFile);
            elements.createForm.reset();
            document.getElementById('deviceCount').value = '1';
            document.getElementById('netmask').value = '24';
            document.getElementById('resourceFile').value = '';
        });

        elements.exportBtn.addEventListener('click', exportDevicesCSV);
        elements.routeScriptBtn.addEventListener('click', downloadRouteScript);
        elements.refreshBtn.addEventListener('click', loadDevices);
        elements.deleteAllBtn.addEventListener('click', deleteAllDevices);
        
        // Pagination event listeners
        elements.prevPageBtn.addEventListener('click', goToPreviousPage);
        elements.nextPageBtn.addEventListener('click', goToNextPage);
        
        // Filter event listeners (attached once during initialization)
        elements.filterDeviceId.addEventListener('input', applyFilters);
        elements.filterIp.addEventListener('input', applyFilters);
        elements.filterInterface.addEventListener('input', applyFilters);
        elements.filterDeviceType.addEventListener('input', applyFilters);
        elements.filterPorts.addEventListener('input', applyFilters);
        elements.filterStatus.addEventListener('change', applyFilters);
        elements.clearFiltersBtn.addEventListener('click', clearAllFilters);
        
        setInterval(loadDevices, 30000);
        
        document.addEventListener('DOMContentLoaded', () => {
            loadDevices();
            loadResources();
            checkStatus(); // Initial status check
            showAlert('Network Device Simulator Web UI loaded successfully!', 'success');
        });
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// Setup REST API routes
func setupRoutes() *mux.Router {
	router := mux.NewRouter()

	// Web UI
	router.HandleFunc("/", webUIHandler).Methods("GET")
	router.HandleFunc("/ui", webUIHandler).Methods("GET")

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
	router.HandleFunc("/cr.gif", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/gif")
		http.ServeFile(w, r, "cr.gif")
	}).Methods("GET", "HEAD")

	// Health check
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}).Methods("GET")

	return router
}