package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// SNMP ASN.1 BER/DER type tags (shared constants defined here)
const (
	ASN1_SEQUENCE     = 0x30
	ASN1_INTEGER      = 0x02
	ASN1_OCTET_STRING = 0x04
	ASN1_NULL         = 0x05
	ASN1_OBJECT_ID    = 0x06
	ASN1_GET_REQUEST  = 0xA0
	ASN1_GET_NEXT     = 0xA1
	ASN1_GET_RESPONSE = 0xA2
	ASN1_SET_REQUEST  = 0xA3
	ASN1_OID          = 0x06
	SNMP_GET_RESPONSE = 0xa2
)

// SNMPv3 specific constants
const (
	SNMPV3_VERSION                = 3
	SNMPV3_MSG_FLAG_AUTH          = 0x01
	SNMPV3_MSG_FLAG_PRIV          = 0x02
	SNMPV3_MSG_FLAG_REPORT        = 0x04
	SNMPV3_SECURITY_MODEL_USM     = 3
	SNMPV3_AUTH_NONE              = 0
	SNMPV3_AUTH_MD5               = 1
	SNMPV3_AUTH_SHA1              = 2
	SNMPV3_PRIV_NONE              = 0
	SNMPV3_PRIV_DES               = 1
	SNMPV3_PRIV_AES128            = 2
)

// Configuration constants
const (
	DEFAULT_SNMP_PORT = 161
	DEFAULT_SSH_PORT  = 22
	USERNAME          = "simadmin"
	PASSWORD          = "simadmin"
	TUN_DEVICE_PREFIX = "sim"
)

// Global manager instance
var manager *SimulatorManager

// TUN interface management functions
func createTunInterface(name string, ip net.IP, netmask string) (*TunInterface, error) {
	// Open TUN device
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %v", err)
	}

	// Configure interface
	ifr := make([]byte, 40)
	copy(ifr, []byte(name))
	binary.LittleEndian.PutUint16(ifr[16:18], 0x0001) // IFF_TUN

	// TUNSETIFF ioctl
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x400454ca, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF ioctl failed: %v", errno)
	}

	tun := &TunInterface{
		Name: name,
		IP:   ip,
		fd:   fd,
	}

	// Configure the interface
	if err := tun.configure(netmask); err != nil {
		tun.destroy()
		return nil, err
	}

	return tun, nil
}

func (tun *TunInterface) configure(netmask string) error {
	// Configure IP address using ip command
	cmd := exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", tun.IP.String(), netmask), "dev", tun.Name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set IP address: %v", err)
	}

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", "dev", tun.Name, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring interface up: %v", err)
	}

	log.Printf("Created TUN interface %s with IP %s", tun.Name, tun.IP.String())
	return nil
}

func (tun *TunInterface) destroy() error {
	if tun.fd > 0 {
		return syscall.Close(tun.fd)
	}
	return nil
}

// compareOIDsLexicographically compares two OID strings lexicographically
// Returns -1 if oid1 < oid2, 0 if equal, 1 if oid1 > oid2
func compareOIDsLexicographically(oid1, oid2 string) int {
	parts1 := strings.Split(oid1, ".")
	parts2 := strings.Split(oid2, ".")
	
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}
	
	for i := 0; i < maxLen; i++ {
		var val1, val2 int
		
		if i < len(parts1) {
			val1, _ = strconv.Atoi(parts1[i])
		}
		if i < len(parts2) {
			val2, _ = strconv.Atoi(parts2[i])
		}
		
		if val1 < val2 {
			return -1
		} else if val1 > val2 {
			return 1
		}
	}
	
	if len(parts1) < len(parts2) {
		return -1
	} else if len(parts1) > len(parts2) {
		return 1
	}
	
	return 0
}

// SimulatorManager implementation
func NewSimulatorManager() *SimulatorManager {
	return &SimulatorManager{
		devices:        make(map[string]*DeviceSimulator),
		nextTunIndex:   0,
		resourcesCache: make(map[string]*DeviceResources),
	}
}

func (sm *SimulatorManager) getNextTunName() string {
	name := fmt.Sprintf("%s%d", TUN_DEVICE_PREFIX, sm.nextTunIndex)
	sm.nextTunIndex++
	return name
}

func (sm *SimulatorManager) LoadResources(filename string) error {
	// Check if file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		log.Printf("Resources file %s not found, creating default resources...", filename)
		return sm.createDefaultResources(filename)
	}

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&sm.deviceResources); err != nil {
		return err
	}

	log.Printf("Loaded %d SNMP and %d SSH resources", len(sm.deviceResources.SNMP), len(sm.deviceResources.SSH))
	return nil
}

func (sm *SimulatorManager) createDefaultResources(filename string) error {
	defaultResources := &DeviceResources{
		SNMP: []SNMPResource{
			{OID: "1.3.6.1.2.1.1.1.0", Response: "Cisco IOS Software, Router Version 15.1"},
			{OID: "1.3.6.1.2.1.1.2.0", Response: "1.3.6.1.4.1.9.1.1"},
			{OID: "1.3.6.1.2.1.1.3.0", Response: "123456789"},
			{OID: "1.3.6.1.2.1.1.4.0", Response: "Network Administrator"},
			{OID: "1.3.6.1.2.1.1.5.0", Response: "Router-Simulator"},
			{OID: "1.3.6.1.2.1.1.6.0", Response: "Simulation Lab"},
			{OID: "1.3.6.1.2.1.2.1.0", Response: "4"},
			{OID: "1.3.6.1.2.1.2.2.1.1.1", Response: "1"},
			{OID: "1.3.6.1.2.1.2.2.1.2.1", Response: "FastEthernet0/0"},
			{OID: "1.3.6.1.2.1.2.2.1.3.1", Response: "6"},
			{OID: "1.3.6.1.2.1.2.2.1.5.1", Response: "1000000000"},
			{OID: "1.3.6.1.2.1.2.2.1.7.1", Response: "1"},
			{OID: "1.3.6.1.2.1.2.2.1.8.1", Response: "1"},
			{OID: "1.3.6.1.2.1.2.2.1.10.1", Response: "1000000"},
			{OID: "1.3.6.1.2.1.2.2.1.16.1", Response: "500000"},
			{OID: "1.3.6.1.2.1.4.1.0", Response: "1"},
			{OID: "1.3.6.1.2.1.4.2.0", Response: "64"},
			{OID: "1.3.6.1.2.1.4.3.0", Response: "100"},
			{OID: "1.3.6.1.2.1.4.4.0", Response: "0"},
			{OID: "1.3.6.1.2.1.4.5.0", Response: "10"},
			{OID: "1.3.6.1.2.1.6.1.0", Response: "1"},
			{OID: "1.3.6.1.2.1.6.2.0", Response: "60"},
			{OID: "1.3.6.1.2.1.6.4.0", Response: "2"},
			{OID: "1.3.6.1.2.1.6.5.0", Response: "1000"},
			{OID: "1.3.6.1.2.1.6.6.0", Response: "500"},
			{OID: "1.3.6.1.2.1.6.8.0", Response: "200"},
			{OID: "1.3.6.1.2.1.6.9.0", Response: "100"},
			{OID: "1.3.6.1.2.1.7.1.0", Response: "1"},
			{OID: "1.3.6.1.2.1.7.2.0", Response: "1000"},
			{OID: "1.3.6.1.2.1.7.3.0", Response: "500"},
		},
		SSH: []SSHResource{
			{Command: "show version", Response: "Cisco IOS Software, Router Version 15.1\nDevice Simulator v1.0\nUptime: 1 day, 2 hours, 30 minutes"},
			{Command: "show interfaces", Response: "FastEthernet0/0 is up, line protocol is up\n  Hardware is FastEthernet, address is 0011.2233.4455\n  Internet address is 192.168.1.1/24\n  MTU 1500 bytes, BW 100000 Kbit/sec"},
			{Command: "show ip route", Response: "Codes: L - local, C - connected, S - static\nGateway of last resort is 192.168.1.254 to network 0.0.0.0\nC    192.168.1.0/24 is directly connected, FastEthernet0/0"},
			{Command: "show running-config", Response: "version 15.1\nhostname Router-Simulator\ninterface FastEthernet0/0\n ip address 192.168.1.1 255.255.255.0\n no shutdown"},
			{Command: "show processes cpu", Response: "CPU utilization for five seconds: 2%/0%; one minute: 3%; five minutes: 4%\nPID Runtime(ms)     Invoked      uSecs   5Sec   1Min   5Min TTY Process\n  1        1000       10000        100  0.5%   0.6%   0.7%   0 Init"},
			{Command: "show memory", Response: "Head    Total(b)     Used(b)     Free(b)   Lowest(b)  Largest(b)\nProcessor  67108864    33554432    33554432   30000000   30000000\n I/O     16777216     8388608     8388608    8000000    8000000"},
			{Command: "ping 8.8.8.8", Response: "Type escape sequence to abort.\nSending 5, 100-byte ICMP Echos to 8.8.8.8, timeout is 2 seconds:\n!!!!!\nSuccess rate is 100 percent (5/5), round-trip min/avg/max = 1/2/4 ms"},
			{Command: "traceroute 8.8.8.8", Response: "Type escape sequence to abort.\nTracing the route to 8.8.8.8\n  1 192.168.1.254 4 msec 2 msec 4 msec\n  2 * * *\n  3 8.8.8.8 20 msec 18 msec 20 msec"},
		},
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(defaultResources); err != nil {
		return err
	}

	sm.deviceResources = defaultResources
	log.Printf("Created default resources file %s with %d SNMP and %d SSH resources",
		filename, len(defaultResources.SNMP), len(defaultResources.SSH))

	return nil
}

// LoadSpecificResources loads a resource file from the resources directory
func (sm *SimulatorManager) LoadSpecificResources(filename string) (*DeviceResources, error) {
	// Check cache first
	if cached, exists := sm.resourcesCache[filename]; exists {
		return cached, nil
	}

	// Construct full path - look in resources directory
	resourcePath := fmt.Sprintf("resources/%s", filename)
	
	// Check if file exists
	if _, err := os.Stat(resourcePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("resource file %s not found in resources directory", filename)
	}

	file, err := os.Open(resourcePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open resource file %s: %v", resourcePath, err)
	}
	defer file.Close()

	var resources DeviceResources
	if err := json.NewDecoder(file).Decode(&resources); err != nil {
		return nil, fmt.Errorf("failed to parse resource file %s: %v", resourcePath, err)
	}

	// Sort SNMP resources by OID to ensure correct lexicographic ordering for SNMP walks
	sort.Slice(resources.SNMP, func(i, j int) bool {
		return compareOIDsLexicographically(resources.SNMP[i].OID, resources.SNMP[j].OID) < 0
	})
	log.Printf("Sorted %d SNMP OIDs in lexicographic order for %s", len(resources.SNMP), filename)

	// Cache the loaded resources
	sm.resourcesCache[filename] = &resources

	log.Printf("Loaded resource file %s: %d SNMP, %d SSH resources", 
		filename, len(resources.SNMP), len(resources.SSH))
	return &resources, nil
}

// ListAvailableResources lists all available resource files in the resources directory
func (sm *SimulatorManager) ListAvailableResources() []ResourceInfo {
	var resources []ResourceInfo
	
	resourceDir := "resources"
	entries, err := os.ReadDir(resourceDir)
	if err != nil {
		log.Printf("Failed to read resources directory: %v", err)
		return resources
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			// Try to determine device type from filename
			name := strings.TrimSuffix(entry.Name(), ".json")
			deviceType := "Unknown"
			
			if strings.Contains(strings.ToLower(name), "cisco") {
				deviceType = "Cisco Router/Switch"
			} else if strings.Contains(strings.ToLower(name), "asr9k") {
				deviceType = "Cisco ASR9K"
			} else if strings.Contains(strings.ToLower(name), "ios") {
				deviceType = "Cisco IOS"
			} else if strings.Contains(strings.ToLower(name), "juniper") {
				deviceType = "Juniper"
			} else if strings.Contains(strings.ToLower(name), "nexus") {
				deviceType = "Cisco Nexus"
			}

			resources = append(resources, ResourceInfo{
				Filename: entry.Name(),
				Name:     name,
				Type:     deviceType,
			})
		}
	}

	return resources
}

// getDeviceTypeFromResourceFile determines the device type from a resource filename
func getDeviceTypeFromResourceFile(filename string) string {
	if filename == "" {
		return "Default"
	}
	
	name := strings.TrimSuffix(filename, ".json")
	name = strings.ToLower(name)
	
	if strings.Contains(name, "asr9k") {
		return "Cisco ASR9K"
	} else if strings.Contains(name, "cisco") && strings.Contains(name, "ios") {
		return "Cisco IOS"
	} else if strings.Contains(name, "cisco") {
		return "Cisco Router/Switch"
	} else if strings.Contains(name, "juniper") {
		return "Juniper"
	} else if strings.Contains(name, "nexus") {
		return "Cisco Nexus"
	} else {
		// Capitalize first letter of filename
		if len(name) > 0 {
			return strings.ToUpper(name[:1]) + name[1:]
		}
		return "Unknown"
	}
}

func (sm *SimulatorManager) CreateDevices(startIP string, count int, netmask string, resourceFile string, v3Config *SNMPv3Config) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check for root privileges for TUN interface creation
	if os.Geteuid() != 0 {
		return fmt.Errorf("root privileges required to create TUN interfaces")
	}

	ip := net.ParseIP(startIP)
	if ip == nil {
		return fmt.Errorf("invalid start IP address: %s", startIP)
	}

	sm.currentIP = ip
	successCount := 0

	// Load the specified resource file if provided
	var resources *DeviceResources
	if resourceFile != "" {
		var err error
		resources, err = sm.LoadSpecificResources(resourceFile)
		if err != nil {
			return fmt.Errorf("failed to load resource file %s: %v", resourceFile, err)
		}
		log.Printf("Using resource file: %s", resourceFile)
	} else {
		// Use default resources
		resources = sm.deviceResources
		log.Printf("Using default resources")
	}

	for i := 0; i < count; i++ {
		deviceID := fmt.Sprintf("device-%s", sm.currentIP.String())

		// Check if device already exists
		if _, exists := sm.devices[deviceID]; exists {
			log.Printf("Device %s already exists, skipping", deviceID)
			sm.incrementIP()
			continue
		}

		// Create individual TUN interface for this device (make a copy of the IP)
		tunName := sm.getNextTunName()
		tunIP := make(net.IP, len(sm.currentIP))
		copy(tunIP, sm.currentIP)
		
		tunIface, err := createTunInterface(tunName, tunIP, netmask)
		if err != nil {
			log.Printf("Failed to create TUN interface for %s: %v", deviceID, err)
			sm.incrementIP()
			continue
		}

		// Create device with default ports (make another copy of the IP for the device)
		deviceIP := make(net.IP, len(sm.currentIP))
		copy(deviceIP, sm.currentIP)
		
		device := &DeviceSimulator{
			ID:           deviceID,
			IP:           deviceIP,
			SNMPPort:     DEFAULT_SNMP_PORT,
			SSHPort:      DEFAULT_SSH_PORT,
			tunIface:     tunIface,
			resources:    resources,
			resourceFile: resourceFile,
		}

		// Create servers with SNMPv3 configuration
		device.snmpServer = &SNMPServer{
			device:   device, 
			v3Config: v3Config,
		}
		device.sshServer = &SSHServer{device: device}

		// Start device services
		if err := device.Start(); err != nil {
			log.Printf("Failed to start device %s: %v", deviceID, err)
			device.Stop() // Clean up
			continue
		}

		sm.devices[deviceID] = device
		successCount++

		log.Printf("Created device: %s on IP %s (interface: %s)", deviceID, sm.currentIP.String(), tunName)
		sm.incrementIP()
	}

	log.Printf("Successfully created %d out of %d requested devices", successCount, count)
	return nil
}

func (sm *SimulatorManager) incrementIP() {
	ip := sm.currentIP.To4()
	if ip == nil {
		return // Only support IPv4 for now
	}

	// Create a copy to avoid modifying the original IP
	newIP := make(net.IP, len(ip))
	copy(newIP, ip)

	// Increment the last octet
	newIP[3]++
	if newIP[3] == 0 {
		newIP[2]++
		if newIP[2] == 0 {
			newIP[1]++
			if newIP[1] == 0 {
				newIP[0]++
			}
		}
	}
	sm.currentIP = newIP
}

func (sm *SimulatorManager) ListDevices() []DeviceInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var devices []DeviceInfo
	for _, device := range sm.devices {
		info := DeviceInfo{
			ID:         device.ID,
			IP:         device.IP.String(),
			SNMPPort:   device.SNMPPort,
			SSHPort:    device.SSHPort,
			Running:    device.running,
			DeviceType: getDeviceTypeFromResourceFile(device.resourceFile),
		}
		if device.tunIface != nil {
			info.Interface = device.tunIface.Name
		}
		devices = append(devices, info)
	}

	return devices
}

func (sm *SimulatorManager) DeleteDevice(deviceID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	device, exists := sm.devices[deviceID]
	if !exists {
		return fmt.Errorf("device %s not found", deviceID)
	}

	// Stop and cleanup device
	if err := device.Stop(); err != nil {
		log.Printf("Error stopping device %s: %v", deviceID, err)
	}

	delete(sm.devices, deviceID)
	log.Printf("Deleted device: %s", deviceID)
	return nil
}

func (sm *SimulatorManager) DeleteAllDevices() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var errors []string
	count := len(sm.devices)

	for deviceID, device := range sm.devices {
		if err := device.Stop(); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", deviceID, err))
		}
	}

	// Clear the devices map
	sm.devices = make(map[string]*DeviceSimulator)
	log.Printf("Deleted all %d devices", count)

	if len(errors) > 0 {
		return fmt.Errorf("errors deleting devices: %s", strings.Join(errors, ", "))
	}
	return nil
}

// DeviceSimulator implementation
func (d *DeviceSimulator) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.running {
		return nil
	}

	var errors []string

	// Start SNMP server
	if err := d.snmpServer.Start(); err != nil {
		errors = append(errors, fmt.Sprintf("SNMP: %v", err))
	}

	// Start SSH server
	if err := d.sshServer.Start(); err != nil {
		errors = append(errors, fmt.Sprintf("SSH: %v", err))
	}

	if len(errors) > 0 {
		// Stop any services that did start
		d.snmpServer.Stop()
		d.sshServer.Stop()
		return fmt.Errorf("failed to start services: %s", strings.Join(errors, ", "))
	}

	d.running = true
	log.Printf("Device %s started on %s (interface: %s, SNMP:%d, SSH:%d)",
		d.ID, d.IP.String(), d.tunIface.Name, d.SNMPPort, d.SSHPort)

	return nil
}

func (d *DeviceSimulator) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.running {
		return nil
	}

	var errors []string

	if d.snmpServer != nil {
		if err := d.snmpServer.Stop(); err != nil {
			errors = append(errors, fmt.Sprintf("SNMP: %v", err))
		}
	}

	if d.sshServer != nil {
		if err := d.sshServer.Stop(); err != nil {
			errors = append(errors, fmt.Sprintf("SSH: %v", err))
		}
	}

	// Note: We don't destroy shared TUN interface here as other devices may use it
	// The SimulatorManager handles TUN interface lifecycle

	d.running = false
	log.Printf("Device %s stopped", d.ID)

	if len(errors) > 0 {
		return fmt.Errorf("errors stopping services: %s", strings.Join(errors, ", "))
	}
	return nil
}

// parseAuthProtocol converts string to authentication protocol constant
func parseAuthProtocol(proto string) int {
	switch strings.ToLower(proto) {
	case "md5":
		return SNMPV3_AUTH_MD5
	case "sha1", "sha":
		return SNMPV3_AUTH_SHA1
	case "none", "":
		return SNMPV3_AUTH_NONE
	default:
		log.Printf("Unknown auth protocol '%s', using MD5", proto)
		return SNMPV3_AUTH_MD5
	}
}

// parsePrivProtocol converts string to privacy protocol constant
func parsePrivProtocol(proto string) int {
	switch strings.ToLower(proto) {
	case "des":
		return SNMPV3_PRIV_DES
	case "aes128", "aes":
		return SNMPV3_PRIV_AES128
	case "none", "":
		return SNMPV3_PRIV_NONE
	default:
		log.Printf("Unknown privacy protocol '%s', using none", proto)
		return SNMPV3_PRIV_NONE
	}
}

// getFirstDeviceKey returns the first device key from the map
func getFirstDeviceKey(devices map[string]*DeviceSimulator) string {
	for key := range devices {
		return key
	}
	return ""
}

func main() {
	// Define command-line flags
	var (
		autoStartIP      = flag.String("auto-start-ip", "", "Auto-create devices starting from this IP address (e.g., 192.168.100.1)")
		autoCount        = flag.Int("auto-count", 0, "Number of devices to auto-create (requires -auto-start-ip)")
		autoNetmask      = flag.String("auto-netmask", "24", "Netmask for auto-created devices (default: 24)")
		snmpv3EngineID   = flag.String("snmpv3-engine-id", "", "Enable SNMPv3 with specified engine ID (e.g., 800000090300AABBCCDD)")
		snmpv3AuthProto  = flag.String("snmpv3-auth", "md5", "SNMPv3 authentication protocol: none, md5, sha1 (default: md5)")
		snmpv3PrivProto  = flag.String("snmpv3-priv", "none", "SNMPv3 privacy protocol: none, des, aes128 (default: none)")
		port             = flag.String("port", "8080", "Server port (default: 8080)")
		showHelp         = flag.Bool("help", false, "Show this help message")
	)
	
	flag.Parse()
	
	// Show help if requested
	if *showHelp {
		fmt.Println("Network Device Simulator with TUN/TAP support")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Printf("  %s [options]\n", os.Args[0])
		fmt.Println()
		fmt.Println("Options:")
		flag.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Printf("  %s                                                    # Start server only\n", os.Args[0])
		fmt.Printf("  %s -auto-start-ip 192.168.100.1 -auto-count 5       # Auto-create 5 devices\n", os.Args[0])
		fmt.Printf("  %s -auto-start-ip 10.10.10.1 -auto-count 3 -port 9090  # Custom port\n", os.Args[0])
		fmt.Printf("  %s -auto-start-ip 192.168.100.1 -auto-count 2 \\      # SNMPv3 with MD5 auth\n", os.Args[0])
		fmt.Printf("    -snmpv3-engine-id 800000090300AABBCCDD -snmpv3-auth md5\n")
		fmt.Printf("  %s -auto-start-ip 192.168.100.1 -auto-count 1 \\      # SNMPv3 with privacy\n", os.Args[0])
		fmt.Printf("    -snmpv3-engine-id 800000090300AABBCCDD -snmpv3-auth sha1 -snmpv3-priv des\n")
		fmt.Println()
		return
	}

	log.Println("Network Device Simulator with TUN/TAP support starting...")

	// Check if running as root
	if os.Geteuid() != 0 {
		log.Println("WARNING: Not running as root. TUN/TAP interface creation will fail.")
		log.Println("Please run with: sudo ./simulator")
	}

	// Initialize manager
	manager = NewSimulatorManager()

	// Load default resources - look for asr9k first, then fallback to cisco_ios
	err := manager.LoadResources("resources/asr9k.json")
	if err != nil {
		log.Printf("Failed to load ASR9K resources: %v", err)
		log.Println("Trying to load default Cisco IOS resources...")
		err = manager.LoadResources("resources/cisco_ios.json")
		if err != nil {
			log.Fatalf("Failed to load any resources: %v", err)
		}
	}

	// Validate auto-creation parameters
	if *autoStartIP != "" && *autoCount <= 0 {
		log.Println("WARNING: -auto-start-ip provided but -auto-count is 0 or negative. No devices will be auto-created.")
	} else if *autoStartIP == "" && *autoCount > 0 {
		log.Println("WARNING: -auto-count provided but -auto-start-ip is empty. No devices will be auto-created.")
	}

	// Auto-create devices if requested
	if *autoStartIP != "" && *autoCount > 0 {
		log.Printf("Auto-creating %d devices starting from %s with netmask /%s", *autoCount, *autoStartIP, *autoNetmask)
		
		// Create SNMPv3 configuration if engine ID is provided
		var v3Config *SNMPv3Config
		if *snmpv3EngineID != "" {
			authProto := parseAuthProtocol(*snmpv3AuthProto)
			privProto := parsePrivProtocol(*snmpv3PrivProto)
			
			v3Config = &SNMPv3Config{
				Enabled:      true,
				EngineID:     *snmpv3EngineID,
				Username:     USERNAME, // Use same as SSH
				Password:     PASSWORD, // Use same as SSH
				AuthProtocol: authProto,
				PrivProtocol: privProto,
				PrivPassword: PASSWORD, // Use same password for privacy
			}
			log.Printf("SNMPv3 enabled with engine ID: %s, auth: %s, priv: %s", 
				*snmpv3EngineID, *snmpv3AuthProto, *snmpv3PrivProto)
		}
		
		err := manager.CreateDevices(*autoStartIP, *autoCount, *autoNetmask, "", v3Config)
		if err != nil {
			log.Printf("Failed to auto-create devices: %v", err)
		} else {
			log.Printf("Successfully auto-created %d devices", *autoCount)
		}
	}

	// Setup REST API
	router := setupRoutes()

	// Start API server
	apiPort := ":" + *port
	log.Printf("Network Device Simulator server starting on port %s", apiPort)
	log.Println()
	log.Println("🌐 Web UI:")
	log.Printf("  http://localhost%s/", apiPort)
	log.Printf("  http://localhost%s/ui", apiPort)
	log.Println()
	log.Println("📡 API Endpoints:")
	log.Println("  POST   /api/v1/devices           - Create devices")
	log.Println("  GET    /api/v1/devices           - List devices")
	log.Println("  GET    /api/v1/devices/export    - Export devices to CSV")
	log.Println("  GET    /api/v1/devices/routes    - Download route configuration script")
	log.Println("  DELETE /api/v1/devices/{id}      - Delete device")
	log.Println("  DELETE /api/v1/devices           - Delete all devices")
	log.Println("  GET    /health                   - Health check")
	log.Println()
	log.Println("💡 Example curl commands:")
	log.Printf(`  curl -X POST http://localhost%s/api/v1/devices -H "Content-Type: application/json" -d '{"start_ip":"192.168.100.1","device_count":3,"netmask":"24"}'`, apiPort)
	log.Println()
	log.Printf(`  curl http://localhost%s/api/v1/devices`, apiPort)
	log.Println()
	log.Printf(`  curl http://localhost%s/api/v1/devices/export -o devices.csv`, apiPort)
	log.Println()
	log.Printf(`  curl http://localhost%s/api/v1/devices/routes -o add_routes.sh`, apiPort)
	log.Println()
	log.Println()
	log.Println("🔐 SNMPv3 + SSH Examples:")
	log.Println("  Create devices with SNMPv3 support:")
	log.Printf("    sudo ./sim -auto-start-ip 192.168.100.1 -auto-count 2 \\")
	log.Println()
	log.Printf("      -snmpv3-engine-id 800000090300AABBCCDD -snmpv3-auth md5")
	log.Println()
	log.Println()
	log.Printf("  Or via REST API with SNMPv3:")
	log.Printf(`    curl -X POST http://localhost%s/api/v1/devices \`, apiPort)
	log.Println()
	log.Printf(`      -H "Content-Type: application/json" \`)
	log.Println()
	log.Printf(`      -d '{"start_ip":"192.168.100.1","device_count":1,"netmask":"24",`)
	log.Println()
	log.Printf(`           "snmpv3":{"enabled":true,"engine_id":"800000090300AABBCCDD",`)
	log.Println()
	log.Printf(`           "username":"simadmin","password":"simadmin","auth_protocol":1,"priv_protocol":0}}'`)
	log.Println()
	log.Println()
	log.Println("🔧 Connection Examples:")
	log.Println("  SSH (same credentials for all devices):")
	log.Println("    ssh simadmin@<device-ip>")
	log.Println("    Password: simadmin")
	log.Println()
	log.Println("  SNMP v2c (traditional):")
	log.Println("    snmpwalk -v2c -c public <device-ip> 1.3.6.1.2.1.1.1.0")
	log.Println()
	log.Println("  SNMPv3 (when enabled):")
	log.Println("    # MD5 auth, no privacy:")
	log.Println("    snmpwalk -v3 -u simadmin -A simadmin -a MD5 -l authNoPriv <device-ip> 1.3.6.1.2.1.1.1.0")
	log.Println()
	log.Println("    # MD5 auth + DES privacy:")
	log.Println("    snmpwalk -v3 -u simadmin -A simadmin -X simadmin -a MD5 -x DES -l authPriv <device-ip> 1.3.6.1.2.1.1.1.0")
	log.Println()
	log.Println("🔧 Additional Tips:")
	log.Println("  - Open the Web UI in your browser for easy management")
	log.Println("  - All devices use same credentials: simadmin/simadmin")
	log.Println("  - SNMPv2c community: public")
	log.Println("  - Check TUN interfaces: ip addr show | grep sim")
	log.Println("  - Test script available: ./test_snmpv3.sh")

	log.Fatal(http.ListenAndServe(apiPort, router))
}
