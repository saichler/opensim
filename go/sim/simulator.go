package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/crypto/ssh"
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

// Configuration constants
const (
	DEFAULT_SNMP_PORT = 2161  // Start from higher port to avoid conflicts
	DEFAULT_SSH_PORT  = 2222  // Start from higher port to avoid conflicts
	USERNAME          = "simadmin"
	PASSWORD          = "simadmin"
	TUN_DEVICE_PREFIX = "sim"
	MAX_GOROUTINES    = 50000  // Limit total goroutines
	MAX_CONNECTIONS   = 10     // Max SSH connections per device
	DEVICES_PER_TUN   = 256    // Devices per shared TUN interface
)

// Global manager instance
var manager *SimulatorManager

// Shared TUN interface management functions
func createSharedTunInterface(name string, network *net.IPNet) (*SharedTunInterface, error) {
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

	tun := &SharedTunInterface{
		Name:    name,
		Network: network,
		fd:      fd,
	}

	// Configure the interface
	if err := tun.configure(); err != nil {
		tun.destroy()
		return nil, err
	}

	return tun, nil
}

// Legacy function for compatibility
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

func (tun *SharedTunInterface) configure() error {
	// Configure IP address using ip command
	cmd := exec.Command("ip", "addr", "add", tun.Network.String(), "dev", tun.Name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set IP address: %v", err)
	}

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", "dev", tun.Name, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring interface up: %v", err)
	}

	log.Printf("Created shared TUN interface %s with network %s", tun.Name, tun.Network.String())
	return nil
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

func (tun *SharedTunInterface) destroy() error {
	tun.mu.Lock()
	defer tun.mu.Unlock()
	
	// Only destroy if no devices are using it
	if tun.deviceCount > 0 {
		return fmt.Errorf("cannot destroy TUN interface %s: still has %d devices", tun.Name, tun.deviceCount)
	}
	
	if tun.fd > 0 {
		return syscall.Close(tun.fd)
	}
	return nil
}

func (tun *SharedTunInterface) addDevice() {
	tun.mu.Lock()
	defer tun.mu.Unlock()
	tun.deviceCount++
}

func (tun *SharedTunInterface) removeDevice() {
	tun.mu.Lock()
	defer tun.mu.Unlock()
	if tun.deviceCount > 0 {
		tun.deviceCount--
	}
}

func (tun *TunInterface) destroy() error {
	if tun.fd > 0 {
		return syscall.Close(tun.fd)
	}
	return nil
}

// Resource pool implementation
func NewResourcePool() (*ResourcePool, error) {
	// Generate shared SSH key once
	sharedKey, err := generateSharedSSHKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate shared SSH key: %v", err)
	}
	
	return &ResourcePool{
		sharedTunIfaces: make(map[string]*SharedTunInterface),
		sharedSSHKey:    sharedKey,
		portAllocator: &PortAllocator{
			snmpPorts: make(map[int]bool),
			sshPorts:  make(map[int]bool),
			nextSNMP:  DEFAULT_SNMP_PORT,
			nextSSH:   DEFAULT_SSH_PORT,
		},
	}, nil
}

// SimulatorManager implementation
func NewSimulatorManager() *SimulatorManager {
	resourcePool, err := NewResourcePool()
	if err != nil {
		log.Fatalf("Failed to create resource pool: %v", err)
	}
	
	return &SimulatorManager{
		devices:       make(map[string]*DeviceSimulator),
		nextTunIndex:  0,
		resourcePool:  resourcePool,
		goroutinePool: make(chan struct{}, MAX_GOROUTINES),
		maxGoroutines: MAX_GOROUTINES,
	}
}

func (sm *SimulatorManager) getOrCreateSharedTunInterface(ip net.IP) (*SharedTunInterface, error) {
	sm.resourcePool.mu.Lock()
	defer sm.resourcePool.mu.Unlock()
	
	// Calculate which TUN interface this IP should use
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("only IPv4 addresses supported")
	}
	
	// Group devices by /24 subnet
	subnetBase := net.IPv4(ipv4[0], ipv4[1], ipv4[2], 0)
	tunName := fmt.Sprintf("%s_%d_%d_%d", TUN_DEVICE_PREFIX, ipv4[0], ipv4[1], ipv4[2])
	
	// Check if TUN interface already exists
	if existingTun, exists := sm.resourcePool.sharedTunIfaces[tunName]; exists {
		return existingTun, nil
	}
	
	// Create new shared TUN interface for this subnet
	network := &net.IPNet{
		IP:   subnetBase,
		Mask: net.CIDRMask(24, 32),
	}
	
	tunIface, err := createSharedTunInterface(tunName, network)
	if err != nil {
		return nil, err
	}
	
	sm.resourcePool.sharedTunIfaces[tunName] = tunIface
	return tunIface, nil
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

	// Set shared resources in resource pool
	sm.resourcePool.sharedResources = sm.deviceResources

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
	// Set shared resources in resource pool
	sm.resourcePool.sharedResources = defaultResources
	
	log.Printf("Created default resources file %s with %d SNMP and %d SSH resources",
		filename, len(defaultResources.SNMP), len(defaultResources.SSH))

	return nil
}

func (sm *SimulatorManager) CreateDevices(startIP string, count int, netmask string) error {
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

	for i := 0; i < count; i++ {
		deviceID := fmt.Sprintf("device-%s", sm.currentIP.String())

		// Check if device already exists
		if _, exists := sm.devices[deviceID]; exists {
			log.Printf("Device %s already exists, skipping", deviceID)
			sm.incrementIP()
			continue
		}

		// Get or create shared TUN interface
		sharedTunIface, err := sm.getOrCreateSharedTunInterface(sm.currentIP)
		if err != nil {
			log.Printf("Failed to get/create shared TUN interface for %s: %v", deviceID, err)
			sm.incrementIP()
			continue
		}

		// Allocate ports
		snmpPort := sm.resourcePool.portAllocator.allocateSNMPPort()
		sshPort := sm.resourcePool.portAllocator.allocateSSHPort()

		// Create device
		device := &DeviceSimulator{
			ID:              deviceID,
			IP:              sm.currentIP,
			SNMPPort:        snmpPort,
			SSHPort:         sshPort,
			sharedTunIface:  sharedTunIface,
			resources:       sm.resourcePool.sharedResources,
		}

		// Create servers with context and limits
		ctx, cancel := context.WithCancel(context.Background())
		device.snmpServer = &SNMPServer{
			device: device,
			ctx:    ctx,
			cancel: cancel,
		}
		device.sshServer = &SSHServer{
			device:      device,
			ctx:         ctx,
			cancel:      cancel,
			connLimiter: make(chan struct{}, MAX_CONNECTIONS),
			maxConns:    MAX_CONNECTIONS,
		}

		// Start device services
		if err := device.Start(); err != nil {
			log.Printf("Failed to start device %s: %v", deviceID, err)
			device.Stop() // Clean up
			continue
		}

		sharedTunIface.addDevice()
		sm.devices[deviceID] = device
		successCount++

		log.Printf("Created device: %s on IP %s (SNMP:%d, SSH:%d)", deviceID, sm.currentIP.String(), snmpPort, sshPort)
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

	// Increment the last octet
	ip[3]++
	if ip[3] == 0 {
		ip[2]++
		if ip[2] == 0 {
			ip[1]++
			if ip[1] == 0 {
				ip[0]++
			}
		}
	}
	sm.currentIP = ip
}

func (sm *SimulatorManager) ListDevices() []DeviceInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var devices []DeviceInfo
	for _, device := range sm.devices {
		info := DeviceInfo{
			ID:       device.ID,
			IP:       device.IP.String(),
			SNMPPort: device.SNMPPort,
			SSHPort:  device.SSHPort,
			Running:  device.running,
		}
		if device.sharedTunIface != nil {
			info.Interface = device.sharedTunIface.Name
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

	// Release ports
	sm.resourcePool.portAllocator.releaseSNMPPort(device.SNMPPort)
	sm.resourcePool.portAllocator.releaseSSHPort(device.SSHPort)

	// Remove device from shared TUN interface
	if device.sharedTunIface != nil {
		device.sharedTunIface.removeDevice()
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

// Port allocation functions
func (pa *PortAllocator) allocateSNMPPort() int {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	
	for {
		if !pa.snmpPorts[pa.nextSNMP] {
			port := pa.nextSNMP
			pa.snmpPorts[port] = true
			pa.nextSNMP++
			if pa.nextSNMP > 65535 {
				pa.nextSNMP = DEFAULT_SNMP_PORT
			}
			return port
		}
		pa.nextSNMP++
		if pa.nextSNMP > 65535 {
			pa.nextSNMP = DEFAULT_SNMP_PORT
		}
	}
}

func (pa *PortAllocator) allocateSSHPort() int {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	
	for {
		if !pa.sshPorts[pa.nextSSH] {
			port := pa.nextSSH
			pa.sshPorts[port] = true
			pa.nextSSH++
			if pa.nextSSH > 65535 {
				pa.nextSSH = DEFAULT_SSH_PORT
			}
			return port
		}
		pa.nextSSH++
		if pa.nextSSH > 65535 {
			pa.nextSSH = DEFAULT_SSH_PORT
		}
	}
}

func (pa *PortAllocator) releaseSNMPPort(port int) {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	delete(pa.snmpPorts, port)
}

func (pa *PortAllocator) releaseSSHPort(port int) {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	delete(pa.sshPorts, port)
}

// Shared SSH key generation
func generateSharedSSHKey() (ssh.Signer, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)
	
	return ssh.ParsePrivateKey(privateKeyBytes)
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
		d.ID, d.IP.String(), d.sharedTunIface.Name, d.SNMPPort, d.SSHPort)

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

func main() {
	log.Println("Network Device Simulator with TUN/TAP support starting...")

	// Check if running as root
	if os.Geteuid() != 0 {
		log.Println("WARNING: Not running as root. TUN/TAP interface creation will fail.")
		log.Println("Please run with: sudo ./simulator")
	}

	// Initialize manager
	manager = NewSimulatorManager()

	// Load resources
	err := manager.LoadResources("resources_asr9k.json")
	if err != nil {
		log.Fatalf("Failed to load resources: %v", err)
	}

	// Setup REST API
	router := setupRoutes()

	// Start API server
	apiPort := ":8080"
	log.Printf("Network Device Simulator server starting on port %s", apiPort)
	log.Println()
	log.Println("🌐 Web UI:")
	log.Printf("  http://localhost%s/", apiPort)
	log.Printf("  http://localhost%s/ui", apiPort)
	log.Println()
	log.Println("📡 API Endpoints:")
	log.Println("  POST   /api/v1/devices           - Create devices")
	log.Println("  GET    /api/v1/devices           - List devices")
	log.Println("  DELETE /api/v1/devices/{id}      - Delete device")
	log.Println("  DELETE /api/v1/devices           - Delete all devices")
	log.Println("  GET    /health                   - Health check")
	log.Println()
	log.Println("💡 Example curl commands:")
	log.Println(`  curl -X POST http://localhost:8080/api/v1/devices -H "Content-Type: application/json" -d '{"start_ip":"192.168.100.1","device_count":3,"netmask":"24"}'`)
	log.Println(`  curl http://localhost:8080/api/v1/devices`)
	log.Println()
	log.Println("🔧 Usage Tips:")
	log.Println("  - Open the Web UI in your browser for easy management")
	log.Println("  - SSH to devices: ssh simadmin@<device-ip> (password: simadmin)")
	log.Println("  - Test SNMP: snmpget -v2c -c public <device-ip> 1.3.6.1.2.1.1.1.0")
	log.Println("  - Check TUN interfaces: ip addr show | grep sim")

	log.Fatal(http.ListenAndServe(apiPort, router))
}
