package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	mathrand "math/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SimulatorManager implementation
func NewSimulatorManager() *SimulatorManager {
	// Initialize random seed once at startup
	mathrand.Seed(time.Now().UnixNano())

	sm := &SimulatorManager{
		devices:          make(map[string]*DeviceSimulator),
		nextTunIndex:     0,
		resourcesCache:   make(map[string]*DeviceResources),
		tunInterfacePool: make(map[string]*TunInterface),
	}
	// Initialize atomic values
	sm.isPreAllocating.Store(false)
	sm.preAllocProgress.Store(0)
	sm.isCreatingDevices.Store(false)
	sm.deviceCreateProgress.Store(0)
	sm.deviceCreateTotal.Store(0)

	// Pre-generate shared SSH host key for all devices
	sm.generateSharedSSHKey()

	return sm
}

func (sm *SimulatorManager) getNextTunName() string {
	name := fmt.Sprintf("%s%d", TUN_DEVICE_PREFIX, sm.nextTunIndex)
	sm.nextTunIndex++
	return name
}

// generateSharedSSHKey generates a single RSA key to be shared by all devices
func (sm *SimulatorManager) generateSharedSSHKey() {
	log.Println("Generating shared SSH host key for all devices...")
	startTime := time.Now()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("WARNING: Failed to generate shared SSH key: %v", err)
		return
	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)

	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		log.Printf("WARNING: Failed to parse shared SSH key: %v", err)
		return
	}

	sm.sharedSSHSigner = signer
	elapsed := time.Since(startTime)
	log.Printf("Shared SSH host key generated in %v", elapsed)
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

	// Build indexes for loaded default resources
	sm.buildResourceIndexes(sm.deviceResources)

	log.Printf("Loaded %d SNMP and %d SSH resources with indexes", len(sm.deviceResources.SNMP), len(sm.deviceResources.SSH))
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

	// Build indexes for default resources too
	sm.buildResourceIndexes(defaultResources)

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

	// Build performance indexes for fast lookups
	sm.buildResourceIndexes(&resources)

	// Cache the loaded resources with indexes
	sm.resourcesCache[filename] = &resources

	return &resources, nil
}

// buildResourceIndexes builds performance optimization indexes for fast OID lookups
func (sm *SimulatorManager) buildResourceIndexes(resources *DeviceResources) {
	// Initialize lock-free sync.Map for O(1) OID lookups
	resources.oidIndex = &sync.Map{}

	// Initialize sorted OID slice for binary search in GetNext operations
	resources.sortedOIDs = make([]string, 0, len(resources.SNMP))

	// Initialize next OID map for pre-computed walk paths
	resources.oidNextMap = &sync.Map{}

	// Build indexes from the SNMP resources
	for i, resource := range resources.SNMP {
		// Skip dynamic OIDs that are handled specially
		if resource.OID == "1.3.6.1.2.1.1.5.0" || resource.OID == "1.3.6.1.2.1.1.6.0" {
			continue
		}

		// Lock-free hash map index: OID -> Response
		resources.oidIndex.Store(resource.OID, resource.Response)

		// Sorted OID list for binary search (resources are already sorted)
		resources.sortedOIDs = append(resources.sortedOIDs, resource.OID)

		// Pre-compute next OID mapping for walks (except for last OID)
		if i < len(resources.SNMP)-1 {
			resources.oidNextMap.Store(resource.OID, resources.SNMP[i+1].OID)
		}
	}
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

func (sm *SimulatorManager) GetStatus() ManagerStatus {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	totalDevices := len(sm.devices)
	runningDevices := 0
	for _, device := range sm.devices {
		if device.running {
			runningDevices++
		}
	}

	return ManagerStatus{
		IsPreAllocating:      sm.isPreAllocating.Load().(bool),
		PreAllocProgress:     sm.preAllocProgress.Load().(int),
		PreAllocTotal:        sm.tunPoolSize,
		IsCreatingDevices:    sm.isCreatingDevices.Load().(bool),
		DeviceCreateProgress: sm.deviceCreateProgress.Load().(int),
		DeviceCreateTotal:    sm.deviceCreateTotal.Load().(int),
		TotalDevices:         totalDevices,
		RunningDevices:       runningDevices,
	}
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
		// log.Printf("Error stopping device %s: %v", deviceID, err)
	}

	delete(sm.devices, deviceID)
	return nil
}

func (sm *SimulatorManager) DeleteAllDevices() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var errors []string
	var tunInterfaces []string

	// Collect all TUN interface names for bulk deletion
	for deviceID, device := range sm.devices {
		if err := device.Stop(); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", deviceID, err))
		}
		// Collect TUN interface names for bulk deletion
		if device.tunIface != nil && !device.tunIface.PreAllocated {
			tunInterfaces = append(tunInterfaces, device.tunIface.Name)
		}
	}

	// Bulk delete TUN interfaces for better performance
	if len(tunInterfaces) > 0 {
		if err := sm.bulkDeleteTunInterfaces(tunInterfaces); err != nil {
			errors = append(errors, fmt.Sprintf("bulk TUN deletion: %v", err))
		}
	}

	// Clear the devices map
	sm.devices = make(map[string]*DeviceSimulator)

	if len(errors) > 0 {
		return fmt.Errorf("errors deleting devices: %s", strings.Join(errors, ", "))
	}
	return nil
}
