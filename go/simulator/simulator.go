package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
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
	ASN1_GET_BULK     = 0xA5
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

// Global list of world cities loaded from CSV file
var worldCities []string

// loadWorldCities loads cities from worldcities.csv file
func loadWorldCities() error {
	file, err := os.Open("worldcities.csv")
	if err != nil {
		log.Printf("Failed to open worldcities.csv, using fallback cities: %v", err)
		// Fallback to a smaller set of cities if CSV file is not available
		worldCities = []string{
			"Tokyo, Japan",
			"New York, NY, USA", 
			"London, England, UK",
			"Paris, France",
			"Sydney, Australia",
			"Berlin, Germany",
			"Singapore, Singapore",
			"Mumbai, India",
			"São Paulo, Brazil",
			"Moscow, Russia",
		}
		return nil
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to read CSV: %v", err)
	}

	// Skip header row and extract city and country information
	// Use a map to ensure uniqueness and avoid duplicate city-country combinations
	uniqueLocations := make(map[string]bool)
	
	for i, record := range records {
		if i == 0 || len(record) < 5 {
			continue // Skip header or malformed rows
		}
		
		city := record[0]     // city name
		country := record[4]  // country name
		adminName := ""
		if len(record) > 7 {
			adminName = record[7] // admin_name (state/province)
		}
		
		// Create location string with more detail for disambiguation
		var location string
		if adminName != "" && adminName != city && adminName != country {
			// Include state/province for better distinction (e.g., "Boston, Massachusetts, United States")
			location = fmt.Sprintf("%s, %s, %s", city, adminName, country)
		} else {
			// Simple city, country format
			location = fmt.Sprintf("%s, %s", city, country)
		}
		
		// Only add if we haven't seen this exact location before
		if !uniqueLocations[location] {
			uniqueLocations[location] = true
		}
	}
	
	// Convert map keys to slice
	worldCities = make([]string, 0, len(uniqueLocations))
	for location := range uniqueLocations {
		worldCities = append(worldCities, location)
	}

	log.Printf("Loaded %d cities from worldcities.csv", len(worldCities))
	return nil
}


// getRandomCity returns a random city from the world cities list
func getRandomCity() string {
	// Ensure cities are loaded
	if len(worldCities) == 0 {
		log.Printf("Warning: worldCities not loaded, loading fallback cities")
		err := loadWorldCities()
		if err != nil {
			log.Printf("Error loading cities: %v", err)
		}
	}
	
	if len(worldCities) == 0 {
		return "Unknown Location"
	}
	
	return worldCities[mathrand.Intn(len(worldCities))]
}

// Global lists for generating random device names
var devicePrefixes = []string{
	"CORE", "EDGE", "ACCESS", "DIST", "AGG", "LEAF", "SPINE", "BORDER", "PE", "CE",
	"WAN", "LAN", "DMZ", "MGMT", "OOB", "BACKUP", "PRIMARY", "SECONDARY", "MAIN", "AUX",
	"HQ", "DC", "BR", "SITE", "CAMPUS", "BLDG", "FLOOR", "RACK", "ROW", "ZONE",
	"NORTH", "SOUTH", "EAST", "WEST", "CENTRAL", "UPPER", "LOWER", "FRONT", "REAR", "MID",
	"PROD", "DEV", "TEST", "STAGE", "LAB", "DEMO", "PILOT", "TRAIN", "TEMP", "MAINT",
}

var deviceTypes = []string{
	"RTR", "SWH", "FWL", "LB", "AP", "GW", "PX", "SRV", "HOST", "NODE",
	"ROUTER", "SWITCH", "FIREWALL", "PROXY", "GATEWAY", "BRIDGE", "HUB", "REPEATER", "MODEM", "ADAPTER",
}

var deviceLocations = []string{
	"NYC", "LAX", "CHI", "MIA", "SEA", "DEN", "ATL", "BOS", "PHX", "DAL",
	"LON", "PAR", "FRA", "AMS", "MAD", "ROM", "BER", "VIE", "ZUR", "MIL",
	"TOK", "SIN", "HKG", "SYD", "MEL", "BOM", "DEL", "BLR", "HYD", "CHE",
	"TOR", "VAN", "MTL", "CAL", "EDM", "WPG", "HAL", "OTT", "QUE", "SAS",
}

var animalNames = []string{
	"WOLF", "TIGER", "EAGLE", "HAWK", "LION", "BEAR", "SHARK", "FALCON", "LYNX", "PANTHER",
	"COBRA", "VIPER", "PYTHON", "MAMBA", "DRAGON", "PHOENIX", "GRIFFIN", "PEGASUS", "HYDRA", "KRAKEN",
	"RHINO", "BUFFALO", "BISON", "MOOSE", "STAG", "BUCK", "RAM", "BULL", "STALLION", "MUSTANG",
}

var mythNames = []string{
	"ATLAS", "TITAN", "HERCULES", "APOLLO", "ARES", "ZEUS", "THOR", "ODIN", "LOKI", "FREYA",
	"ARTEMIS", "ATHENA", "DIANA", "MARS", "VENUS", "NEPTUNE", "PLUTO", "MERCURY", "SATURN", "JUPITER",
	"ORION", "ANDROMEDA", "CASSIOPEIA", "VEGA", "ALTAIR", "SIRIUS", "RIGEL", "BETELGEUSE", "POLARIS", "ANTARES",
}

// getRandomDeviceName generates a random device name using various patterns
func getRandomDeviceName() string {
	
	// Choose a random pattern for the device name
	patterns := []func() string{
		// Pattern 1: PREFIX-TYPE-NUMBER (e.g., CORE-RTR-01)
		func() string {
			prefix := devicePrefixes[mathrand.Intn(len(devicePrefixes))]
			devType := deviceTypes[mathrand.Intn(len(deviceTypes))]
			number := mathrand.Intn(99) + 1
			return fmt.Sprintf("%s-%s-%02d", prefix, devType, number)
		},
		// Pattern 2: LOCATION-PREFIX-NUMBER (e.g., NYC-CORE-03)
		func() string {
			location := deviceLocations[mathrand.Intn(len(deviceLocations))]
			prefix := devicePrefixes[mathrand.Intn(len(devicePrefixes))]
			number := mathrand.Intn(99) + 1
			return fmt.Sprintf("%s-%s-%02d", location, prefix, number)
		},
		// Pattern 3: ANIMAL-NUMBER (e.g., WOLF-07)
		func() string {
			animal := animalNames[mathrand.Intn(len(animalNames))]
			number := mathrand.Intn(99) + 1
			return fmt.Sprintf("%s-%02d", animal, number)
		},
		// Pattern 4: MYTH-LOCATION (e.g., ATLAS-NYC)
		func() string {
			myth := mythNames[mathrand.Intn(len(mythNames))]
			location := deviceLocations[mathrand.Intn(len(deviceLocations))]
			return fmt.Sprintf("%s-%s", myth, location)
		},
		// Pattern 5: PREFIX-LOCATION-TYPE (e.g., CORE-NYC-SWH)
		func() string {
			prefix := devicePrefixes[mathrand.Intn(len(devicePrefixes))]
			location := deviceLocations[mathrand.Intn(len(deviceLocations))]
			devType := deviceTypes[mathrand.Intn(len(deviceTypes))]
			return fmt.Sprintf("%s-%s-%s", prefix, location, devType)
		},
		// Pattern 6: TYPE-ANIMAL-NUMBER (e.g., RTR-HAWK-12)
		func() string {
			devType := deviceTypes[mathrand.Intn(len(deviceTypes))]
			animal := animalNames[mathrand.Intn(len(animalNames))]
			number := mathrand.Intn(99) + 1
			return fmt.Sprintf("%s-%s-%02d", devType, animal, number)
		},
	}
	
	// Select a random pattern and generate the name
	pattern := patterns[mathrand.Intn(len(patterns))]
	name := pattern()
	// log.Printf("Generated device name: %s", name)
	return name
}

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

// bindToTunInterface opens an existing TUN interface for use by a device
func bindToTunInterface(name string, ip net.IP) (*TunInterface, error) {
	// Open TUN device
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %v", err)
	}

	// Bind to existing interface
	ifr := make([]byte, 40)
	copy(ifr, []byte(name))
	binary.LittleEndian.PutUint16(ifr[16:18], 0x0001) // IFF_TUN

	// TUNSETIFF ioctl to bind to existing interface
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x400454ca, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF ioctl failed: %v", errno)
	}

	return &TunInterface{
		Name: name,
		IP:   ip,
		fd:   fd,
	}, nil
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

	// log.Printf("Created TUN interface %s with IP %s", tun.Name, tun.IP.String())
	return nil
}

func (tun *TunInterface) destroy() error {
	if tun.fd > 0 {
		return syscall.Close(tun.fd)
	}
	return nil
}

// reconfigure updates the IP address of an existing TUN interface
func (tun *TunInterface) reconfigure(newIP net.IP, netmask string) error {
	// Remove old IP address
	cmd := exec.Command("ip", "addr", "del", fmt.Sprintf("%s/%s", tun.IP.String(), netmask), "dev", tun.Name)
	cmd.Run() // Ignore errors in case the IP wasn't set

	// Set new IP address
	cmd = exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", newIP.String(), netmask), "dev", tun.Name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set new IP address %s: %v", newIP.String(), err)
	}

	// Update the interface IP
	tun.IP = make(net.IP, len(newIP))
	copy(tun.IP, newIP)

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
	// Initialize random seed once at startup
	mathrand.Seed(time.Now().UnixNano())

	sm := &SimulatorManager{
		devices:        make(map[string]*DeviceSimulator),
		nextTunIndex:   0,
		resourcesCache: make(map[string]*DeviceResources),
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
	log.Printf("✅ Shared SSH host key generated in %v", elapsed)
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
	// log.Printf("Built indexes for %d SNMP OIDs in %s", len(resources.SNMP), filename)

	// Cache the loaded resources with indexes
	sm.resourcesCache[filename] = &resources

	// log.Printf("Loaded resource file %s: %d SNMP, %d SSH resources", 
	//	filename, len(resources.SNMP), len(resources.SSH))
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

	// Note: sortedOIDs should already be in lexicographic order since
	// resources.SNMP was sorted before calling this function
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

// PreAllocateTunInterfaces creates a pool of TUN interfaces in parallel for faster device creation
func (sm *SimulatorManager) PreAllocateTunInterfaces(poolSize int, maxWorkers int, startIP net.IP, netmask string) error {
	if poolSize <= 0 {
		return nil // No pre-allocation requested
	}

	// Limit maximum workers to prevent resource exhaustion
	if maxWorkers > 500 {
		maxWorkers = 500
		log.Printf("WARNING: Limiting workers to 500 to prevent resource exhaustion")
	}

	// Set pre-allocation status
	sm.isPreAllocating.Store(true)
	sm.preAllocProgress.Store(0)
	defer sm.isPreAllocating.Store(false)

	log.Printf("🚀 PERFORMANCE TEST: Pre-allocating %d TUN interfaces with %d workers...", poolSize, maxWorkers)
	log.Printf("📊 Test Parameters:")
	log.Printf("   - Pool Size: %d interfaces", poolSize)
	log.Printf("   - Workers: %d parallel workers", maxWorkers)
	log.Printf("   - Start IP: %s/%s", startIP.String(), netmask)
	log.Printf("   - Test Started: %s", time.Now().Format("2006-01-02 15:04:05.000"))
	log.Println()

	startTime := time.Now()
	log.Printf("⏱️  PRE-ALLOCATION START TIME: %v", startTime.Format("15:04:05.000"))
	log.Printf("⏱️  START TIMESTAMP (nanoseconds): %d", startTime.UnixNano())

	// Store pool size for device creation to know pre-allocation was done
	sm.tunPoolSize = poolSize
	sm.maxWorkers = maxWorkers

	// Worker pool for parallel interface creation
	sem := make(chan struct{}, maxWorkers) // Limit concurrent workers
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errors []error

	// Current IP for allocation (make a copy to avoid modifying the manager's IP)
	currentIP := make(net.IP, len(startIP))
	copy(currentIP, startIP)

	for i := 0; i < poolSize; i++ {
		// Create a unique IP for this interface
		interfaceIP := make(net.IP, len(currentIP))
		copy(interfaceIP, currentIP)

		wg.Add(1)
		go func(interfaceIndex int, ip net.IP) {
			defer wg.Done()

			// Acquire worker slot
			sem <- struct{}{}
			defer func() { <-sem }()

			// Generate unique interface name using the current nextTunIndex offset
			tunName := fmt.Sprintf("%s%d", TUN_DEVICE_PREFIX, sm.nextTunIndex+interfaceIndex)

			// Create TUN interface
			tunIface, err := createTunInterface(tunName, ip, netmask)
			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("failed to create interface %s: %v", tunName, err))
				mu.Unlock()
				return
			}

			// Mark as pre-allocated
			tunIface.PreAllocated = true

			// Store interface in the pool indexed by IP
			sm.tunPoolMutex.Lock()
			sm.tunInterfacePool[ip.String()] = tunIface
			sm.tunPoolMutex.Unlock()

			// Update progress counter
			current := sm.preAllocProgress.Load().(int)
			sm.preAllocProgress.Store(current + 1)

			// Log progress every 50 interfaces or for milestones
			newCurrent := current + 1
			if newCurrent%50 == 0 || newCurrent == 100 || newCurrent == 200 || newCurrent == 250 {
				elapsed := time.Since(startTime)
				rate := float64(newCurrent) / elapsed.Seconds()
				log.Printf("📈 Progress: %d/%d interfaces created (%.1f interfaces/sec, %v elapsed)",
					newCurrent, poolSize, rate, elapsed.Round(time.Millisecond))
			}

		}(i, interfaceIP)

		// Increment IP for next interface
		sm.incrementIPAddress(currentIP)
	}

	// Wait for all workers to complete with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All workers completed successfully
	case <-time.After(5 * time.Minute):
		log.Printf("WARNING: Pre-allocation timed out after 5 minutes")
		return fmt.Errorf("pre-allocation timed out")
	}

	elapsed := time.Since(startTime)
	created := sm.preAllocProgress.Load().(int)
	endTime := time.Now()

	log.Printf("⏱️  PRE-ALLOCATION END TIME: %v", endTime.Format("15:04:05.000"))
	log.Printf("⏱️  END TIMESTAMP (nanoseconds): %d", endTime.UnixNano())
	log.Println()

	log.Printf("🎯 PERFORMANCE RESULTS:")
	log.Printf("   ✅ Total interfaces created: %d/%d", created, poolSize)
	log.Printf("   ⏱️  Total time: %v", elapsed)
	log.Printf("   ⏱️  Total time (milliseconds): %.3f ms", float64(elapsed.Nanoseconds())/1e6)
	log.Printf("   ⏱️  Total time (nanoseconds): %d ns", elapsed.Nanoseconds())
	log.Printf("   📊 Average time per interface: %.3f ms", float64(elapsed.Nanoseconds())/float64(created*1e6))
	log.Printf("   📊 Average time per interface: %.0f ns", float64(elapsed.Nanoseconds())/float64(created))
	log.Printf("   🚀 Interfaces per second: %.2f", float64(created)/elapsed.Seconds())
	log.Printf("   👥 Workers used: %d", maxWorkers)
	log.Printf("   💾 Memory efficiency: ~%.1f KB per interface", float64(created*4)/1024.0) // Rough estimate

	if len(errors) > 0 {
		log.Printf("   ❌ Errors encountered: %d", len(errors))
		log.Printf("   📈 Success rate: %.1f%%", float64(created)/float64(poolSize)*100.0)
		log.Println()
		log.Printf("First few errors for debugging:")
		for i, err := range errors {
			if i >= 5 { // Limit error output
				log.Printf("... and %d more errors", len(errors)-5)
				break
			}
			log.Printf("   Error %d: %v", i+1, err)
		}
	} else {
		log.Printf("   ✅ Success rate: 100%%")
	}

	log.Println()
	log.Printf("🔍 System Impact:")
	log.Printf("   - Use 'ip link show | grep sim' to verify interfaces")
	log.Printf("   - Use 'ip addr show | grep sim -A1' to see IP assignments")
	log.Printf("   - Memory usage: Use 'free -h' to check system memory")

	// Update manager's nextTunIndex to continue after pre-allocated interfaces
	sm.nextTunIndex += poolSize

	// Update the manager's currentIP to continue after pre-allocated interfaces
	// so that device creation uses the correct starting IP
	sm.currentIP = make(net.IP, len(currentIP))
	copy(sm.currentIP, currentIP)

	return nil
}


// incrementIPAddress increments an IP address in-place with same logic as incrementIP()
func (sm *SimulatorManager) incrementIPAddress(ip net.IP) {
	ip4 := ip.To4()
	if ip4 == nil {
		return // Only support IPv4
	}

	// Increment the last octet
	ip4[3]++

	// Handle overflow or reaching 255 (move to next subnet)
	if ip4[3] == 0 || ip4[3] == 255 {
		ip4[2]++
		ip4[3] = 1 // Start from .1 in the new subnet
		if ip4[2] == 0 {
			ip4[1]++
			ip4[3] = 1 // Start from .1 in the new subnet
			if ip4[1] == 0 {
				ip4[0]++
				ip4[3] = 1 // Start from .1 in the new subnet
			}
		}
	}
}

func (sm *SimulatorManager) CreateDevices(startIP string, count int, netmask string, resourceFile string, v3Config *SNMPv3Config) error {
	return sm.CreateDevicesWithOptions(startIP, count, netmask, resourceFile, v3Config, true, 0)
}

// CreateDevicesWithOptions creates devices with optional pre-allocation control
func (sm *SimulatorManager) CreateDevicesWithOptions(startIP string, count int, netmask string, resourceFile string, v3Config *SNMPv3Config, preAllocate bool, maxWorkers int) error {
	// Set device creation status
	sm.isCreatingDevices.Store(true)
	sm.deviceCreateProgress.Store(0)
	sm.deviceCreateTotal.Store(count)
	defer sm.isCreatingDevices.Store(false)

	// Automatically pre-allocate TUN interfaces if creating many devices
	// Pre-allocate by default for 10+ devices unless explicitly disabled
	shouldPreAllocate := preAllocate && count >= 10

	if shouldPreAllocate {
		ip := net.ParseIP(startIP)
		if ip != nil {
			// Use provided maxWorkers or determine optimal count based on device count
			if maxWorkers == 0 {
				if count >= 1000 {
					maxWorkers = 200
				} else if count >= 500 {
					maxWorkers = 150
				} else {
					maxWorkers = 100
				}
			}

			log.Printf("Pre-allocating %d TUN interfaces with %d workers for faster device creation...", count, maxWorkers)
			err := sm.PreAllocateTunInterfaces(count, maxWorkers, ip, netmask)
			if err != nil {
				log.Printf("WARNING: Pre-allocation failed: %v. Falling back to on-demand creation.", err)
				// Continue with device creation even if pre-allocation fails
			}
		}
	}

	log.Printf("🚀 DEVICE STARTUP TEST: Creating %d devices starting from %s/%s", count, startIP, netmask)
	log.Printf("📊 Device Creation Parameters:")
	log.Printf("   - Device Count: %d", count)
	log.Printf("   - Start IP: %s/%s", startIP, netmask)
	log.Printf("   - Resource File: %s", resourceFile)
	log.Printf("   - SNMPv3 Enabled: %t", v3Config != nil && v3Config.Enabled)
	log.Printf("   - Test Started: %s", time.Now().Format("2006-01-02 15:04:05.000"))
	log.Println()

	deviceStartTime := time.Now()
	log.Printf("⏱️  DEVICE CREATION START TIME: %v", deviceStartTime.Format("15:04:05.000"))
	log.Printf("⏱️  DEVICE START TIMESTAMP (nanoseconds): %d", deviceStartTime.UnixNano())

	// Check for root privileges for TUN interface creation
	if os.Geteuid() != 0 {
		return fmt.Errorf("root privileges required to create TUN interfaces")
	}

	ip := net.ParseIP(startIP)
	if ip == nil {
		return fmt.Errorf("invalid start IP address: %s", startIP)
	}

	// Initialize with a write lock, then release it for the loop
	sm.mu.Lock()
	sm.currentIP = ip
	sm.mu.Unlock()

	successCount := 0

	// Load the specified resource file if provided
	var resources *DeviceResources
	if resourceFile != "" {
		var err error
		resources, err = sm.LoadSpecificResources(resourceFile)
		if err != nil {
			return fmt.Errorf("failed to load resource file %s: %v", resourceFile, err)
		}
			// log.Printf("Using resource file: %s", resourceFile)
	} else {
		// Use default resources
		resources = sm.deviceResources
		// log.Printf("Using default resources")
	}

	if sm.tunPoolSize > 0 {
		// Pre-allocation was done - create devices in parallel
		sm.createDevicesParallel(count, netmask, resourceFile, resources, v3Config, &successCount)
	} else {
		// No pre-allocation - create devices sequentially (original logic)
		for i := 0; i < count; i++ {
		// Get current IP with a read lock
		sm.mu.RLock()
		currentIP := make(net.IP, len(sm.currentIP))
		copy(currentIP, sm.currentIP)
		deviceID := fmt.Sprintf("device-%s", currentIP.String())

		// Check if device already exists
		_, exists := sm.devices[deviceID]
		sm.mu.RUnlock()

		if exists {
			// log.Printf("Device %s already exists, skipping", deviceID)
			sm.mu.Lock()
			sm.incrementIP()
			sm.mu.Unlock()
			continue
		}

		// Get or create TUN interface
		var tunIface *TunInterface
		var err error

		// Check if we have a pre-allocated interface for this IP
		sm.tunPoolMutex.RLock()
		preAllocated, exists := sm.tunInterfacePool[currentIP.String()]
		sm.tunPoolMutex.RUnlock()

		if exists && preAllocated != nil {
			// Use pre-allocated interface - it already has IP configured
			tunIface = preAllocated
			// log.Printf("Reusing pre-allocated interface %s for IP %s", tunIface.Name, currentIP.String())
		} else {
			// No pre-allocation or not found, create TUN interface on-demand
			sm.mu.Lock()
			tunName := sm.getNextTunName()
			sm.mu.Unlock()

			tunIP := make(net.IP, len(currentIP))
			copy(tunIP, currentIP)

			tunIface, err = createTunInterface(tunName, tunIP, netmask)
			if err != nil {
				// log.Printf("Failed to create TUN interface for %s: %v", deviceID, err)
				sm.mu.Lock()
				sm.incrementIP()
				sm.mu.Unlock()
				continue
			}
		}

		// Create device with default ports (use the copied IP)
		deviceIP := make(net.IP, len(currentIP))
		copy(deviceIP, currentIP)
		
		sysLocationValue := getRandomCity()
		sysNameValue := getRandomDeviceName()

		device := &DeviceSimulator{
			ID:           deviceID,
			IP:           deviceIP,
			SNMPPort:     DEFAULT_SNMP_PORT,
			SSHPort:      DEFAULT_SSH_PORT,
			tunIface:     tunIface,
			resources:    resources,
			resourceFile: resourceFile,
			sysLocation:  sysLocationValue,
			sysName:      sysNameValue,
		}

		// Cache the dynamic values using atomic for lock-free access
		device.cachedSysName.Store(sysNameValue)
		device.cachedSysLocation.Store(sysLocationValue)

		// Create servers with SNMPv3 configuration
		device.snmpServer = &SNMPServer{
			device:   device, 
			v3Config: v3Config,
		}
		device.sshServer = &SSHServer{device: device, signer: sm.sharedSSHSigner}

		// Start device services
		if err := device.Start(); err != nil {
			// log.Printf("Failed to start device %s: %v", deviceID, err)
			device.Stop() // Clean up
			sm.mu.Lock()
			sm.incrementIP()
			sm.mu.Unlock()
			continue
		}

		// Add device to map with a write lock
		sm.mu.Lock()
		sm.devices[deviceID] = device
		sm.incrementIP()
		sm.mu.Unlock()

		successCount++

		// Update progress counter
		sm.deviceCreateProgress.Store(successCount)

		// log.Printf("Created device: %s on IP %s (interface: %s)", deviceID, currentIP.String(), tunName)
	}

	}

	deviceElapsed := time.Since(deviceStartTime)
	deviceEndTime := time.Now()

	log.Printf("⏱️  DEVICE CREATION END TIME: %v", deviceEndTime.Format("15:04:05.000"))
	log.Printf("⏱️  DEVICE END TIMESTAMP (nanoseconds): %d", deviceEndTime.UnixNano())
	log.Println()

	log.Printf("🎯 DEVICE CREATION RESULTS:")
	log.Printf("   ✅ Total devices created: %d/%d", successCount, count)
	log.Printf("   ⏱️  Total device creation time: %v", deviceElapsed)
	log.Printf("   ⏱️  Total device creation time (milliseconds): %.3f ms", float64(deviceElapsed.Nanoseconds())/1e6)
	log.Printf("   ⏱️  Total device creation time (nanoseconds): %d ns", deviceElapsed.Nanoseconds())
	log.Printf("   📊 Average time per device: %.3f ms", float64(deviceElapsed.Nanoseconds())/float64(successCount*1e6))
	log.Printf("   📊 Average time per device: %.0f ns", float64(deviceElapsed.Nanoseconds())/float64(successCount))
	log.Printf("   🚀 Devices created per second: %.2f", float64(successCount)/deviceElapsed.Seconds())
	if sm.tunPoolSize > 0 {
		log.Printf("   💡 Mode: Parallel creation with pre-allocated interfaces")
		log.Printf("   👥 Workers used: %d", sm.maxWorkers)
	} else {
		log.Printf("   💡 Mode: Sequential creation with on-demand interfaces")
	}

	if successCount < count {
		log.Printf("   ❌ Failed devices: %d", count-successCount)
		log.Printf("   📈 Success rate: %.1f%%", float64(successCount)/float64(count)*100.0)
	} else {
		log.Printf("   ✅ Success rate: 100%%")
	}

	log.Printf("Successfully created %d out of %d requested devices", successCount, count)
	return nil
}

// createDevicesParallel creates devices in parallel when pre-allocation was done
func (sm *SimulatorManager) createDevicesParallel(count int, netmask string, resourceFile string, resources *DeviceResources, v3Config *SNMPv3Config, successCount *int) {
	// Worker pool for parallel device creation
	sem := make(chan struct{}, sm.maxWorkers) // Limit concurrent workers
	var wg sync.WaitGroup
	var mu sync.Mutex

	log.Printf("📡 Creating %d devices in parallel with %d workers...", count, sm.maxWorkers)
	parallelStartTime := time.Now()
	log.Printf("⏱️  PARALLEL DEVICE START TIME: %v", parallelStartTime.Format("15:04:05.000"))

	// Get starting IP with read lock
	sm.mu.RLock()
	startingIP := make(net.IP, len(sm.currentIP))
	copy(startingIP, sm.currentIP)
	sm.mu.RUnlock()

	for i := 0; i < count; i++ {
		// Calculate IP for this device index
		deviceIP := make(net.IP, len(startingIP))
		copy(deviceIP, startingIP)

		// Increment IP for this device index
		for j := 0; j < i; j++ {
			sm.incrementIPAddress(deviceIP)
		}

		deviceID := fmt.Sprintf("device-%s", deviceIP.String())

		// Check if device already exists
		sm.mu.RLock()
		_, exists := sm.devices[deviceID]
		sm.mu.RUnlock()

		if exists {
			continue
		}

		wg.Add(1)
		go func(deviceIndex int, ip net.IP, devID string) {
			defer wg.Done()

			// Acquire worker slot
			sem <- struct{}{}
			defer func() { <-sem }()

			// Create device in parallel
			if sm.createSingleDevice(deviceIndex, ip, devID, netmask, resourceFile, resources, v3Config) {
				mu.Lock()
				(*successCount)++
				progress := *successCount
				mu.Unlock()

				// Update progress counter
				sm.deviceCreateProgress.Store(progress)
			}

		}(i, deviceIP, deviceID)
	}

	// Wait for all workers to complete
	wg.Wait()

	parallelElapsed := time.Since(parallelStartTime)
	parallelEndTime := time.Now()
	log.Printf("⏱️  PARALLEL DEVICE END TIME: %v", parallelEndTime.Format("15:04:05.000"))
	log.Printf("📊 Parallel device creation completed: %d devices in %v (%.3f ms per device)",
		*successCount, parallelElapsed, float64(parallelElapsed.Nanoseconds())/float64(*successCount*1e6))
	log.Printf("📊 Parallel creation rate: %.2f devices/second", float64(*successCount)/parallelElapsed.Seconds())
}

// createSingleDevice creates a single device - used by parallel device creation
func (sm *SimulatorManager) createSingleDevice(deviceIndex int, deviceIP net.IP, deviceID string, netmask string, resourceFile string, resources *DeviceResources, v3Config *SNMPv3Config) bool {
	// Check if we have a pre-allocated interface for this IP
	var tunIface *TunInterface

	sm.tunPoolMutex.RLock()
	preAllocated, exists := sm.tunInterfacePool[deviceIP.String()]
	sm.tunPoolMutex.RUnlock()

	if exists && preAllocated != nil {
		// Use pre-allocated interface - it already has IP configured
		tunIface = preAllocated
	} else {
		// No pre-allocated interface found, create on-demand
		// Use getNextTunName to ensure unique interface names
		sm.mu.Lock()
		tunName := sm.getNextTunName()
		sm.mu.Unlock()
		var err error
		tunIface, err = createTunInterface(tunName, deviceIP, netmask)
		if err != nil {
			// log.Printf("Failed to create TUN interface for %s: %v", deviceID, err)
			return false
		}
	}

	// Create device with default ports
	sysLocationValue := getRandomCity()
	sysNameValue := getRandomDeviceName()

	device := &DeviceSimulator{
		ID:           deviceID,
		IP:           make(net.IP, len(deviceIP)),
		SNMPPort:     DEFAULT_SNMP_PORT,
		SSHPort:      DEFAULT_SSH_PORT,
		tunIface:     tunIface,
		resources:    resources,
		resourceFile: resourceFile,
		sysLocation:  sysLocationValue,
		sysName:      sysNameValue,
	}
	copy(device.IP, deviceIP)

	// Cache the dynamic values using atomic for lock-free access
	device.cachedSysName.Store(sysNameValue)
	device.cachedSysLocation.Store(sysLocationValue)

	// Create servers with SNMPv3 configuration
	device.snmpServer = &SNMPServer{
		device:   device,
		v3Config: v3Config,
	}
	device.sshServer = &SSHServer{device: device, signer: sm.sharedSSHSigner}

	// Start device services
	if err := device.Start(); err != nil {
		device.Stop() // Clean up
		return false
	}

	// Add device to map with a write lock
	sm.mu.Lock()
	sm.devices[deviceID] = device
	sm.mu.Unlock()

	return true
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

	// Handle overflow or reaching 255 (move to next subnet)
	if newIP[3] == 0 || newIP[3] == 255 {
		newIP[2]++
		newIP[3] = 1 // Start from .1 in the new subnet
		if newIP[2] == 0 {
			newIP[1]++
			newIP[3] = 1 // Start from .1 in the new subnet
			if newIP[1] == 0 {
				newIP[0]++
				newIP[3] = 1 // Start from .1 in the new subnet
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
	// log.Printf("Deleted device: %s", deviceID)
	return nil
}

func (sm *SimulatorManager) DeleteAllDevices() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var errors []string

	for deviceID, device := range sm.devices {
		if err := device.Stop(); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", deviceID, err))
		}
	}

	// Clear the devices map
	sm.devices = make(map[string]*DeviceSimulator)
	// log.Printf("Deleted all %d devices", count)

	if len(errors) > 0 {
		return fmt.Errorf("errors deleting devices: %s", strings.Join(errors, ", "))
	}
	return nil
}

// CleanupPreAllocatedInterfaces destroys all pre-allocated TUN interfaces
func (sm *SimulatorManager) CleanupPreAllocatedInterfaces() {
	sm.tunPoolMutex.Lock()
	defer sm.tunPoolMutex.Unlock()

	for _, tunIface := range sm.tunInterfacePool {
		if tunIface != nil && tunIface.PreAllocated {
			tunIface.destroy()
			// log.Printf("Cleaned up pre-allocated interface %s", tunIface.Name)
		}
	}

	// Clear the pool
	sm.tunInterfacePool = make(map[string]*TunInterface)
	sm.tunPoolSize = 0
	log.Printf("Cleaned up all pre-allocated interfaces")
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
	// log.Printf("Device %s started on %s (interface: %s, SNMP:%d, SSH:%d)",
	//	d.ID, d.IP.String(), d.tunIface.Name, d.SNMPPort, d.SSHPort)

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

	// Only destroy TUN interface if it's not pre-allocated
	if d.tunIface != nil && !d.tunIface.PreAllocated {
		d.tunIface.destroy()
	}
	// Pre-allocated interfaces remain available for reuse

	d.running = false
	// log.Printf("Device %s stopped", d.ID)

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
		fmt.Printf("  %s -auto-start-ip 192.168.100.1 -auto-count 10000       # 10K devices\n", os.Args[0])
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

	// Load world cities from CSV file
	if err := loadWorldCities(); err != nil {
		log.Printf("Warning: failed to load world cities: %v", err)
	}

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

	// Setup REST API first
	router := setupRoutes()

	// Start API server in background
	apiPort := ":" + *port
	log.Printf("Network Device Simulator server starting on port %s", apiPort)
	log.Println()
	log.Println("🌐 Web UI:")
	log.Printf("  http://localhost%s/", apiPort)
	log.Printf("  http://localhost%s/ui", apiPort)
	log.Println()

	// Start web server in background
	go func() {
		log.Fatal(http.ListenAndServe(apiPort, router))
	}()

	// Give web server a moment to start
	time.Sleep(100 * time.Millisecond)
	log.Printf("✅ Web UI is now available at http://localhost%s/ui", apiPort)
	log.Println()

	// Auto-create devices in background if requested
	if *autoStartIP != "" && *autoCount > 0 {
		go func() {
			log.Printf("🚀 Starting background device creation: %d devices from %s/%s", *autoCount, *autoStartIP, *autoNetmask)

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
				log.Printf("❌ Failed to auto-create devices: %v", err)
			} else {
				log.Printf("✅ Successfully auto-created %d devices", *autoCount)
			}
		}()
	}

	// Print API documentation
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

	// Keep the main thread alive
	select {}
}
