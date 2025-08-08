package main

import (
	"bufio"
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/ssh"
)

// SNMP ASN.1 BER/DER type tags
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
)

// Configuration constants
const (
	DEFAULT_SNMP_PORT = 161
	DEFAULT_SSH_PORT  = 22
	USERNAME          = "simadmin"
	PASSWORD          = "simadmin"
	TUN_DEVICE_PREFIX = "sim"
)

// TUN/TAP interface constants
const (
	TUNSETIFF   = 0x400454ca
	IFF_TUN     = 0x0001
	IFF_TAP     = 0x0002
	IFF_NO_PI   = 0x1000
	IFF_UP      = 0x1
	IFF_RUNNING = 0x40
)

// TUN interface structure
type TunInterface struct {
	Name string
	File *os.File
	IP   net.IP
	fd   int
}

// Device resource structures
type SNMPResource struct {
	OID      string `json:"oid"`
	Response string `json:"response"`
}

type SSHResource struct {
	Command  string `json:"command"`
	Response string `json:"response"`
}

type DeviceResources struct {
	SNMP []SNMPResource `json:"snmp"`
	SSH  []SSHResource  `json:"ssh"`
}

// Device simulator structure
type DeviceSimulator struct {
	ID         string
	IP         net.IP
	SNMPPort   int
	SSHPort    int
	tunIface   *TunInterface
	snmpServer *SNMPServer
	sshServer  *SSHServer
	resources  DeviceResources
	running    bool
	mu         sync.RWMutex
}

// SNMP Server structure
type SNMPServer struct {
	device   *DeviceSimulator
	listener *net.UDPConn
	running  bool
}

// SSH Server structure
type SSHServer struct {
	device   *DeviceSimulator
	listener net.Listener
	config   *ssh.ServerConfig
	running  bool
}

// Simulator manager
type SimulatorManager struct {
	devices      map[string]*DeviceSimulator
	mu           sync.RWMutex
	resources    DeviceResources
	nextIP       net.IP
	tunCounter   int
	tunCounterMu sync.Mutex
}

// Global manager instance
var manager *SimulatorManager

// REST API request/response structures
type CreateDevicesRequest struct {
	StartIP     string `json:"start_ip"`
	DeviceCount int    `json:"device_count"`
	Netmask     string `json:"netmask,omitempty"` // Optional, defaults to /24
}

type DeviceInfo struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	SNMPPort  int    `json:"snmp_port"`
	SSHPort   int    `json:"ssh_port"`
	Running   bool   `json:"running"`
	Interface string `json:"interface,omitempty"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// TUN/TAP interface management
func createTunInterface(name string, ip net.IP, netmask string) (*TunInterface, error) {
	// Check if running as root
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("TUN/TAP interface creation requires root privileges")
	}

	// Open TUN device
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %v", err)
	}

	// Create interface request structure
	var ifr struct {
		name  [16]byte
		flags uint16
		_     [22]byte // padding
	}

	// Set interface name
	copy(ifr.name[:], name)
	ifr.flags = IFF_TUN | IFF_NO_PI

	// Create TUN interface
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), TUNSETIFF, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		file.Close()
		return nil, fmt.Errorf("failed to create TUN interface: %v", errno)
	}

	tunIface := &TunInterface{
		Name: name,
		File: file,
		IP:   ip,
		fd:   int(file.Fd()),
	}

	// Configure the interface
	err = tunIface.configure(netmask)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to configure TUN interface: %v", err)
	}

	log.Printf("Created TUN interface %s with IP %s", name, ip.String())
	return tunIface, nil
}

func (tun *TunInterface) configure(netmask string) error {
	if netmask == "" {
		netmask = "24" // Default to /24
	}

	// Bring interface up and assign IP
	commands := [][]string{
		{"ip", "link", "set", tun.Name, "up"},
		{"ip", "addr", "add", fmt.Sprintf("%s/%s", tun.IP.String(), netmask), "dev", tun.Name},
	}

	for _, cmd := range commands {
		err := exec.Command(cmd[0], cmd[1:]...).Run()
		if err != nil {
			return fmt.Errorf("failed to execute %v: %v", cmd, err)
		}
	}

	return nil
}

func (tun *TunInterface) destroy() error {
	if tun.File != nil {
		tun.File.Close()
	}

	// Remove interface
	err := exec.Command("ip", "link", "delete", tun.Name).Run()
	if err != nil {
		log.Printf("Warning: failed to delete interface %s: %v", tun.Name, err)
	}

	log.Printf("Destroyed TUN interface %s", tun.Name)
	return nil
}

// Initialize simulator manager
func NewSimulatorManager() *SimulatorManager {
	return &SimulatorManager{
		devices:    make(map[string]*DeviceSimulator),
		tunCounter: 0,
	}
}

// Generate unique TUN interface name
func (sm *SimulatorManager) getNextTunName() string {
	sm.tunCounterMu.Lock()
	defer sm.tunCounterMu.Unlock()

	name := fmt.Sprintf("%s%d", TUN_DEVICE_PREFIX, sm.tunCounter)
	sm.tunCounter++
	return name
}

// Load resources from file
func (sm *SimulatorManager) LoadResources(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		// Create default resources if file doesn't exist
		return sm.createDefaultResources(filename)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&sm.resources)
	if err != nil {
		return fmt.Errorf("error parsing resources file: %v", err)
	}

	log.Printf("Loaded %d SNMP and %d SSH resources", len(sm.resources.SNMP), len(sm.resources.SSH))
	return nil
}

// Create default resources file
func (sm *SimulatorManager) createDefaultResources(filename string) error {
	defaultResources := DeviceResources{
		SNMP: []SNMPResource{
			{OID: "1.3.6.1.2.1.1.1.0", Response: "Cisco IOS Software, Router Version 15.1"},
			{OID: "1.3.6.1.2.1.1.2.0", Response: "1.3.6.1.4.1.9.1.1"},
			{OID: "1.3.6.1.2.1.1.3.0", Response: "123456789"},
			{OID: "1.3.6.1.2.1.1.4.0", Response: "Network Administrator"},
			{OID: "1.3.6.1.2.1.1.5.0", Response: "Router-Simulator"},
			{OID: "1.3.6.1.2.1.1.6.0", Response: "Simulation Lab"},
			{OID: "1.3.6.1.2.1.2.1.0", Response: "4"},
		},
		SSH: []SSHResource{
			{Command: "show version", Response: "Cisco IOS Software, C2900 Software\nSystem uptime is 15 days, 3 hours"},
			{Command: "show interfaces", Response: "GigabitEthernet0/0 is up, line protocol is up\nGigabitEthernet0/1 is up, line protocol is up"},
			{Command: "show ip route", Response: "Codes: C - connected, S - static, R - RIP\nGateway of last resort is 192.168.1.1"},
			{Command: "show running-config", Response: "Building configuration...\n!\nhostname Router-Simulator\n!"},
			{Command: "show memory", Response: "Head    Total(b)     Used(b)     Free(b)\nProcessor   262144000  45678900  216465100"},
			{Command: "show cpu", Response: "CPU utilization: 23%/12%; one minute: 25%; five minutes: 28%"},
			{Command: "show clock", Response: time.Now().Format("15:04:05.000 MST Mon Jan 2 2006")},
			{Command: "show users", Response: "Line       User       Host(s)              Idle\nvty 0      simadmin   idle                 00:00:00"},
		},
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(defaultResources)
	if err != nil {
		return err
	}

	sm.resources = defaultResources
	log.Printf("Created default resources file: %s", filename)
	return nil
}

// Create multiple devices
func (sm *SimulatorManager) CreateDevices(startIP string, count int, netmask string) error {
	ip := net.ParseIP(startIP)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", startIP)
	}

	// Check root privileges for TUN interface creation
	if os.Geteuid() != 0 {
		return fmt.Errorf("root privileges required to create TUN interfaces")
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.nextIP = ip
	created := 0
	var errors []string

	for i := 0; i < count; i++ {
		deviceID := fmt.Sprintf("device-%s", sm.nextIP.String())

		// Check if device already exists
		if _, exists := sm.devices[deviceID]; exists {
			log.Printf("Device %s already exists, skipping", deviceID)
			sm.incrementIP()
			continue
		}

		// Create TUN interface for this device
		tunName := sm.getNextTunName()
		tunIface, err := createTunInterface(tunName, sm.nextIP, netmask)
		if err != nil {
			errMsg := fmt.Sprintf("failed to create TUN interface for %s: %v", deviceID, err)
			log.Printf(errMsg)
			errors = append(errors, errMsg)
			sm.incrementIP()
			continue
		}

		device := &DeviceSimulator{
			ID:        deviceID,
			IP:        make(net.IP, len(sm.nextIP)),
			SNMPPort:  DEFAULT_SNMP_PORT,
			SSHPort:   DEFAULT_SSH_PORT,
			tunIface:  tunIface,
			resources: sm.resources,
			running:   false,
		}
		copy(device.IP, sm.nextIP)

		// Start the device
		err = device.Start()
		if err != nil {
			errMsg := fmt.Sprintf("failed to start device %s: %v", deviceID, err)
			log.Printf(errMsg)
			errors = append(errors, errMsg)

			// Clean up TUN interface
			tunIface.destroy()
			sm.incrementIP()
			continue
		}

		sm.devices[deviceID] = device
		log.Printf("Created device: %s on IP %s (interface: %s)", deviceID, device.IP.String(), tunName)
		created++
		sm.incrementIP()
	}

	if created == 0 {
		if len(errors) > 0 {
			return fmt.Errorf("failed to create any devices. Errors: %s", strings.Join(errors, "; "))
		}
		return fmt.Errorf("failed to create any devices")
	}

	log.Printf("Successfully created %d out of %d requested devices", created, count)
	if len(errors) > 0 {
		log.Printf("Errors encountered: %s", strings.Join(errors, "; "))
	}
	return nil
}

// Increment IP address
func (sm *SimulatorManager) incrementIP() {
	// Convert IP to 32-bit integer, increment, and convert back
	ip := sm.nextIP.To4()
	if ip == nil {
		return
	}

	val := binary.BigEndian.Uint32(ip)
	val++
	binary.BigEndian.PutUint32(ip, val)
	sm.nextIP = ip
}

// List all devices
func (sm *SimulatorManager) ListDevices() []DeviceInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	devices := make([]DeviceInfo, 0, len(sm.devices))
	for _, device := range sm.devices {
		device.mu.RLock()
		info := DeviceInfo{
			ID:       device.ID,
			IP:       device.IP.String(),
			SNMPPort: device.SNMPPort,
			SSHPort:  device.SSHPort,
			Running:  device.running,
		}
		if device.tunIface != nil {
			info.Interface = device.tunIface.Name
		}
		device.mu.RUnlock()
		devices = append(devices, info)
	}

	return devices
}

// Delete device
func (sm *SimulatorManager) DeleteDevice(deviceID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	device, exists := sm.devices[deviceID]
	if !exists {
		return fmt.Errorf("device %s not found", deviceID)
	}

	err := device.Stop()
	if err != nil {
		log.Printf("Error stopping device %s: %v", deviceID, err)
	}

	delete(sm.devices, deviceID)
	log.Printf("Deleted device: %s", deviceID)
	return nil
}

// Delete all devices
func (sm *SimulatorManager) DeleteAllDevices() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var errors []string
	for deviceID, device := range sm.devices {
		err := device.Stop()
		if err != nil {
			errMsg := fmt.Sprintf("error stopping device %s: %v", deviceID, err)
			log.Printf(errMsg)
			errors = append(errors, errMsg)
		}
	}

	sm.devices = make(map[string]*DeviceSimulator)
	log.Println("Deleted all devices")

	if len(errors) > 0 {
		return fmt.Errorf("errors occurred while deleting devices: %s", strings.Join(errors, "; "))
	}
	return nil
}

// Device simulator methods
func (d *DeviceSimulator) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.running {
		return fmt.Errorf("device %s is already running", d.ID)
	}

	// Start SNMP server
	snmpServer := &SNMPServer{device: d}
	err := snmpServer.Start()
	if err != nil {
		return fmt.Errorf("failed to start SNMP server: %v", err)
	}
	d.snmpServer = snmpServer

	// Start SSH server
	sshServer := &SSHServer{device: d}
	err = sshServer.Start()
	if err != nil {
		d.snmpServer.Stop()
		return fmt.Errorf("failed to start SSH server: %v", err)
	}
	d.sshServer = sshServer

	d.running = true
	interfaceName := "unknown"
	if d.tunIface != nil {
		interfaceName = d.tunIface.Name
	}
	log.Printf("Device %s started on %s (interface: %s, SNMP:%d, SSH:%d)",
		d.ID, d.IP.String(), interfaceName, d.SNMPPort, d.SSHPort)
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

	// Destroy TUN interface
	if d.tunIface != nil {
		if err := d.tunIface.destroy(); err != nil {
			errors = append(errors, fmt.Sprintf("TUN: %v", err))
		}
	}

	d.running = false
	log.Printf("Device %s stopped", d.ID)

	if len(errors) > 0 {
		return fmt.Errorf("errors stopping services: %s", strings.Join(errors, ", "))
	}
	return nil
}

// SNMP Server implementation
func (s *SNMPServer) Start() error {
	addr := &net.UDPAddr{
		IP:   s.device.IP,
		Port: s.device.SNMPPort,
	}

	listener, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	s.listener = listener
	s.running = true

	go s.handleRequests()
	return nil
}

func (s *SNMPServer) Stop() error {
	if s.listener != nil {
		s.running = false
		return s.listener.Close()
	}
	return nil
}

func (s *SNMPServer) handleRequests() {
	buffer := make([]byte, 1024)

	for s.running {
		n, clientAddr, err := s.listener.ReadFromUDP(buffer)
		if err != nil {
			if s.running {
				log.Printf("SNMP server error reading UDP: %v", err)
			}
			continue
		}

		// Parse SNMP request (simplified)
		oid := s.parseOIDFromRequest(buffer[:n])
		response := s.findResponse(oid)

		// Create simple SNMP response
		responsePacket := s.createSNMPResponse(oid, response)

		_, err = s.listener.WriteToUDP(responsePacket, clientAddr)
		if err != nil {
			log.Printf("Error sending SNMP response: %v", err)
		}

		log.Printf("SNMP %s: %s -> %s", s.device.ID, oid, response)
	}
}

func (s *SNMPServer) findResponse(oid string) string {
	for _, resource := range s.device.resources.SNMP {
		if resource.OID == oid {
			return resource.Response
		}
	}
	return "OID not supported"
}

func (s *SNMPServer) createSNMPResponse(oid, value string) []byte {
	// Create a basic SNMP response packet (simplified)
	response := fmt.Sprintf("SNMP Response: %s = %s", oid, value)
	return []byte(response)
}

// SSH Server implementation
func (s *SSHServer) Start() error {
	// Generate host key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)

	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return err
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == USERNAME && string(pass) == PASSWORD {
				return nil, nil
			}
			return nil, fmt.Errorf("invalid credentials")
		},
	}
	config.AddHostKey(signer)

	addr := fmt.Sprintf("%s:%d", s.device.IP.String(), s.device.SSHPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	s.listener = listener
	s.config = config
	s.running = true

	go s.handleConnections()
	return nil
}

func (s *SSHServer) Stop() error {
	if s.listener != nil {
		s.running = false
		return s.listener.Close()
	}
	return nil
}

func (s *SSHServer) handleConnections() {
	for s.running {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.running {
				log.Printf("SSH server error accepting connection: %v", err)
			}
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *SSHServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	sshConn, channels, requests, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		log.Printf("SSH handshake error: %v", err)
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(requests)

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Error accepting channel: %v", err)
			continue
		}

		go s.handleSession(channel, requests)
	}
}

func (s *SSHServer) handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	// Handle session requests
	go func() {
		for req := range requests {
			switch req.Type {
			case "shell", "exec":
				req.Reply(true, nil)
			default:
				req.Reply(false, nil)
			}
		}
	}()

	// Send welcome message
	welcome := fmt.Sprintf("Welcome to %s\nDevice Simulator SSH Server\n\n", s.device.ID)
	channel.Write([]byte(welcome))

	scanner := bufio.NewScanner(channel)

	for {
		// Send prompt
		channel.Write([]byte(fmt.Sprintf("%s> ", s.device.ID)))

		// Read command
		if !scanner.Scan() {
			break
		}

		command := strings.TrimSpace(scanner.Text())
		if command == "" {
			continue
		}

		if command == "exit" || command == "quit" {
			channel.Write([]byte("Goodbye!\n"))
			break
		}

		// Find response
		response := s.findCommandResponse(command)
		channel.Write([]byte(response + "\n\n"))

		log.Printf("SSH %s: %s -> %s", s.device.ID, command, strings.Split(response, "\n")[0])
	}
}

func (s *SSHServer) findCommandResponse(command string) string {
	for _, resource := range s.device.resources.SSH {
		if strings.EqualFold(resource.Command, command) {
			return resource.Response
		}
	}
	return "Command not found"
}

// REST API handlers
func createDevicesHandler(w http.ResponseWriter, r *http.Request) {
	var req CreateDevicesRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		sendErrorResponse(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.DeviceCount <= 0 || req.DeviceCount > 100 {
		sendErrorResponse(w, "Device count must be between 1 and 100", http.StatusBadRequest)
		return
	}

	err = manager.CreateDevices(req.StartIP, req.DeviceCount, req.Netmask)
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
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh; padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header {
            background: rgba(255, 255, 255, 0.1); backdrop-filter: blur(10px);
            border-radius: 20px; padding: 30px; margin-bottom: 30px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }
        .header h1 { color: white; font-size: 2.5em; font-weight: 300; margin-bottom: 10px; text-align: center; }
        .header p { color: rgba(255, 255, 255, 0.8); text-align: center; font-size: 1.1em; }
        .controls, .status, .devices {
            background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(10px);
            border-radius: 20px; padding: 30px; margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .controls h2, .devices h2 { color: #333; margin-bottom: 20px; font-weight: 600; }
        .form-row { display: flex; gap: 20px; align-items: end; }
        .form-row .form-group { flex: 1; margin-bottom: 0; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: #555; font-weight: 500; }
        input, select {
            width: 100%; padding: 12px 16px; border: 2px solid #e1e5e9;
            border-radius: 12px; font-size: 16px; transition: all 0.3s ease; background: white;
        }
        input:focus, select:focus {
            outline: none; border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; border: none; padding: 12px 24px; border-radius: 12px;
            cursor: pointer; font-size: 16px; font-weight: 600;
            transition: all 0.3s ease; min-width: 120px;
        }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(102, 126, 234, 0.3); }
        .btn-danger { background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%); }
        .btn-danger:hover { box-shadow: 0 8px 25px rgba(255, 107, 107, 0.3); }
        .btn-small { padding: 8px 16px; font-size: 14px; min-width: auto; }
        .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
        .status-card {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white; padding: 20px; border-radius: 16px; text-align: center;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }
        .status-card h3 { font-size: 2em; margin-bottom: 5px; font-weight: 300; }
        .status-card p { opacity: 0.9; }
        .device-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 20px; }
        .device-card {
            background: white; border: 2px solid #e1e5e9; border-radius: 16px;
            padding: 20px; transition: all 0.3s ease; position: relative; overflow: hidden;
        }
        .device-card::before {
            content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .device-card:hover { transform: translateY(-4px); box-shadow: 0 12px 30px rgba(0, 0, 0, 0.1); }
        .device-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .device-id { font-weight: 600; color: #333; font-size: 1.1em; }
        .device-status { padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }
        .status-running { background: #d4edda; color: #155724; }
        .status-stopped { background: #f8d7da; color: #721c24; }
        .device-details { margin-bottom: 15px; }
        .device-detail { display: flex; justify-content: space-between; margin-bottom: 8px; font-size: 14px; }
        .device-detail .label { color: #666; font-weight: 500; }
        .device-detail .value { color: #333; font-family: Monaco, monospace; }
        .device-actions { display: flex; gap: 10px; }
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
            .device-grid { grid-template-columns: 1fr; }
            .status-grid { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 Network Device Simulator</h1>
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
                        <input type="number" id="deviceCount" min="1" max="100" value="1" required>
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
                    <button id="refreshBtn" class="btn btn-small">
                        🔄 Refresh <span id="refreshLoading" class="loading" style="display: none;"></span>
                    </button>
                    <button id="deleteAllBtn" class="btn btn-danger btn-small">
                        🗑️ Delete All <span id="deleteAllLoading" class="loading" style="display: none;"></span>
                    </button>
                </div>
            </div>
            <div id="deviceList" class="device-grid"></div>
        </div>
    </div>
    <script>
        const API_BASE = '/api/v1';
        let devices = [];
        
        const elements = {
            createForm: document.getElementById('createForm'),
            deviceList: document.getElementById('deviceList'),
            alerts: document.getElementById('alerts'),
            refreshBtn: document.getElementById('refreshBtn'),
            deleteAllBtn: document.getElementById('deleteAllBtn'),
            totalDevices: document.getElementById('totalDevices'),
            runningDevices: document.getElementById('runningDevices'),
            stoppedDevices: document.getElementById('stoppedDevices'),
            tunInterfaces: document.getElementById('tunInterfaces')
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

        async function createDevices(startIp, deviceCount, netmask) {
            try {
                setLoading('createLoading', true);
                const response = await apiCall('/devices', {
                    method: 'POST',
                    body: JSON.stringify({
                        start_ip: startIp,
                        device_count: parseInt(deviceCount),
                        netmask: netmask
                    })
                });
                showAlert(response.message, 'success');
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

        function renderDevices() {
            if (devices.length === 0) {
                elements.deviceList.innerHTML = '<div class="empty-state" style="grid-column: 1 / -1;"><div style="font-size: 4em; margin-bottom: 20px;">📱</div><h3>No Devices Found</h3><p>Create your first simulated network device to get started</p></div>';
                return;
            }
            
            elements.deviceList.innerHTML = devices.map((device, index) => 
                '<div class="device-card">' +
                '<div class="device-header">' +
                '<div class="device-id">' + device.id + '</div>' +
                '<div class="device-status ' + (device.running ? 'status-running' : 'status-stopped') + '">' +
                (device.running ? '● RUNNING' : '● STOPPED') +
                '</div></div>' +
                '<div class="device-details">' +
                '<div class="device-detail"><span class="label">IP Address:</span><span class="value">' + device.ip + '</span></div>' +
                '<div class="device-detail"><span class="label">Interface:</span><span class="value">' + (device.interface || 'N/A') + '</span></div>' +
                '<div class="device-detail"><span class="label">SNMP Port:</span><span class="value">' + device.snmp_port + '</span></div>' +
                '<div class="device-detail"><span class="label">SSH Port:</span><span class="value">' + device.ssh_port + '</span></div>' +
                '<div class="device-detail"><span class="label">Status:</span><span class="value">' + (device.running ? 'Active' : 'Inactive') + '</span></div>' +
                '</div>' +
                '<div class="device-actions">' +
                '<button class="btn btn-small" data-action="test-ssh" data-ip="' + device.ip + '" data-port="' + device.ssh_port + '">🔗 Test SSH</button>' +
                '<button class="btn btn-small" data-action="ping" data-ip="' + device.ip + '">📡 Ping</button>' +
                '<button class="btn btn-danger btn-small" data-action="delete" data-device-id="' + device.id + '">🗑️ Delete</button>' +
                '</div></div>'
            ).join('');
            
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
            if (!startIp || !deviceCount) {
                showAlert('Please fill in all required fields', 'error');
                return;
            }
            await createDevices(startIp, deviceCount, netmask);
            elements.createForm.reset();
            document.getElementById('deviceCount').value = '1';
            document.getElementById('netmask').value = '24';
        });

        elements.refreshBtn.addEventListener('click', loadDevices);
        elements.deleteAllBtn.addEventListener('click', deleteAllDevices);
        
        setInterval(loadDevices, 30000);
        
        document.addEventListener('DOMContentLoaded', () => {
            loadDevices();
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
	api.HandleFunc("/devices/{id}", deleteDeviceHandler).Methods("DELETE")
	api.HandleFunc("/devices", deleteAllDevicesHandler).Methods("DELETE")

	// Health check
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}).Methods("GET")

	return router
}

// parseOIDFromRequest extracts the first OID from an SNMP request packet
func (s *SNMPServer) parseOIDFromRequest(data []byte) string {
	if len(data) < 10 {
		return "1.3.6.1.2.1.1.1.0" // Default fallback
	}

	// Find the OID in the SNMP packet
	oid := extractOIDFromSNMPPacket(data)
	if oid == "" {
		return "1.3.6.1.2.1.1.1.0" // Default fallback
	}

	return oid
}

// extractOIDFromSNMPPacket parses SNMP BER/DER encoded packet to find OID
func extractOIDFromSNMPPacket(data []byte) string {
	pos := 0

	// Parse the outer SEQUENCE
	if pos >= len(data) || data[pos] != ASN1_SEQUENCE {
		return ""
	}
	pos++

	// Skip length of outer sequence
	length, newPos := parseLength(data, pos)
	if length == -1 {
		return ""
	}
	pos = newPos

	// Parse SNMP version (INTEGER)
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return ""
	}
	pos++

	// Skip version length and value
	versionLen, newPos := parseLength(data, pos)
	if versionLen == -1 {
		return ""
	}
	pos = newPos + versionLen

	// Parse community string (OCTET STRING)
	if pos >= len(data) || data[pos] != ASN1_OCTET_STRING {
		return ""
	}
	pos++

	// Skip community length and value
	communityLen, newPos := parseLength(data, pos)
	if communityLen == -1 {
		return ""
	}
	pos = newPos + communityLen

	// Parse PDU (GET_REQUEST, GET_NEXT, etc.)
	if pos >= len(data) {
		return ""
	}
	pduType := data[pos]
	if pduType != ASN1_GET_REQUEST && pduType != ASN1_GET_NEXT &&
		pduType != ASN1_SET_REQUEST && pduType != ASN1_GET_RESPONSE {
		return ""
	}
	pos++

	// Skip PDU length
	pduLen, newPos := parseLength(data, pos)
	if pduLen == -1 {
		return ""
	}
	pos = newPos

	// Parse request ID (INTEGER)
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return ""
	}
	pos++

	// Skip request ID length and value
	reqIdLen, newPos := parseLength(data, pos)
	if reqIdLen == -1 {
		return ""
	}
	pos = newPos + reqIdLen

	// Parse error status (INTEGER)
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return ""
	}
	pos++

	// Skip error status length and value
	errorLen, newPos := parseLength(data, pos)
	if errorLen == -1 {
		return ""
	}
	pos = newPos + errorLen

	// Parse error index (INTEGER)
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return ""
	}
	pos++

	// Skip error index length and value
	errorIdxLen, newPos := parseLength(data, pos)
	if errorIdxLen == -1 {
		return ""
	}
	pos = newPos + errorIdxLen

	// Parse variable bindings (SEQUENCE)
	if pos >= len(data) || data[pos] != ASN1_SEQUENCE {
		return ""
	}
	pos++

	// Skip varbind list length
	varbindLen, newPos := parseLength(data, pos)
	if varbindLen == -1 {
		return ""
	}
	pos = newPos

	// Parse first variable binding (SEQUENCE)
	if pos >= len(data) || data[pos] != ASN1_SEQUENCE {
		return ""
	}
	pos++

	// Skip first varbind length
	firstVarbindLen, newPos := parseLength(data, pos)
	if firstVarbindLen == -1 {
		return ""
	}
	pos = newPos

	// Parse OID (OBJECT IDENTIFIER)
	if pos >= len(data) || data[pos] != ASN1_OBJECT_ID {
		return ""
	}
	pos++

	// Parse OID length
	oidLen, newPos := parseLength(data, pos)
	if oidLen == -1 || newPos+oidLen > len(data) {
		return ""
	}
	pos = newPos

	// Extract and decode the OID
	oidBytes := data[pos : pos+oidLen]
	return decodeOID(oidBytes)
}

// parseLength parses ASN.1 BER/DER length encoding
func parseLength(data []byte, pos int) (int, int) {
	if pos >= len(data) {
		return -1, pos
	}

	length := int(data[pos])
	pos++

	// Short form (length < 128)
	if length < 0x80 {
		return length, pos
	}

	// Long form
	lengthBytes := length & 0x7F
	if lengthBytes == 0 || lengthBytes > 4 || pos+lengthBytes > len(data) {
		return -1, pos
	}

	length = 0
	for i := 0; i < lengthBytes; i++ {
		length = (length << 8) | int(data[pos])
		pos++
	}

	return length, pos
}

// decodeOID converts ASN.1 encoded OID bytes to dot notation string
func decodeOID(oidBytes []byte) string {
	if len(oidBytes) == 0 {
		return ""
	}

	var oid []string

	// First byte encodes first two sub-identifiers
	// first = byte / 40, second = byte % 40
	firstByte := oidBytes[0]
	first := firstByte / 40
	second := firstByte % 40
	oid = append(oid, strconv.Itoa(int(first)))
	oid = append(oid, strconv.Itoa(int(second)))

	// Process remaining bytes
	pos := 1
	for pos < len(oidBytes) {
		value := 0

		// Parse variable length encoding (base 128)
		for pos < len(oidBytes) {
			b := oidBytes[pos]
			pos++

			value = (value << 7) | int(b&0x7F)

			// If high bit is 0, this is the last byte of this sub-identifier
			if (b & 0x80) == 0 {
				break
			}
		}

		oid = append(oid, strconv.Itoa(value))
	}

	return strings.Join(oid, ".")
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
	err := manager.LoadResources("resources.json")
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
