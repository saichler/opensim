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
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/ssh"
)

// Configuration constants
const (
	DEFAULT_SNMP_PORT = 161
	DEFAULT_SSH_PORT  = 22
	USERNAME          = "simadmin"
	PASSWORD          = "simadmin"
)

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
	devices   map[string]*DeviceSimulator
	mu        sync.RWMutex
	resources DeviceResources
	nextIP    net.IP
}

// Global manager instance
var manager *SimulatorManager

// REST API request/response structures
type CreateDevicesRequest struct {
	StartIP     string `json:"start_ip"`
	DeviceCount int    `json:"device_count"`
}

type DeviceInfo struct {
	ID       string `json:"id"`
	IP       string `json:"ip"`
	SNMPPort int    `json:"snmp_port"`
	SSHPort  int    `json:"ssh_port"`
	Running  bool   `json:"running"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Initialize simulator manager
func NewSimulatorManager() *SimulatorManager {
	return &SimulatorManager{
		devices: make(map[string]*DeviceSimulator),
	}
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
func (sm *SimulatorManager) CreateDevices(startIP string, count int) error {
	ip := net.ParseIP(startIP)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", startIP)
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.nextIP = ip
	created := 0

	for i := 0; i < count; i++ {
		deviceID := fmt.Sprintf("device-%s", sm.nextIP.String())

		// Check if device already exists
		if _, exists := sm.devices[deviceID]; exists {
			log.Printf("Device %s already exists, skipping", deviceID)
			sm.incrementIP()
			continue
		}

		device := &DeviceSimulator{
			ID:        deviceID,
			IP:        make(net.IP, len(sm.nextIP)),
			SNMPPort:  DEFAULT_SNMP_PORT,
			SSHPort:   DEFAULT_SSH_PORT,
			resources: sm.resources,
			running:   false,
		}
		copy(device.IP, sm.nextIP)

		// Start the device
		err := device.Start()
		if err != nil {
			log.Printf("Failed to start device %s: %v", deviceID, err)
			sm.incrementIP()
			continue
		}

		sm.devices[deviceID] = device
		log.Printf("Created device: %s on IP %s", deviceID, device.IP.String())
		created++
		sm.incrementIP()
	}

	if created == 0 {
		return fmt.Errorf("failed to create any devices")
	}

	log.Printf("Successfully created %d out of %d requested devices", created, count)
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

	for deviceID, device := range sm.devices {
		err := device.Stop()
		if err != nil {
			log.Printf("Error stopping device %s: %v", deviceID, err)
		}
	}

	sm.devices = make(map[string]*DeviceSimulator)
	log.Println("Deleted all devices")
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
	log.Printf("Device %s started on %s (SNMP:%d, SSH:%d)", d.ID, d.IP.String(), d.SNMPPort, d.SSHPort)
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

func (s *SNMPServer) parseOIDFromRequest(data []byte) string {
	// Simplified OID extraction - in practice, you'd use proper ASN.1 parsing
	// For demo, we'll return a common system OID
	return "1.3.6.1.2.1.1.1.0"
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
	// Create a basic SNMP v3 response packet (simplified)
	// This is a minimal implementation for demonstration
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

	err = manager.CreateDevices(req.StartIP, req.DeviceCount)
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

// Setup REST API routes
func setupRoutes() *mux.Router {
	router := mux.NewRouter()

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

func main() {
	log.Println("Network Device Simulator starting...")

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
	log.Printf("REST API server starting on port %s", apiPort)
	log.Println("API Endpoints:")
	log.Println("  POST   /api/v1/devices           - Create devices")
	log.Println("  GET    /api/v1/devices           - List devices")
	log.Println("  DELETE /api/v1/devices/{id}      - Delete device")
	log.Println("  DELETE /api/v1/devices           - Delete all devices")
	log.Println("  GET    /health                   - Health check")

	log.Fatal(http.ListenAndServe(apiPort, router))
}
