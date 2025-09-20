package main

import (
	"net"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
)

// TUN interface management structures
type TunInterface struct {
	Name string
	IP   net.IP
	fd   int
}

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

	// Performance optimization indexes (not serialized)
	oidIndex    *sync.Map  `json:"-"` // Lock-free OID -> Response mapping for O(1) lookups
	sortedOIDs  []string   `json:"-"` // Pre-sorted OID list for GetNext operations
	oidNextMap  *sync.Map  `json:"-"` // Pre-computed next OID mapping for walks
}

// Device simulator represents a single simulated device
type DeviceSimulator struct {
	ID           string
	IP           net.IP
	SNMPPort     int
	SSHPort      int
	tunIface     *TunInterface
	snmpServer   *SNMPServer
	sshServer    *SSHServer
	resources    *DeviceResources
	resourceFile string // Track which resource file was used
	sysLocation  string // Dynamic sysLocation for this device
	sysName      string // Dynamic sysName for this device
	// Cached frequently accessed values (lock-free)
	cachedSysName     atomic.Value // Stores string
	cachedSysLocation atomic.Value // Stores string
	running      bool
	mu           sync.RWMutex
}

// SNMPv3 USM (User-based Security Model) configuration
type SNMPv3Config struct {
	Enabled      bool   `json:"enabled"`
	EngineID     string `json:"engine_id"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	AuthProtocol int    `json:"auth_protocol"` // 0=none, 1=MD5, 2=SHA1
	PrivProtocol int    `json:"priv_protocol"` // 0=none, 1=DES, 2=AES128
	PrivPassword string `json:"priv_password"` // Can be same as auth password
}

// SNMPv3 message structures
type SNMPv3Message struct {
	Version        int
	GlobalData     SNMPv3GlobalData
	SecurityParams SNMPv3SecurityParams
	ScopedPDU      []byte // Can be encrypted
}

type SNMPv3GlobalData struct {
	MsgID           int
	MsgMaxSize      int
	MsgFlags        byte
	MsgSecurityModel int
}

type SNMPv3SecurityParams struct {
	AuthoritativeEngineID    string
	AuthoritativeEngineBoots int
	AuthoritativeEngineTime  int
	UserName                 string
	AuthParams               []byte
	PrivParams               []byte
}

type SNMPServer struct {
	device    *DeviceSimulator
	listener  *net.UDPConn
	running   bool
	v3Config  *SNMPv3Config
}

type SSHServer struct {
	device   *DeviceSimulator
	listener net.Listener
	config   *ssh.ServerConfig
	running  bool
}

// Manager for all simulated devices
type SimulatorManager struct {
	devices         map[string]*DeviceSimulator
	currentIP       net.IP
	nextTunIndex    int
	deviceResources *DeviceResources
	resourcesCache  map[string]*DeviceResources // Cache for loaded resource files

	// TUN interface pre-allocation settings
	tunPoolSize     int                   // Size of the pre-allocated pool (0 = no pre-allocation)
	maxWorkers      int                   // Maximum parallel workers for interface creation

	// Status tracking for pre-allocation and device creation
	isPreAllocating      atomic.Value      // bool - true when pre-allocation is in progress
	preAllocProgress     atomic.Value      // int - number of interfaces pre-allocated so far
	isCreatingDevices    atomic.Value      // bool - true when device creation is in progress
	deviceCreateProgress atomic.Value      // int - number of devices created so far
	deviceCreateTotal    atomic.Value      // int - total number of devices to create

	mu              sync.RWMutex
}

// Resource file info for API
type ResourceInfo struct {
	Filename string `json:"filename"`
	Name     string `json:"name"`
	Type     string `json:"type"`
}

// API request/response structures
type CreateDevicesRequest struct {
	StartIP      string         `json:"start_ip"`
	DeviceCount  int            `json:"device_count"`
	Netmask      string         `json:"netmask"`
	ResourceFile string         `json:"resource_file,omitempty"` // Optional resource file selection
	SNMPv3       *SNMPv3Config  `json:"snmpv3,omitempty"`
}

type DeviceInfo struct {
	ID         string `json:"id"`
	IP         string `json:"ip"`
	Interface  string `json:"interface,omitempty"`
	SNMPPort   int    `json:"snmp_port"`
	SSHPort    int    `json:"ssh_port"`
	Running    bool   `json:"running"`
	DeviceType string `json:"device_type,omitempty"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type ManagerStatus struct {
	IsPreAllocating      bool `json:"is_pre_allocating"`
	PreAllocProgress     int  `json:"pre_alloc_progress"`
	PreAllocTotal        int  `json:"pre_alloc_total"`
	IsCreatingDevices    bool `json:"is_creating_devices"`
	DeviceCreateProgress int  `json:"device_create_progress"`
	DeviceCreateTotal    int  `json:"device_create_total"`
	TotalDevices         int  `json:"total_devices"`
	RunningDevices       int  `json:"running_devices"`
}