package main

import (
	"net"
	"sync"

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