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
	ID         string
	IP         net.IP
	SNMPPort   int
	SSHPort    int
	tunIface   *TunInterface
	snmpServer *SNMPServer
	sshServer  *SSHServer
	resources  *DeviceResources
	running    bool
	mu         sync.RWMutex
}

type SNMPServer struct {
	device   *DeviceSimulator
	listener *net.UDPConn
	running  bool
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
	mu              sync.RWMutex
}

// API request/response structures
type CreateDevicesRequest struct {
	StartIP     string `json:"start_ip"`
	DeviceCount int    `json:"device_count"`
	Netmask     string `json:"netmask"`
}

type DeviceInfo struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	Interface string `json:"interface,omitempty"`
	SNMPPort  int    `json:"snmp_port"`
	SSHPort   int    `json:"ssh_port"`
	Running   bool   `json:"running"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}