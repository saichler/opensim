package main

import (
	"context"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Shared TUN interface management structures
type SharedTunInterface struct {
	Name        string
	Network     *net.IPNet
	fd          int
	deviceCount int
	mu          sync.RWMutex
}

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
	ID            string
	IP            net.IP
	SNMPPort      int
	SSHPort       int
	sharedTunIface *SharedTunInterface
	snmpServer    *SNMPServer
	sshServer     *SSHServer
	resources     *DeviceResources
	running       bool
	mu            sync.RWMutex
}

type SNMPServer struct {
	device   *DeviceSimulator
	listener *net.UDPConn
	running  bool
	ctx      context.Context
	cancel   context.CancelFunc
}

type SSHServer struct {
	device        *DeviceSimulator
	listener      net.Listener
	config        *ssh.ServerConfig
	running       bool
	ctx           context.Context
	cancel        context.CancelFunc
	connLimiter   chan struct{}
	maxConns      int
}

// Resource pools for efficient memory usage
type ResourcePool struct {
	sharedResources *DeviceResources
	sharedSSHKey    ssh.Signer
	sharedTunIfaces map[string]*SharedTunInterface
	portAllocator   *PortAllocator
	mu              sync.RWMutex
}

type PortAllocator struct {
	snmpPorts map[int]bool
	sshPorts  map[int]bool
	nextSNMP  int
	nextSSH   int
	mu        sync.RWMutex
}

// Manager for all simulated devices
type SimulatorManager struct {
	devices         map[string]*DeviceSimulator
	currentIP       net.IP
	nextTunIndex    int
	deviceResources *DeviceResources
	resourcePool    *ResourcePool
	goroutinePool   chan struct{}
	maxGoroutines   int
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