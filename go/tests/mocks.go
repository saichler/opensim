package testside

import (
	"fmt"
	"strings"
	"time"

	"github.com/saichler/probler/go/types"
)

// GenerateMockNetworkDevice creates a mock NetworkDevice based on the same patterns 
// used in the device application's JavaScript mock data generation
func GenerateMockNetworkDevice(deviceID, deviceType string) *types.NetworkDevice {
	device := &types.NetworkDevice{
		Id:   deviceID,
		Info: generateMockEquipmentInfo(deviceID, deviceType),
		Physicals: make(map[string]*types.Physical),
		Logicals:  make(map[string]*types.Logical),
		Topology: generateMockNetworkTopology(deviceID),
		NetworkLinks: generateMockNetworkLinks(deviceID),
		NetworkHealth: generateMockNetworkHealth(),
	}

	// Generate physical components based on device type
	physical := generateMockPhysical(deviceType)
	device.Physicals["physical-0"] = physical

	// Generate logical components
	logical := generateMockLogical()
	device.Logicals["logical-0"] = logical

	return device
}

func generateMockEquipmentInfo(deviceID, deviceType string) *types.EquipmentInfo {
	now := time.Now().Format(time.RFC3339)
	
	info := &types.EquipmentInfo{
		SysName:         fmt.Sprintf("%s.example.com", deviceID),
		Location:        "Data Center A - Rack 42",
		Latitude:        37.7749,
		Longitude:       -122.4194,
		DeviceStatus:    types.DeviceStatus_DEVICE_STATUS_ONLINE,
		LastSeen:        now,
		Uptime:          "45d 12h 30m",
		IpAddress:       fmt.Sprintf("192.168.1.%d", len(deviceID)%254+1),
	}

	switch deviceType {
	case "switch":
		info.Vendor = "Cisco"
		info.Series = "Catalyst"
		info.Family = "9300"
		info.Model = "C9300-48T"
		info.Software = "Cisco IOS XE"
		info.Version = "16.12.04"
		info.SerialNumber = fmt.Sprintf("SW%s001", deviceID)
		info.FirmwareVersion = "16.12.04"
		info.DeviceType = types.DeviceType_DEVICE_TYPE_SWITCH
	case "router":
		info.Vendor = "Cisco"
		info.Series = "ISR"
		info.Family = "4000"
		info.Model = "ISR4431"
		info.Software = "Cisco IOS XE"
		info.Version = "16.09.05"
		info.SerialNumber = fmt.Sprintf("RT%s001", deviceID)
		info.FirmwareVersion = "16.09.05"
		info.DeviceType = types.DeviceType_DEVICE_TYPE_ROUTER
	case "firewall":
		info.Vendor = "Cisco"
		info.Series = "ASA"
		info.Family = "5500"
		info.Model = "ASA5516-X"
		info.Software = "Cisco ASA"
		info.Version = "9.8.4"
		info.SerialNumber = fmt.Sprintf("FW%s001", deviceID)
		info.FirmwareVersion = "9.8.4"
		info.DeviceType = types.DeviceType_DEVICE_TYPE_FIREWALL
	default:
		info.Vendor = "Generic"
		info.Series = "Unknown"
		info.Family = "Unknown"
		info.Model = "Generic Device"
		info.Software = "Unknown OS"
		info.Version = "1.0.0"
		info.SerialNumber = fmt.Sprintf("GN%s001", deviceID)
		info.FirmwareVersion = "1.0.0"
		info.DeviceType = types.DeviceType_DEVICE_TYPE_UNKNOWN
	}

	return info
}

func generateMockPhysical(deviceType string) *types.Physical {
	physical := &types.Physical{
		Id:       "physical-0",
		Chassis:  []*types.Chassis{generateMockChassis(deviceType)},
		Ports:    generateMockPorts(deviceType),
		PowerSupplies: generateMockPowerSupplies(deviceType),
		Fans:     generateMockFans(deviceType),
		Performance: generateMockPerformanceMetrics(),
	}

	return physical
}

func generateMockChassis(deviceType string) *types.Chassis {
	chassis := &types.Chassis{
		Id:           "chassis-0",
		Model:        "Main Chassis",
		Description:  fmt.Sprintf("%s Main Chassis", deviceType),
		Status:       types.ComponentStatus_COMPONENT_STATUS_OK,
		Temperature:  35.5,
		Modules:      generateMockModules(deviceType),
		Ports:        generateMockPorts(deviceType),
	}

	switch deviceType {
	case "switch":
		chassis.SerialNumber = "CH-SW-001"
		chassis.PowerSupplies = generateMockPowerSupplies(deviceType)
		chassis.Fans = generateMockFans(deviceType)
	case "router":
		chassis.SerialNumber = "CH-RT-001"
		chassis.PowerSupplies = generateMockPowerSupplies(deviceType)
	case "firewall":
		chassis.SerialNumber = "CH-FW-001"
	default:
		chassis.SerialNumber = "CH-GN-001"
	}

	return chassis
}

func generateMockModules(deviceType string) []*types.Module {
	var modules []*types.Module

	switch deviceType {
	case "switch":
		// Supervisor Module
		supervisor := &types.Module{
			Id:          "module-supervisor",
			Name:        "Supervisor Module",
			Model:       "C9300-SUP-1",
			Description: "Supervisor Engine",
			ModuleType:  types.ModuleType_MODULE_TYPE_SUPERVISOR,
			Status:      types.ComponentStatus_COMPONENT_STATUS_OK,
			Temperature: 42.3,
			Cpus:        []*types.Cpu{generateMockCpu("supervisor")},
			MemoryModules: []*types.Memory{generateMockMemory("supervisor")},
		}
		
		// Line Card
		lineCard := &types.Module{
			Id:          "module-linecard-1",
			Name:        "Line Card 1",
			Model:       "C9300-48T",
			Description: "48-Port Gigabit Line Card",
			ModuleType:  types.ModuleType_MODULE_TYPE_LINE_CARD,
			Status:      types.ComponentStatus_COMPONENT_STATUS_OK,
			Temperature: 38.7,
			Ports:       generateSwitchPorts(),
		}

		modules = append(modules, supervisor, lineCard)

	case "router":
		// Route Processor
		routeProcessor := &types.Module{
			Id:          "module-rp",
			Name:        "Route Processor",
			Model:       "ISR4431-RP",
			Description: "Main Route Processor",
			ModuleType:  types.ModuleType_MODULE_TYPE_ROUTE_PROCESSOR,
			Status:      types.ComponentStatus_COMPONENT_STATUS_OK,
			Temperature: 45.2,
			Cpus:        []*types.Cpu{generateMockCpu("route-processor")},
			MemoryModules: []*types.Memory{generateMockMemory("route-processor")},
		}

		// Interface Module
		interfaceModule := &types.Module{
			Id:          "module-int-1",
			Name:        "Interface Module 1",
			Model:       "ISR4431-4x10GE",
			Description: "4-Port 10GE Interface Module",
			ModuleType:  types.ModuleType_MODULE_TYPE_INTERFACE_MODULE,
			Status:      types.ComponentStatus_COMPONENT_STATUS_OK,
			Temperature: 40.1,
			Ports:       generateRouterPorts(),
		}

		modules = append(modules, routeProcessor, interfaceModule)

	case "firewall":
		// Management Processor
		managementProcessor := &types.Module{
			Id:          "module-mgmt",
			Name:        "Management Processor",
			Model:       "ASA5516-MGMT",
			Description: "Main Management Processor",
			ModuleType:  types.ModuleType_MODULE_TYPE_MANAGEMENT_PROCESSOR,
			Status:      types.ComponentStatus_COMPONENT_STATUS_OK,
			Temperature: 41.5,
			Cpus:        []*types.Cpu{generateMockCpu("management")},
			MemoryModules: []*types.Memory{generateMockMemory("management")},
		}

		// Security Processing Unit
		securityModule := &types.Module{
			Id:          "module-spu",
			Name:        "Security Processing Unit",
			Model:       "ASA5516-SPU",
			Description: "Hardware Security Processing",
			ModuleType:  types.ModuleType_MODULE_TYPE_SECURITY_PROCESSING_UNIT,
			Status:      types.ComponentStatus_COMPONENT_STATUS_OK,
			Temperature: 39.8,
		}

		modules = append(modules, managementProcessor, securityModule)

	default:
		// Basic Processor for unknown devices
		processor := &types.Module{
			Id:          "module-proc",
			Name:        "Main Processor",
			Model:       "GENERIC-PROC",
			Description: "Main Processing Unit",
			ModuleType:  types.ModuleType_MODULE_TYPE_UNKNOWN,
			Status:      types.ComponentStatus_COMPONENT_STATUS_OK,
			Temperature: 40.0,
			Cpus:        []*types.Cpu{generateMockCpu("generic")},
			MemoryModules: []*types.Memory{generateMockMemory("generic")},
		}

		modules = append(modules, processor)
	}

	return modules
}

func generateMockCpu(processorType string) *types.Cpu {
	cpu := &types.Cpu{
		Status:             types.ComponentStatus_COMPONENT_STATUS_OK,
		Temperature:        55.3,
		UtilizationPercent: 15.7,
	}

	switch processorType {
	case "supervisor":
		cpu.Id = "cpu-supervisor"
		cpu.Name = "Supervisor CPU"
		cpu.Model = "Intel Xeon E5-2690"
		cpu.Architecture = "x86_64"
		cpu.Cores = 8
		cpu.FrequencyMhz = 2900
	case "route-processor":
		cpu.Id = "cpu-rp"
		cpu.Name = "Route Processor CPU"
		cpu.Model = "Intel Core i7-8700"
		cpu.Architecture = "x86_64"
		cpu.Cores = 6
		cpu.FrequencyMhz = 3200
	case "management":
		cpu.Id = "cpu-mgmt"
		cpu.Name = "Management CPU"
		cpu.Model = "ARM Cortex-A72"
		cpu.Architecture = "arm64"
		cpu.Cores = 4
		cpu.FrequencyMhz = 1800
	default:
		cpu.Id = "cpu-generic"
		cpu.Name = "Generic CPU"
		cpu.Model = "Generic Processor"
		cpu.Architecture = "x86_64"
		cpu.Cores = 2
		cpu.FrequencyMhz = 2000
	}

	return cpu
}

func generateMockMemory(processorType string) *types.Memory {
	memory := &types.Memory{
		Status:             types.ComponentStatus_COMPONENT_STATUS_OK,
		Type:               "DDR4",
		FrequencyMhz:       2400,
		UtilizationPercent: 32.5,
	}

	switch processorType {
	case "supervisor":
		memory.Id = "memory-supervisor"
		memory.Name = "Supervisor Memory"
		memory.SizeBytes = 16 * 1024 * 1024 * 1024 // 16GB
	case "route-processor":
		memory.Id = "memory-rp"
		memory.Name = "Route Processor Memory"
		memory.SizeBytes = 8 * 1024 * 1024 * 1024 // 8GB
	case "management":
		memory.Id = "memory-mgmt"
		memory.Name = "Management Memory"
		memory.SizeBytes = 4 * 1024 * 1024 * 1024 // 4GB
	default:
		memory.Id = "memory-generic"
		memory.Name = "Generic Memory"
		memory.SizeBytes = 2 * 1024 * 1024 * 1024 // 2GB
	}

	return memory
}

func generateSwitchPorts() []*types.Port {
	var ports []*types.Port

	// Generate 48 ports for switch
	for i := 1; i <= 48; i++ {
		port := &types.Port{
			Id: fmt.Sprintf("port-%d", i),
			Interfaces: []*types.Interface{
				{
					Id:            fmt.Sprintf("interface-ge-0/0/%d", i),
					Name:          fmt.Sprintf("GigabitEthernet0/0/%d", i),
					Status:        "up",
					Description:   fmt.Sprintf("Port %d", i),
					InterfaceType: types.InterfaceType_INTERFACE_TYPE_GIGABIT_ETHERNET,
					Speed:         1000000000, // 1Gbps
					MacAddress:    fmt.Sprintf("00:1a:2b:3c:4d:%02x", i),
					Mtu:           1500,
					AdminStatus:   true,
					Statistics:    generateMockInterfaceStatistics(),
				},
			},
		}
		ports = append(ports, port)
	}

	return ports
}

func generateRouterPorts() []*types.Port {
	var ports []*types.Port

	// Generate 4 x 10GE ports for router
	for i := 1; i <= 4; i++ {
		port := &types.Port{
			Id: fmt.Sprintf("port-10ge-%d", i),
			Interfaces: []*types.Interface{
				{
					Id:            fmt.Sprintf("interface-te-0/1/%d", i),
					Name:          fmt.Sprintf("TenGigabitEthernet0/1/%d", i),
					Status:        "up",
					Description:   fmt.Sprintf("10GE Port %d", i),
					InterfaceType: types.InterfaceType_INTERFACE_TYPE_10GIGE,
					Speed:         10000000000, // 10Gbps
					MacAddress:    fmt.Sprintf("00:2a:3b:4c:5d:%02x", i),
					Mtu:           9000,
					AdminStatus:   true,
					Statistics:    generateMockInterfaceStatistics(),
				},
			},
		}
		ports = append(ports, port)
	}

	return ports
}

func generateMockPorts(deviceType string) []*types.Port {
	switch deviceType {
	case "switch":
		return generateSwitchPorts()
	case "router":
		return generateRouterPorts()
	case "firewall":
		var ports []*types.Port
		
		// 16 x 1GE ports
		for i := 1; i <= 16; i++ {
			port := &types.Port{
				Id: fmt.Sprintf("port-ge-%d", i),
				Interfaces: []*types.Interface{
					{
						Id:            fmt.Sprintf("interface-ge-0/0/%d", i),
						Name:          fmt.Sprintf("GigabitEthernet0/0/%d", i),
						Status:        "up",
						Description:   fmt.Sprintf("GE Port %d", i),
						InterfaceType: types.InterfaceType_INTERFACE_TYPE_GIGABIT_ETHERNET,
						Speed:         1000000000,
						MacAddress:    fmt.Sprintf("00:3a:4b:5c:6d:%02x", i),
						Mtu:           1500,
						AdminStatus:   true,
						Statistics:    generateMockInterfaceStatistics(),
					},
				},
			}
			ports = append(ports, port)
		}
		
		// 4 x 10GE ports
		for i := 1; i <= 4; i++ {
			port := &types.Port{
				Id: fmt.Sprintf("port-10ge-%d", i),
				Interfaces: []*types.Interface{
					{
						Id:            fmt.Sprintf("interface-te-0/1/%d", i),
						Name:          fmt.Sprintf("TenGigabitEthernet0/1/%d", i),
						Status:        "up",
						Description:   fmt.Sprintf("10GE Port %d", i),
						InterfaceType: types.InterfaceType_INTERFACE_TYPE_10GIGE,
						Speed:         10000000000,
						MacAddress:    fmt.Sprintf("00:4a:5b:6c:7d:%02x", i),
						Mtu:           9000,
						AdminStatus:   true,
						Statistics:    generateMockInterfaceStatistics(),
					},
				},
			}
			ports = append(ports, port)
		}
		
		return ports
	default:
		// Single network interface for generic device
		return []*types.Port{
			{
				Id: "port-1",
				Interfaces: []*types.Interface{
					{
						Id:            "interface-eth-0",
						Name:          "eth0",
						Status:        "up",
						Description:   "Primary Network Interface",
						InterfaceType: types.InterfaceType_INTERFACE_TYPE_ETHERNET,
						Speed:         1000000000,
						MacAddress:    "00:5a:6b:7c:8d:9e",
						IpAddress:     "192.168.1.100",
						Mtu:           1500,
						AdminStatus:   true,
						Statistics:    generateMockInterfaceStatistics(),
					},
				},
			},
		}
	}
}

func generateMockPowerSupplies(deviceType string) []*types.PowerSupply {
	var supplies []*types.PowerSupply

	switch deviceType {
	case "switch":
		// 2 x 1100W Power Supplies
		for i := 1; i <= 2; i++ {
			supply := &types.PowerSupply{
				Id:           fmt.Sprintf("psu-%d", i),
				Name:         fmt.Sprintf("Power Supply %d", i),
				Model:        "PWR-C1-1100WAC",
				SerialNumber: fmt.Sprintf("PSU-SW-%03d", i),
				Wattage:      1100,
				PowerType:    types.PowerType_POWER_TYPE_AC,
				Status:       types.ComponentStatus_COMPONENT_STATUS_OK,
				Temperature:  45.2,
				LoadPercent:  35.8,
				Voltage:      230.0,
				Current:      4.8,
			}
			supplies = append(supplies, supply)
		}
	case "router":
		// 1 x 2000W Power Supply
		supply := &types.PowerSupply{
			Id:           "psu-1",
			Name:         "Power Supply 1",
			Model:        "PWR-4430-AC",
			SerialNumber: "PSU-RT-001",
			Wattage:      2000,
			PowerType:    types.PowerType_POWER_TYPE_AC,
			Status:       types.ComponentStatus_COMPONENT_STATUS_OK,
			Temperature:  42.1,
			LoadPercent:  28.5,
			Voltage:      230.0,
			Current:      5.2,
		}
		supplies = append(supplies, supply)
	default:
		// Generic 500W Power Supply
		supply := &types.PowerSupply{
			Id:           "psu-1",
			Name:         "Power Supply 1",
			Model:        "PWR-GENERIC-500W",
			SerialNumber: "PSU-GN-001",
			Wattage:      500,
			PowerType:    types.PowerType_POWER_TYPE_AC,
			Status:       types.ComponentStatus_COMPONENT_STATUS_OK,
			Temperature:  40.0,
			LoadPercent:  45.0,
			Voltage:      230.0,
			Current:      2.2,
		}
		supplies = append(supplies, supply)
	}

	return supplies
}

func generateMockFans(deviceType string) []*types.Fan {
	var fans []*types.Fan

	switch deviceType {
	case "switch":
		// Fan Tray with 4 fans
		for i := 1; i <= 4; i++ {
			fan := &types.Fan{
				Id:            fmt.Sprintf("fan-%d", i),
				Name:          fmt.Sprintf("Fan %d", i),
				Description:   fmt.Sprintf("Cooling Fan %d", i),
				Status:        types.ComponentStatus_COMPONENT_STATUS_OK,
				SpeedRpm:      3500,
				MaxSpeedRpm:   5000,
				Temperature:   35.0,
				VariableSpeed: true,
			}
			fans = append(fans, fan)
		}
	default:
		// Single cooling fan for other devices
		fan := &types.Fan{
			Id:            "fan-1",
			Name:          "Cooling Fan",
			Description:   "Main Cooling Fan",
			Status:        types.ComponentStatus_COMPONENT_STATUS_OK,
			SpeedRpm:      2800,
			MaxSpeedRpm:   4000,
			Temperature:   38.0,
			VariableSpeed: true,
		}
		fans = append(fans, fan)
	}

	return fans
}

func generateMockPerformanceMetrics() *types.PerformanceMetrics {
	return &types.PerformanceMetrics{
		CpuUsagePercent:    15.7,
		MemoryUsagePercent: 32.5,
		TemperatureCelsius: 42.3,
		Uptime:             "45d 12h 30m",
		LoadAverage:        1500,
		Processes:          generateMockProcesses(),
	}
}

func generateMockProcesses() []*types.ProcessInfo {
	processes := []*types.ProcessInfo{
		{
			Name:          "kernel",
			Pid:           1,
			CpuPercent:    0.1,
			MemoryPercent: 0.5,
			Status:        "running",
		},
		{
			Name:          "network-daemon",
			Pid:           1234,
			CpuPercent:    5.2,
			MemoryPercent: 12.3,
			Status:        "running",
		},
		{
			Name:          "routing-engine",
			Pid:           2345,
			CpuPercent:    8.7,
			MemoryPercent: 15.8,
			Status:        "running",
		},
		{
			Name:          "management-interface",
			Pid:           3456,
			CpuPercent:    1.2,
			MemoryPercent: 3.4,
			Status:        "running",
		},
	}

	return processes
}

func generateMockInterfaceStatistics() *types.InterfaceStatistics {
	return &types.InterfaceStatistics{
		RxPackets:  12345678,
		TxPackets:  9876543,
		RxBytes:    1234567890,
		TxBytes:    987654321,
		RxErrors:   12,
		TxErrors:   8,
		RxDrops:    3,
		TxDrops:    1,
		Collisions: 0,
	}
}

func generateMockLogical() *types.Logical {
	logical := &types.Logical{
		Id:        "logical-0",
		Intefaces: generateMockInterfaces(),
	}

	return logical
}

func generateMockInterfaces() []*types.Interface {
	interfaces := []*types.Interface{
		{
			Id:            "interface-vlan-1",
			Name:          "Vlan1",
			Status:        "up",
			Description:   "Management VLAN",
			InterfaceType: types.InterfaceType_INTERFACE_TYPE_VLAN,
			IpAddress:     "192.168.1.1",
			Mtu:           1500,
			AdminStatus:   true,
			Statistics:    generateMockInterfaceStatistics(),
		},
		{
			Id:            "interface-loopback-0",
			Name:          "Loopback0",
			Status:        "up",
			Description:   "Loopback Interface",
			InterfaceType: types.InterfaceType_INTERFACE_TYPE_LOOPBACK,
			IpAddress:     "10.1.1.1",
			Mtu:           1514,
			AdminStatus:   true,
			Statistics:    generateMockInterfaceStatistics(),
		},
	}

	return interfaces
}

func generateMockNetworkTopology(deviceID string) *types.NetworkTopology {
	now := time.Now().Format(time.RFC3339)
	
	return &types.NetworkTopology{
		TopologyId:   fmt.Sprintf("topology-%s", deviceID),
		Name:         "Network Topology",
		TopologyType: types.TopologyType_TOPOLOGY_TYPE_PHYSICAL,
		Nodes:        generateMockNetworkNodes(deviceID),
		Edges:        generateMockNetworkEdges(),
		GeographicBounds: &types.GeographicBounds{
			NorthEast: &types.GeographicCoordinates{
				Latitude:  37.7849,
				Longitude: -122.4094,
			},
			SouthWest: &types.GeographicCoordinates{
				Latitude:  37.7649,
				Longitude: -122.4294,
			},
			Center: &types.GeographicCoordinates{
				Latitude:  37.7749,
				Longitude: -122.4194,
			},
			ZoomLevel: 12,
		},
		Statistics:   generateMockTopologyStatistics(),
		HealthStatus: generateMockTopologyHealth(),
		LastUpdated:  now,
	}
}

func generateMockNetworkNodes(deviceID string) []*types.NetworkNode {
	nodes := []*types.NetworkNode{
		{
			NodeId:   deviceID,
			Name:     fmt.Sprintf("Node-%s", deviceID),
			NodeType: types.NetworkNodeType_NETWORK_NODE_TYPE_SWITCH,
			Status:   types.NetworkNodeStatus_NODE_STATUS_ONLINE,
			Location: "Data Center A",
			Coordinates: &types.GeographicCoordinates{
				Latitude:  37.7749,
				Longitude: -122.4194,
			},
			Interfaces: []string{"ge-0/0/1", "ge-0/0/2", "ge-0/0/3"},
			Capabilities: &types.NodeCapabilities{
				Protocols:             []string{"OSPF", "BGP", "LACP"},
				Services:              []string{"switching", "routing"},
				MaxThroughputBps:      48000000000, // 48Gbps
				MaxConnections:        1000,
				RoutingCapable:        true,
				SwitchingCapable:      true,
				FirewallCapable:       false,
				LoadBalancingCapable:  false,
			},
			Metrics: &types.NodeMetrics{
				CpuUtilization:     15.7,
				MemoryUtilization:  32.5,
				PacketsForwarded:   1234567890,
				PacketsDropped:     12345,
				BytesProcessed:     9876543210,
				ActiveConnections:  125,
				Temperature:        42.3,
				Uptime:            "45d 12h 30m",
			},
			Region: "US-West",
			Tier:   2,
		},
	}

	return nodes
}

func generateMockNetworkEdges() []*types.NetworkEdge {
	edges := []*types.NetworkEdge{
		{
			EdgeId:     "edge-1",
			SourceNode: "node-1",
			TargetNode: "node-2",
			EdgeType:   types.EdgeType_EDGE_TYPE_PHYSICAL,
			Status:     types.EdgeStatus_EDGE_STATUS_UP,
			Properties: &types.EdgeProperties{
				Weight: 1.0,
				Cost:   100,
				Label:  "Primary Link",
				Attributes: map[string]string{
					"bandwidth": "1Gbps",
					"protocol":  "Ethernet",
				},
			},
			Metrics: []*types.EdgeMetric{
				{
					MetricName: "utilization",
					Value:      25.5,
					Unit:       "percent",
					Timestamp:  time.Now().Format(time.RFC3339),
				},
			},
		},
	}

	return edges
}

func generateMockNetworkLinks(deviceID string) []*types.NetworkLink {
	links := []*types.NetworkLink{
		{
			LinkId:        fmt.Sprintf("link-%s-1", deviceID),
			Name:          "Primary Uplink",
			FromNode:      deviceID,
			ToNode:        "core-switch-1",
			LinkStatus:    types.LinkStatus_LINK_STATUS_ACTIVE,
			Bandwidth:     "10Gbps",
			LinkType:      types.LinkType_LINK_TYPE_ETHERNET,
			Metrics: &types.LinkMetrics{
				BytesTransmitted:   9876543210,
				BytesReceived:      8765432109,
				PacketsTransmitted: 87654321,
				PacketsReceived:    76543210,
				ErrorCount:         12,
				DropCount:          3,
				JitterMs:           0.5,
				PacketLossPercent:  0.01,
				ThroughputBps:      8500000000, // 8.5Gbps
				LastMeasurement:    time.Now().Format(time.RFC3339),
			},
			UtilizationPercent:    85.0,
			LatencyMs:             2.3,
			DistanceKm:            0.5,
			Uptime:                "45d 12h 30m",
			ErrorRate:             0.001,
			AvailabilityPercent:   99.95,
		},
	}

	return links
}

func generateMockNetworkHealth() *types.NetworkHealth {
	now := time.Now().Format(time.RFC3339)
	
	return &types.NetworkHealth{
		OverallStatus:             types.HealthStatus_HEALTH_STATUS_HEALTHY,
		TotalDevices:              100,
		OnlineDevices:             98,
		OfflineDevices:            1,
		WarningDevices:            1,
		CriticalDevices:           0,
		TotalLinks:                150,
		ActiveLinks:               148,
		InactiveLinks:             1,
		WarningLinks:              1,
		NetworkAvailabilityPercent: 99.2,
		Alerts:                    generateMockHealthAlerts(),
		LastHealthCheck:           now,
	}
}

func generateMockHealthAlerts() []*types.HealthAlert {
	now := time.Now().Format(time.RFC3339)
	
	alerts := []*types.HealthAlert{
		{
			AlertId:           "alert-001",
			Severity:          types.AlertSeverity_ALERT_SEVERITY_WARNING,
			Title:             "High Interface Utilization",
			Description:       "Interface utilization exceeded 80% threshold",
			AffectedComponent: "ge-0/0/1",
			ComponentType:     types.ComponentType_COMPONENT_TYPE_INTERFACE,
			Timestamp:         now,
			Acknowledged:      false,
		},
	}

	return alerts
}

func generateMockTopologyStatistics() *types.TopologyStatistics {
	return &types.TopologyStatistics{
		TotalNodes:            100,
		TotalEdges:            150,
		ActiveNodes:           98,
		ActiveEdges:           148,
		NetworkDensity:        0.75,
		ConnectedComponents:   1,
		AverageDegree:         3.0,
		MaxDegree:            12,
		ClusteringCoefficient: 0.65,
	}
}

func generateMockTopologyHealth() *types.TopologyHealth {
	now := time.Now().Format(time.RFC3339)
	
	return &types.TopologyHealth{
		Status:      types.HealthStatus_HEALTH_STATUS_HEALTHY,
		HealthScore: 95.5,
		Issues:      []*types.HealthIssue{},
		Recommendations: []*types.HealthRecommendation{
			{
				RecommendationId: "rec-001",
				Type:            types.RecommendationType_RECOMMENDATION_TYPE_OPTIMIZATION,
				Title:           "Network Optimization",
				Description:     "Consider load balancing traffic across redundant links",
				Priority:        types.RecommendationPriority_RECOMMENDATION_PRIORITY_MEDIUM,
				TargetComponent: "network-core",
				ActionItems:     []string{"Enable ECMP", "Configure link aggregation"},
			},
		},
		AssessmentTime: now,
	}
}

// deviceMockData represents the exact mock data from the device application
type deviceMockData struct {
	id           int
	name         string
	ipAddress    string
	deviceType   string
	location     string
	latitude     float64
	longitude    float64
	status       string
	cpuUsage     int
	memoryUsage  int
	uptime       string
	lastSeen     string
	model        string
	serialNumber string
	firmware     string
	interfaces   int
	temperature  int
}

// getExactDeviceMockData returns the exact same 19 devices from the device application
func getExactDeviceMockData() []deviceMockData {
	return []deviceMockData{
		{
			id: 1, name: "Core-Switch-01", ipAddress: "192.168.1.10", deviceType: "Switch",
			location: "Data Center A", latitude: 37.7749, longitude: -122.4194,
			status: "online", cpuUsage: 25, memoryUsage: 45, uptime: "45d 12h 30m",
			lastSeen: "2025-08-03 14:30:00", model: "Cisco Catalyst 9500",
			serialNumber: "CAT9500-001", firmware: "16.12.04", interfaces: 48, temperature: 42,
		},
		{
			id: 2, name: "NY-CORE-01", ipAddress: "192.168.1.1", deviceType: "Router",
			location: "New York, USA", latitude: 40.7128, longitude: -74.0060,
			status: "online", cpuUsage: 67, memoryUsage: 78, uptime: "23d 8h 15m",
			lastSeen: "2025-08-03 14:29:45", model: "Juniper MX240",
			serialNumber: "JNP-MX240-002", firmware: "20.4R3.8", interfaces: 24, temperature: 38,
		},
		{
			id: 3, name: "LA-CORE-02", ipAddress: "192.168.50.15", deviceType: "Router",
			location: "Los Angeles, USA", latitude: 34.0522, longitude: -118.2426,
			status: "online", cpuUsage: 15, memoryUsage: 32, uptime: "89d 14h 22m",
			lastSeen: "2025-08-03 14:31:00", model: "Cisco ASR 9000",
			serialNumber: "ASR9000-001", firmware: "7.3.2", interfaces: 36, temperature: 35,
		},
		{
			id: 4, name: "CHI-SW-01", ipAddress: "10.0.0.1", deviceType: "Switch",
			location: "Chicago, USA", latitude: 41.8781, longitude: -87.6298,
			status: "online", cpuUsage: 89, memoryUsage: 92, uptime: "127d 3h 45m",
			lastSeen: "2025-08-03 14:30:00", model: "Palo Alto PA-3220",
			serialNumber: "PA3220-001", firmware: "10.1.6", interfaces: 16, temperature: 55,
		},
		{
			id: 5, name: "TOR-FW-01", ipAddress: "192.168.2.1", deviceType: "Firewall",
			location: "Toronto, Canada", latitude: 43.6532, longitude: -79.3832,
			status: "warning", cpuUsage: 76, memoryUsage: 83, uptime: "45d 18h 12m",
			lastSeen: "2025-08-03 14:25:30", model: "Fortinet FortiGate 600E",
			serialNumber: "FGT600E-001", firmware: "7.2.4", interfaces: 20, temperature: 48,
		},
		{
			id: 6, name: "LON-CORE-01", ipAddress: "192.168.100.1", deviceType: "Router",
			location: "London, UK", latitude: 51.5074, longitude: -0.1278,
			status: "online", cpuUsage: 34, memoryUsage: 56, uptime: "156d 7h 33m",
			lastSeen: "2025-08-03 14:32:15", model: "Juniper MX960",
			serialNumber: "JNP-MX960-001", firmware: "21.4R1.12", interfaces: 80, temperature: 41,
		},
		{
			id: 7, name: "PAR-SW-01", ipAddress: "192.168.101.1", deviceType: "Switch",
			location: "Paris, France", latitude: 48.8566, longitude: 2.3522,
			status: "online", cpuUsage: 28, memoryUsage: 44, uptime: "98d 23h 45m",
			lastSeen: "2025-08-03 14:31:45", model: "Cisco Nexus 9500",
			serialNumber: "N9K-9500-001", firmware: "9.3.8", interfaces: 64, temperature: 39,
		},
		{
			id: 8, name: "FRA-CORE-02", ipAddress: "192.168.102.1", deviceType: "Router",
			location: "Frankfurt, Germany", latitude: 50.1109, longitude: 8.6821,
			status: "online", cpuUsage: 42, memoryUsage: 67, uptime: "203d 11h 18m",
			lastSeen: "2025-08-03 14:33:00", model: "Huawei NE8000 X16",
			serialNumber: "NE8000-001", firmware: "8.20.10", interfaces: 96, temperature: 43,
		},
		{
			id: 9, name: "AMS-SRV-01", ipAddress: "192.168.103.1", deviceType: "Server",
			location: "Amsterdam, Netherlands", latitude: 52.3676, longitude: 4.9041,
			status: "online", cpuUsage: 18, memoryUsage: 35, uptime: "87d 14h 56m",
			lastSeen: "2025-08-03 14:32:30", model: "Dell PowerEdge R750",
			serialNumber: "PE-R750-001", firmware: "2.8.2", interfaces: 4, temperature: 32,
		},
		{
			id: 10, name: "TYO-CORE-01", ipAddress: "192.168.200.1", deviceType: "Router",
			location: "Tokyo, Japan", latitude: 35.6762, longitude: 139.6503,
			status: "online", cpuUsage: 52, memoryUsage: 74, uptime: "145d 9h 27m",
			lastSeen: "2025-08-03 14:34:00", model: "NEC IX3315",
			serialNumber: "IX3315-001", firmware: "10.7.22", interfaces: 48, temperature: 46,
		},
		{
			id: 11, name: "SIN-SW-01", ipAddress: "192.168.201.1", deviceType: "Switch",
			location: "Singapore", latitude: 1.3521, longitude: 103.8198,
			status: "online", cpuUsage: 31, memoryUsage: 48, uptime: "76d 19h 41m",
			lastSeen: "2025-08-03 14:33:45", model: "Arista 7280R3",
			serialNumber: "AR-7280R3-001", firmware: "4.29.2F", interfaces: 32, temperature: 38,
		},
		{
			id: 12, name: "MUM-FW-01", ipAddress: "192.168.202.1", deviceType: "Firewall",
			location: "Mumbai, India", latitude: 19.0760, longitude: 72.8777,
			status: "offline", cpuUsage: 0, memoryUsage: 0, uptime: "0m",
			lastSeen: "2025-08-03 11:15:22", model: "Check Point 15600",
			serialNumber: "CP-15600-001", firmware: "R81.20", interfaces: 24, temperature: 0,
		},
		{
			id: 13, name: "SEO-SRV-01", ipAddress: "192.168.203.1", deviceType: "Server",
			location: "Seoul, South Korea", latitude: 37.5665, longitude: 126.9780,
			status: "warning", cpuUsage: 78, memoryUsage: 91, uptime: "34d 6h 15m",
			lastSeen: "2025-08-03 14:28:15", model: "HPE ProLiant DL380 Gen10",
			serialNumber: "HP-DL380-001", firmware: "2.65", interfaces: 4, temperature: 51,
		},
		{
			id: 14, name: "SYD-CORE-01", ipAddress: "192.168.300.1", deviceType: "Router",
			location: "Sydney, Australia", latitude: -33.8688, longitude: 151.2093,
			status: "online", cpuUsage: 39, memoryUsage: 62, uptime: "167d 22h 8m",
			lastSeen: "2025-08-03 14:35:00", model: "Cisco CRS-X",
			serialNumber: "CRS-X-001", firmware: "6.7.3", interfaces: 144, temperature: 44,
		},
		{
			id: 15, name: "MEL-SW-01", ipAddress: "192.168.301.1", deviceType: "Switch",
			location: "Melbourne, Australia", latitude: -37.8136, longitude: 144.9631,
			status: "online", cpuUsage: 22, memoryUsage: 38, uptime: "124d 16h 52m",
			lastSeen: "2025-08-03 14:34:30", model: "Extreme Networks VSP 4450",
			serialNumber: "EX-VSP4450-001", firmware: "8.10.1", interfaces: 48, temperature: 36,
		},
		{
			id: 16, name: "SAO-CORE-01", ipAddress: "192.168.400.1", deviceType: "Router",
			location: "São Paulo, Brazil", latitude: -23.5505, longitude: -46.6333,
			status: "online", cpuUsage: 45, memoryUsage: 69, uptime: "89d 4h 33m",
			lastSeen: "2025-08-03 14:31:15", model: "Nokia 7750 SR-12",
			serialNumber: "NK-7750-001", firmware: "20.10.R5", interfaces: 72, temperature: 47,
		},
		{
			id: 17, name: "BOG-FW-01", ipAddress: "192.168.401.1", deviceType: "Firewall",
			location: "Bogotá, Colombia", latitude: 4.7110, longitude: -74.0721,
			status: "warning", cpuUsage: 68, memoryUsage: 82, uptime: "56d 12h 19m",
			lastSeen: "2025-08-03 14:29:00", model: "SonicWall NSa 6700",
			serialNumber: "SW-NSa6700-001", firmware: "7.0.1-5050", interfaces: 16, temperature: 49,
		},
		{
			id: 18, name: "CAI-SW-01", ipAddress: "192.168.500.1", deviceType: "Switch",
			location: "Cairo, Egypt", latitude: 30.0444, longitude: 31.2357,
			status: "online", cpuUsage: 33, memoryUsage: 51, uptime: "78d 8h 44m",
			lastSeen: "2025-08-03 14:32:45", model: "D-Link DGS-3630-52TC",
			serialNumber: "DL-DGS3630-001", firmware: "3.00.B012", interfaces: 52, temperature: 41,
		},
		{
			id: 19, name: "CPT-SRV-01", ipAddress: "192.168.501.1", deviceType: "Server",
			location: "Cape Town, South Africa", latitude: -33.9249, longitude: 18.4241,
			status: "online", cpuUsage: 26, memoryUsage: 43, uptime: "145d 17h 26m",
			lastSeen: "2025-08-03 14:33:15", model: "IBM Power System S922",
			serialNumber: "IBM-S922-001", firmware: "FW940.21", interfaces: 4, temperature: 38,
		},
	}
}

// convertDeviceTypeToProto converts string device type to protobuf enum
func convertDeviceTypeToProto(deviceType string) types.DeviceType {
	switch deviceType {
	case "Router":
		return types.DeviceType_DEVICE_TYPE_ROUTER
	case "Switch":
		return types.DeviceType_DEVICE_TYPE_SWITCH
	case "Firewall":
		return types.DeviceType_DEVICE_TYPE_FIREWALL
	case "Server":
		return types.DeviceType_DEVICE_TYPE_SERVER
	default:
		return types.DeviceType_DEVICE_TYPE_UNKNOWN
	}
}

// convertStatusToProto converts string status to protobuf enum
func convertStatusToProto(status string) types.DeviceStatus {
	switch status {
	case "online":
		return types.DeviceStatus_DEVICE_STATUS_ONLINE
	case "offline":
		return types.DeviceStatus_DEVICE_STATUS_OFFLINE
	case "warning":
		return types.DeviceStatus_DEVICE_STATUS_WARNING
	default:
		return types.DeviceStatus_DEVICE_STATUS_UNKNOWN
	}
}

// parseVendorFromModel extracts vendor name from model string
func parseVendorFromModel(model string) string {
	if strings.Contains(model, "Cisco") {
		return "Cisco"
	}
	if strings.Contains(model, "Juniper") {
		return "Juniper"
	}
	if strings.Contains(model, "Palo Alto") {
		return "Palo Alto Networks"
	}
	if strings.Contains(model, "Fortinet") {
		return "Fortinet"
	}
	if strings.Contains(model, "Huawei") {
		return "Huawei"
	}
	if strings.Contains(model, "Dell") {
		return "Dell"
	}
	if strings.Contains(model, "NEC") {
		return "NEC"
	}
	if strings.Contains(model, "Arista") {
		return "Arista"
	}
	if strings.Contains(model, "Check Point") {
		return "Check Point"
	}
	if strings.Contains(model, "HPE") {
		return "Hewlett Packard Enterprise"
	}
	if strings.Contains(model, "Nokia") {
		return "Nokia"
	}
	if strings.Contains(model, "SonicWall") {
		return "SonicWall"
	}
	if strings.Contains(model, "D-Link") {
		return "D-Link"
	}
	if strings.Contains(model, "IBM") {
		return "IBM"
	}
	if strings.Contains(model, "Extreme") {
		return "Extreme Networks"
	}
	return "Unknown"
}

// convertMockDataToNetworkDevice converts deviceMockData to NetworkDevice protobuf
func convertMockDataToNetworkDevice(mockData deviceMockData) *types.NetworkDevice {
	deviceID := fmt.Sprintf("device-%03d", mockData.id)
	vendor := parseVendorFromModel(mockData.model)
	
	// Create equipment info with the exact mock data
	info := &types.EquipmentInfo{
		Vendor:          vendor,
		Model:           mockData.model,
		SerialNumber:    mockData.serialNumber,
		FirmwareVersion: mockData.firmware,
		SysName:         mockData.name,
		IpAddress:       mockData.ipAddress,
		DeviceType:      convertDeviceTypeToProto(mockData.deviceType),
		DeviceStatus:    convertStatusToProto(mockData.status),
		Location:        mockData.location,
		Latitude:        mockData.latitude,
		Longitude:       mockData.longitude,
		LastSeen:        mockData.lastSeen,
		Uptime:          mockData.uptime,
		Version:         mockData.firmware,
	}
	
	// Parse series and family from model
	switch vendor {
	case "Cisco":
		if strings.Contains(mockData.model, "Catalyst") {
			info.Series = "Catalyst"
			info.Family = "9500"
		} else if strings.Contains(mockData.model, "ASR") {
			info.Series = "ASR"
			info.Family = "9000"
		} else if strings.Contains(mockData.model, "Nexus") {
			info.Series = "Nexus"
			info.Family = "9500"
		} else if strings.Contains(mockData.model, "CRS") {
			info.Series = "CRS"
			info.Family = "X"
		}
		info.Software = "Cisco IOS XE"
	case "Juniper":
		info.Series = "MX"
		if strings.Contains(mockData.model, "MX240") {
			info.Family = "240"
		} else {
			info.Family = "960"
		}
		info.Software = "Junos OS"
	case "Palo Alto Networks":
		info.Series = "PA"
		info.Family = "3220"
		info.Software = "PAN-OS"
	case "Fortinet":
		info.Series = "FortiGate"
		info.Family = "600E"
		info.Software = "FortiOS"
	case "Huawei":
		info.Series = "NE8000"
		info.Family = "X16"
		info.Software = "VRP"
	case "Dell":
		info.Series = "PowerEdge"
		info.Family = "R750"
		info.Software = "iDRAC"
	case "NEC":
		info.Series = "IX"
		info.Family = "3315"
		info.Software = "IX Series Software"
	case "Arista":
		info.Series = "7280R3"
		info.Family = "7280"
		info.Software = "EOS"
	case "Check Point":
		info.Series = "15600"
		info.Family = "15000"
		info.Software = "GAiA"
	case "Hewlett Packard Enterprise":
		info.Series = "ProLiant"
		info.Family = "DL380"
		info.Software = "iLO"
	case "Nokia":
		info.Series = "7750"
		info.Family = "SR-12"
		info.Software = "SR OS"
	case "SonicWall":
		info.Series = "NSa"
		info.Family = "6700"
		info.Software = "SonicOS"
	case "D-Link":
		info.Series = "DGS"
		info.Family = "3630"
		info.Software = "D-Link OS"
	case "IBM":
		info.Series = "Power System"
		info.Family = "S922"
		info.Software = "AIX"
	case "Extreme Networks":
		info.Series = "VSP"
		info.Family = "4450"
		info.Software = "VOSS"
	}

	device := &types.NetworkDevice{
		Id:            deviceID,
		Info:          info,
		Physicals:     make(map[string]*types.Physical),
		Logicals:      make(map[string]*types.Logical),
		Topology:      generateMockNetworkTopology(deviceID),
		NetworkLinks:  generateMockNetworkLinks(deviceID),
		NetworkHealth: generateMockNetworkHealth(),
	}

	// Generate physical components with realistic data based on the actual device specs
	deviceTypeForGeneration := strings.ToLower(mockData.deviceType)
	if deviceTypeForGeneration == "server" {
		deviceTypeForGeneration = "generic" // Use generic template for servers
	}
	
	physical := generateMockPhysicalForRealDevice(deviceTypeForGeneration, mockData)
	device.Physicals["physical-0"] = physical

	// Generate logical components
	logical := generateMockLogical()
	device.Logicals["logical-0"] = logical

	return device
}

// generateMockPhysicalForRealDevice creates physical components with real device metrics
func generateMockPhysicalForRealDevice(deviceType string, mockData deviceMockData) *types.Physical {
	physical := &types.Physical{
		Id:       "physical-0",
		Chassis:  []*types.Chassis{generateMockChassisForRealDevice(deviceType, mockData)},
		Ports:    generateMockPortsForRealDevice(deviceType, mockData.interfaces),
		PowerSupplies: generateMockPowerSupplies(deviceType),
		Fans:     generateMockFans(deviceType),
		Performance: &types.PerformanceMetrics{
			CpuUsagePercent:    float64(mockData.cpuUsage),
			MemoryUsagePercent: float64(mockData.memoryUsage),
			TemperatureCelsius: float64(mockData.temperature),
			Uptime:             mockData.uptime,
			LoadAverage:        uint64(mockData.cpuUsage * 10), // Approximation
			Processes:          generateMockProcesses(),
		},
	}

	return physical
}

// generateMockChassisForRealDevice creates chassis with real device data
func generateMockChassisForRealDevice(deviceType string, mockData deviceMockData) *types.Chassis {
	chassis := &types.Chassis{
		Id:           "chassis-0",
		SerialNumber: mockData.serialNumber,
		Model:        mockData.model,
		Description:  fmt.Sprintf("%s - %s", mockData.name, mockData.model),
		Status:       types.ComponentStatus_COMPONENT_STATUS_OK,
		Temperature:  float64(mockData.temperature),
		Modules:      generateMockModules(deviceType),
		Ports:        generateMockPortsForRealDevice(deviceType, mockData.interfaces),
	}

	// Adjust status based on device status
	switch mockData.status {
	case "offline":
		chassis.Status = types.ComponentStatus_COMPONENT_STATUS_OFFLINE
	case "warning":
		chassis.Status = types.ComponentStatus_COMPONENT_STATUS_WARNING
	default:
		chassis.Status = types.ComponentStatus_COMPONENT_STATUS_OK
	}

	return chassis
}

// generateMockPortsForRealDevice creates the exact number of ports as specified in mock data
func generateMockPortsForRealDevice(deviceType string, interfaceCount int) []*types.Port {
	var ports []*types.Port

	// Generate the exact number of interfaces as specified in the mock data
	for i := 1; i <= interfaceCount; i++ {
		var interfaceType types.InterfaceType
		var speed uint64
		var name string

		// Determine interface type based on device type and interface number
		switch deviceType {
		case "switch":
			if i <= 48 {
				interfaceType = types.InterfaceType_INTERFACE_TYPE_GIGABIT_ETHERNET
				speed = 1000000000 // 1Gbps
				name = fmt.Sprintf("GigabitEthernet0/0/%d", i)
			} else {
				interfaceType = types.InterfaceType_INTERFACE_TYPE_10GIGE
				speed = 10000000000 // 10Gbps
				name = fmt.Sprintf("TenGigabitEthernet0/1/%d", i-48)
			}
		case "router":
			if interfaceCount > 50 {
				// High-end routers with mixed interfaces
				if i <= interfaceCount/2 {
					interfaceType = types.InterfaceType_INTERFACE_TYPE_GIGABIT_ETHERNET
					speed = 1000000000
					name = fmt.Sprintf("GigabitEthernet0/0/%d", i)
				} else {
					interfaceType = types.InterfaceType_INTERFACE_TYPE_10GIGE
					speed = 10000000000
					name = fmt.Sprintf("TenGigabitEthernet0/1/%d", i-interfaceCount/2)
				}
			} else {
				// Mid-range routers
				interfaceType = types.InterfaceType_INTERFACE_TYPE_10GIGE
				speed = 10000000000
				name = fmt.Sprintf("TenGigabitEthernet0/1/%d", i)
			}
		case "firewall":
			if i <= 16 {
				interfaceType = types.InterfaceType_INTERFACE_TYPE_GIGABIT_ETHERNET
				speed = 1000000000
				name = fmt.Sprintf("GigabitEthernet0/0/%d", i)
			} else {
				interfaceType = types.InterfaceType_INTERFACE_TYPE_10GIGE
				speed = 10000000000
				name = fmt.Sprintf("TenGigabitEthernet0/1/%d", i-16)
			}
		default: // server or generic
			interfaceType = types.InterfaceType_INTERFACE_TYPE_GIGABIT_ETHERNET
			speed = 1000000000
			name = fmt.Sprintf("eth%d", i-1)
		}

		port := &types.Port{
			Id: fmt.Sprintf("port-%d", i),
			Interfaces: []*types.Interface{
				{
					Id:            fmt.Sprintf("interface-%d", i),
					Name:          name,
					Status:        "up",
					Description:   fmt.Sprintf("Interface %d", i),
					InterfaceType: interfaceType,
					Speed:         speed,
					MacAddress:    fmt.Sprintf("00:1a:2b:3c:%02x:%02x", i/256, i%256),
					Mtu:           1500,
					AdminStatus:   true,
					Statistics:    generateMockInterfaceStatistics(),
				},
			},
		}
		ports = append(ports, port)
	}

	return ports
}

// GenerateExactDeviceTableMockData creates the exact same 19 devices from the device application
func GenerateExactDeviceTableMockData() *types.NetworkDeviceList {
	mockDevices := getExactDeviceMockData()
	var devices []*types.NetworkDevice

	for _, mockDevice := range mockDevices {
		device := convertMockDataToNetworkDevice(mockDevice)
		devices = append(devices, device)
	}

	return &types.NetworkDeviceList{
		List: devices,
	}
}

// GenerateMockNetworkDeviceList creates a list of mock network devices (kept for backward compatibility)
func GenerateMockNetworkDeviceList(count int) *types.NetworkDeviceList {
	deviceTypes := []string{"switch", "router", "firewall"}
	var devices []*types.NetworkDevice

	for i := 0; i < count; i++ {
		deviceType := deviceTypes[i%len(deviceTypes)]
		deviceID := fmt.Sprintf("device-%03d", i+1)
		device := GenerateMockNetworkDevice(deviceID, deviceType)
		devices = append(devices, device)
	}

	return &types.NetworkDeviceList{
		List: devices,
	}
}
