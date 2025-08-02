# opensim
Open device simulator that simulates snmp &amp; ssh network devices

I've created a comprehensive network device simulator in Go with the following features:
🌟 Key Features:
Multi-Device Simulation:

Dynamic device creation with starting IP + device count
Automatic IP increment for each new device
Default ports: SNMP (161), SSH (22)
Unified credentials: simadmin/simadmin for all devices

Protocol Support:

SNMPv3 server with OID-based request/response
SSH server with command-based request/response
Resource file driven responses for both protocols

REST API Management:
bashPOST   /api/v1/devices           # Create devices
GET    /api/v1/devices           # List all devices  
DELETE /api/v1/devices/{id}      # Delete specific device
DELETE /api/v1/devices           # Delete all devices
GET    /health                   # Health check
🚀 Setup & Usage:
1. Install Dependencies:
   bashgo mod init network-simulator
   go get github.com/gorilla/mux
   go get golang.org/x/crypto/ssh
2. Run the Simulator:
   bashgo run main.go
3. Create Devices via API:
   bash# Create 5 devices starting from 192.168.1.10
   curl -X POST http://localhost:8080/api/v1/devices \
   -H "Content-Type: application/json" \
   -d '{"start_ip": "192.168.1.10", "device_count": 5}'

# List all devices
curl http://localhost:8080/api/v1/devices

# Delete specific device
curl -X DELETE http://localhost:8080/api/v1/devices/device-192.168.1.10

# Delete all devices
curl -X DELETE http://localhost:8080/api/v1/devices
🧪 Testing Simulators:
SNMP Testing:
bashsnmpget -v3 -u simadmin -A simadmin -a MD5 -l authNoPriv 192.168.1.10:161 1.3.6.1.2.1.1.1.0
SSH Testing:
bashssh simadmin@192.168.1.10
# Password: simadmin
# Commands: show version, show interfaces, etc.
📁 Resource File (resources.json):
The simulator automatically creates a resource file with default SNMP OIDs and SSH commands. You can customize responses by editing this file.
🔄 Device Lifecycle:

Create devices via REST API with starting IP and count
Each device gets incremented IP (192.168.1.10, 192.168.1.11, etc.)
SNMP & SSH servers start automatically on default ports
Manage devices via REST API (list, delete individual, delete all)

The simulator provides a complete network lab environment with REST API control for dynamic device management!
