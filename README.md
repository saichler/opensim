# opensim
Open device simulator that simulates snmp &amp; ssh network devices

🛠️ Complete Setup Instructions
1. Create the Go Module
   bash# Create a new directory for your project
   mkdir network-simulator
   cd network-simulator

# Initialize Go module
go mod init network-simulator

# Create the main file
# Copy the complete code from the artifact into simulator.go
2. Install Dependencies
   bash# This will download the required dependencies
   go mod tidy
   The go.mod file should look like this:
   gomodule network-simulator

go 1.19

require (
github.com/gorilla/mux v1.8.0
golang.org/x/crypto v0.14.0
)
3. Build the Application
   bash# Build the executable
   go build -o simulator simulator.go
4. Run with Root Privileges
   bash# Run the simulator (requires root for TUN interfaces)
   sudo ./simulator
   ✅ What You Should See
   When you run the application, you should see output like:
   Network Device Simulator with TUN/TAP support starting...
   Created default resources file: resources.json
   Loaded 7 SNMP and 8 SSH resources
   Network Device Simulator server starting on port :8080

🌐 Web UI:
http://localhost:8080/
http://localhost:8080/ui

📡 API Endpoints:
POST   /api/v1/devices           - Create devices
GET    /api/v1/devices           - List devices
DELETE /api/v1/devices/{id}      - Delete device
DELETE /api/v1/devices           - Delete all devices
GET    /health                   - Health check

💡 Example curl commands:
curl -X POST http://localhost:8080/api/v1/devices -H "Content-Type: application/json" -d '{"start_ip":"192.168.100.1","device_count":3,"netmask":"24"}'
curl http://localhost:8080/api/v1/devices

🔧 Usage Tips:
- Open the Web UI in your browser for easy management
- SSH to devices: ssh simadmin@<device-ip> (password: simadmin)
- Test SNMP: snmpget -v2c -c public <device-ip> 1.3.6.1.2.1.1.1.0
- Check TUN interfaces: ip addr show | grep sim
  🌐 Access the Web UI
  Open your browser and navigate to http://localhost:8080/ to see the beautiful web interface for managing your network device simulator!
  The code is now complete and should compile without any issues. All functions, handlers, and the web UI are properly implemented.