package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// Web handlers for HTTP API endpoints

func createDevicesHandler(w http.ResponseWriter, r *http.Request) {
	var req CreateDevicesRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		sendErrorResponse(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.DeviceCount <= 0 {
		sendErrorResponse(w, "Device count must be greater than 0", http.StatusBadRequest)
		return
	}

	err = manager.CreateDevices(req.StartIP, req.DeviceCount, req.Netmask, req.SNMPv3)
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

func exportDevicesCSVHandler(w http.ResponseWriter, r *http.Request) {
	devices := manager.ListDevices()
	
	// Set headers for CSV download
	filename := fmt.Sprintf("devices_%s.csv", time.Now().Format("2006-01-02_15-04-05"))
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	
	// Create CSV writer
	writer := csv.NewWriter(w)
	defer writer.Flush()
	
	// Write CSV headers
	headers := []string{"Device ID", "IP Address", "Interface", "SNMP Port", "SSH Port", "Status"}
	if err := writer.Write(headers); err != nil {
		http.Error(w, "Failed to write CSV headers", http.StatusInternalServerError)
		return
	}
	
	// Write device data
	for _, device := range devices {
		status := "Stopped"
		if device.Running {
			status = "Running"
		}
		
		interfaceName := device.Interface
		if interfaceName == "" {
			interfaceName = "N/A"
		}
		
		record := []string{
			device.ID,
			device.IP,
			interfaceName,
			fmt.Sprintf("%d", device.SNMPPort),
			fmt.Sprintf("%d", device.SSHPort),
			status,
		}
		
		if err := writer.Write(record); err != nil {
			http.Error(w, "Failed to write CSV record", http.StatusInternalServerError)
			return
		}
	}
}

func generateRouteScriptHandler(w http.ResponseWriter, r *http.Request) {
	devices := manager.ListDevices()
	
	// Set headers for script download
	filename := fmt.Sprintf("add_simulator_routes_%s.sh", time.Now().Format("2006-01-02_15-04-05"))
	w.Header().Set("Content-Type", "application/x-sh")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	
	// Generate bash script content
	script := generateRouteScript(devices)
	w.Write([]byte(script))
}

func generateRouteScript(devices []DeviceInfo) string {
	if len(devices) == 0 {
		return `#!/bin/bash
# No devices found in simulator
echo "No devices found in simulator"
exit 1
`
	}
	
	// Collect unique subnets from devices
	subnets := make(map[string]bool)
	for _, device := range devices {
		ip := net.ParseIP(device.IP)
		if ip != nil {
			// Assume /24 subnet for route calculation
			subnet := fmt.Sprintf("%d.%d.%d.0/24", ip[12], ip[13], ip[14])
			subnets[subnet] = true
		}
	}
	
	var script strings.Builder
	script.WriteString(`#!/bin/bash
#
# Static Route Configuration Script for Network Device Simulator
# Generated on: ` + time.Now().Format("2006-01-02 15:04:05") + `
#
# Usage: ./add_simulator_routes.sh <SIMULATOR_HOST_IP>
# Example: ./add_simulator_routes.sh 192.168.1.100
#

if [ $# -ne 1 ]; then
    echo "Usage: $0 <SIMULATOR_HOST_IP>"
    echo "Example: $0 192.168.1.100"
    echo ""
    echo "This script will add static routes for the following subnets:"
`)

	// Add subnet list to help text
	for subnet := range subnets {
		script.WriteString(fmt.Sprintf(`    echo "  - %s"`, subnet))
		script.WriteString("\n")
	}
	
	script.WriteString(`    exit 1
fi

SIMULATOR_HOST=$1

echo "Adding static routes to simulator subnets via $SIMULATOR_HOST"
echo ""

`)

	// Add simple route commands for each subnet
	for subnet := range subnets {
		script.WriteString(fmt.Sprintf(`# Add route for %s
echo "Adding route: %s via $SIMULATOR_HOST"
sudo ip route add %s via $SIMULATOR_HOST 2>/dev/null || echo "Route %s already exists or failed to add"

`, subnet, subnet, subnet, subnet))
	}
	
	script.WriteString(`echo ""
echo "Route configuration complete!"
echo ""
echo "To remove these routes later, run:"
`)

	for subnet := range subnets {
		script.WriteString(fmt.Sprintf(`echo "  sudo ip route del %s"`, subnet))
		script.WriteString("\n")
	}

	return script.String()
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
        .device-table {
            width: 100%; background: white; border-radius: 16px; overflow: hidden;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1); border: 2px solid #e1e5e9;
        }
        .device-table table { width: 100%; border-collapse: collapse; }
        .device-table thead {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .device-table thead th {
            padding: 16px 12px; text-align: left; font-weight: 600; font-size: 14px;
            border-bottom: 2px solid rgba(255, 255, 255, 0.2);
        }
        .device-table tbody tr {
            transition: all 0.2s ease; border-bottom: 1px solid #e1e5e9;
        }
        .device-table tbody tr:hover { background: rgba(102, 126, 234, 0.05); }
        .device-table tbody tr:last-child { border-bottom: none; }
        .device-table tbody td {
            padding: 16px 12px; vertical-align: middle; font-size: 14px;
        }
        .device-id { font-weight: 600; color: #333; font-family: Monaco, monospace; }
        .device-ip { font-family: Monaco, monospace; color: #333; }
        .device-interface { font-family: Monaco, monospace; color: #666; }
        .device-ports { font-family: Monaco, monospace; color: #666; font-size: 13px; }
        .device-status { padding: 6px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; display: inline-block; }
        .status-running { background: #d4edda; color: #155724; }
        .status-stopped { background: #f8d7da; color: #721c24; }
        .device-actions { display: flex; gap: 8px; flex-wrap: wrap; }
        .device-actions .btn { padding: 6px 12px; font-size: 12px; min-width: auto; }
        .pagination-controls {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 20px;
            padding: 15px 0;
            border-top: 1px solid #eee;
        }
        .pagination-info {
            color: #666;
            font-size: 0.9em;
        }
        .pagination-buttons {
            display: flex;
            gap: 10px;
        }
        .pagination-buttons .btn {
            min-width: 80px;
        }
        .pagination-buttons .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .filter-controls {
            margin-bottom: 15px;
        }
        .filter-table {
            width: 100%;
            border-collapse: collapse;
        }
        .filter-row th {
            padding: 8px;
            background: #f8f9fa;
            border-bottom: 2px solid #dee2e6;
        }
        .filter-input {
            width: 100%;
            padding: 6px 8px;
            border: 1px solid #ced4da;
            border-radius: 4px;
            font-size: 0.85em;
            background: white;
        }
        .filter-input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 2px rgba(102, 126, 234, 0.1);
        }
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
            .status-grid { grid-template-columns: repeat(2, 1fr); }
            .device-table table { font-size: 12px; }
            .device-table thead th { padding: 12px 8px; }
            .device-table tbody td { padding: 12px 8px; }
            .device-actions { flex-direction: column; gap: 4px; }
            .device-actions .btn { font-size: 11px; padding: 4px 8px; }
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
                        <input type="number" id="deviceCount" min="1" value="1" required>
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
                    <button id="exportBtn" class="btn btn-small">
                        📊 Export CSV <span id="exportLoading" class="loading" style="display: none;"></span>
                    </button>
                    <button id="routeScriptBtn" class="btn btn-small">
                        🛤️ Route Script <span id="routeScriptLoading" class="loading" style="display: none;"></span>
                    </button>
                    <button id="refreshBtn" class="btn btn-small">
                        🔄 Refresh <span id="refreshLoading" class="loading" style="display: none;"></span>
                    </button>
                    <button id="deleteAllBtn" class="btn btn-danger btn-small">
                        🗑️ Delete All <span id="deleteAllLoading" class="loading" style="display: none;"></span>
                    </button>
                </div>
            </div>
            <div id="deviceList" class="device-table">
                <div id="filterControls" class="filter-controls">
                    <table class="filter-table">
                        <tr class="filter-row">
                            <th><input type="text" id="filterDeviceId" placeholder="Filter ID..." class="filter-input"></th>
                            <th><input type="text" id="filterIp" placeholder="Filter IP..." class="filter-input"></th>
                            <th><input type="text" id="filterInterface" placeholder="Filter interface..." class="filter-input"></th>
                            <th><input type="text" id="filterPorts" placeholder="Filter ports..." class="filter-input"></th>
                            <th><select id="filterStatus" class="filter-input"><option value="">All</option><option value="running">Running</option><option value="stopped">Stopped</option></select></th>
                            <th><button id="clearFiltersBtn" class="btn btn-small">Clear</button></th>
                        </tr>
                    </table>
                </div>
                <div id="deviceTable"></div>
            </div>
            <div id="paginationControls" class="pagination-controls" style="display: none;">
                <div class="pagination-info">
                    <span id="pageInfo">Page 1 of 1 (0 devices)</span>
                </div>
                <div class="pagination-buttons">
                    <button id="prevPageBtn" class="btn btn-small" disabled>‹ Previous</button>
                    <button id="nextPageBtn" class="btn btn-small" disabled>Next ›</button>
                </div>
            </div>
        </div>
    </div>
    <script>
        const API_BASE = '/api/v1';
        let devices = [];
        
        // Pagination state
        const DEVICES_PER_PAGE = 50;
        let currentPage = 1;
        
        // Filter state
        let filters = {
            id: '',
            ip: '',
            interface: '',
            ports: '',
            status: ''
        };
        
        const elements = {
            createForm: document.getElementById('createForm'),
            deviceList: document.getElementById('deviceList'),
            alerts: document.getElementById('alerts'),
            exportBtn: document.getElementById('exportBtn'),
            routeScriptBtn: document.getElementById('routeScriptBtn'),
            refreshBtn: document.getElementById('refreshBtn'),
            deleteAllBtn: document.getElementById('deleteAllBtn'),
            totalDevices: document.getElementById('totalDevices'),
            runningDevices: document.getElementById('runningDevices'),
            stoppedDevices: document.getElementById('stoppedDevices'),
            tunInterfaces: document.getElementById('tunInterfaces'),
            paginationControls: document.getElementById('paginationControls'),
            pageInfo: document.getElementById('pageInfo'),
            prevPageBtn: document.getElementById('prevPageBtn'),
            nextPageBtn: document.getElementById('nextPageBtn'),
            filterControls: document.getElementById('filterControls'),
            deviceTable: document.getElementById('deviceTable'),
            filterDeviceId: document.getElementById('filterDeviceId'),
            filterIp: document.getElementById('filterIp'),
            filterInterface: document.getElementById('filterInterface'),
            filterPorts: document.getElementById('filterPorts'),
            filterStatus: document.getElementById('filterStatus'),
            clearFiltersBtn: document.getElementById('clearFiltersBtn')
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

        function exportDevicesCSV() {
            try {
                setLoading('exportLoading', true);
                
                if (devices.length === 0) {
                    showAlert('No devices to export', 'warning');
                    return;
                }

                // Direct download from API endpoint
                const link = document.createElement('a');
                link.href = API_BASE + '/devices/export';
                link.download = 'devices.csv';
                link.style.display = 'none';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                
                showAlert('Device list exported successfully', 'success');
            } catch (error) {
                showAlert('Failed to export devices: ' + error.message, 'error');
            } finally {
                setLoading('exportLoading', false);
            }
        }

        function downloadRouteScript() {
            try {
                setLoading('routeScriptLoading', true);
                
                if (devices.length === 0) {
                    showAlert('No devices to generate routes for', 'warning');
                    return;
                }

                // Direct download from API endpoint
                const link = document.createElement('a');
                link.href = API_BASE + '/devices/routes';
                link.download = 'add_simulator_routes.sh';
                link.style.display = 'none';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                
                showAlert('Route configuration script downloaded successfully', 'success');
            } catch (error) {
                showAlert('Failed to download route script: ' + error.message, 'error');
            } finally {
                setLoading('routeScriptLoading', false);
            }
        }

        // Filter helper functions
        function getFilteredDevices() {
            return devices.filter(device => {
                const matchesId = !filters.id || device.id.toLowerCase().includes(filters.id.toLowerCase());
                const matchesIp = !filters.ip || device.ip.includes(filters.ip);
                const matchesInterface = !filters.interface || (device.interface && device.interface.toLowerCase().includes(filters.interface.toLowerCase()));
                const matchesPorts = !filters.ports || 
                    (device.snmp_port.toString().includes(filters.ports) || 
                     device.ssh_port.toString().includes(filters.ports));
                const matchesStatus = !filters.status || 
                    (filters.status === 'running' && device.running) ||
                    (filters.status === 'stopped' && !device.running);
                
                return matchesId && matchesIp && matchesInterface && matchesPorts && matchesStatus;
            });
        }

        function updateFiltersFromInputs() {
            filters.id = elements.filterDeviceId.value;
            filters.ip = elements.filterIp.value;
            filters.interface = elements.filterInterface.value;
            filters.ports = elements.filterPorts.value;
            filters.status = elements.filterStatus.value;
        }

        function clearAllFilters() {
            filters.id = '';
            filters.ip = '';
            filters.interface = '';
            filters.ports = '';
            filters.status = '';
            
            elements.filterDeviceId.value = '';
            elements.filterIp.value = '';
            elements.filterInterface.value = '';
            elements.filterPorts.value = '';
            elements.filterStatus.value = '';
            
            currentPage = 1;
            renderDevices();
        }

        function applyFilters() {
            updateFiltersFromInputs();
            currentPage = 1; // Reset to first page when filtering
            renderDevices();
        }

        // Pagination helper functions
        function getTotalPages() {
            const filteredDevices = getFilteredDevices();
            return Math.ceil(filteredDevices.length / DEVICES_PER_PAGE);
        }

        function getCurrentPageDevices() {
            const filteredDevices = getFilteredDevices();
            const startIndex = (currentPage - 1) * DEVICES_PER_PAGE;
            const endIndex = startIndex + DEVICES_PER_PAGE;
            return filteredDevices.slice(startIndex, endIndex);
        }

        function updatePaginationControls() {
            const filteredDevices = getFilteredDevices();
            const totalPages = getTotalPages();
            const hasDevices = filteredDevices.length > 0;
            
            // Show/hide pagination controls
            elements.paginationControls.style.display = hasDevices ? 'flex' : 'none';
            
            if (hasDevices) {
                // Update page info
                const showingCount = getCurrentPageDevices().length;
                const totalFiltered = filteredDevices.length;
                const totalDevices = devices.length;
                
                let pageInfoText = 'Page ' + currentPage + ' of ' + totalPages + ' (' + showingCount + ' of ' + totalFiltered + ' devices';
                if (totalFiltered !== totalDevices) {
                    pageInfoText += ' filtered from ' + totalDevices + ' total';
                }
                pageInfoText += ')';
                
                elements.pageInfo.textContent = pageInfoText;
                
                // Update button states
                elements.prevPageBtn.disabled = currentPage <= 1;
                elements.nextPageBtn.disabled = currentPage >= totalPages;
            }
        }

        function goToPage(page) {
            const totalPages = getTotalPages();
            if (page >= 1 && page <= totalPages) {
                currentPage = page;
                renderDevices();
                updatePaginationControls();
            }
        }

        function goToPreviousPage() {
            if (currentPage > 1) {
                goToPage(currentPage - 1);
            }
        }

        function goToNextPage() {
            const totalPages = getTotalPages();
            if (currentPage < totalPages) {
                goToPage(currentPage + 1);
            }
        }

        function renderDevices() {
            // Filter controls are always visible
            
            if (devices.length === 0) {
                elements.deviceTable.innerHTML = '<div class="empty-state"><div style="font-size: 4em; margin-bottom: 20px;">📱</div><h3>No Devices Found</h3><p>Create your first simulated network device to get started</p></div>';
                updatePaginationControls();
                return;
            }

            const filteredDevices = getFilteredDevices();
            if (filteredDevices.length === 0) {
                elements.deviceTable.innerHTML = '<div class="empty-state"><div style="font-size: 4em; margin-bottom: 20px;">🔍</div><h3>No Devices Match Filters</h3><p>Try adjusting your filter criteria or clear filters to see all devices</p></div>';
                updatePaginationControls();
                return;
            }
            
            const tableHTML = '<table>' +
                '<thead>' +
                '<tr>' +
                '<th>Device ID</th>' +
                '<th>IP Address</th>' +
                '<th>Interface</th>' +
                '<th>Ports</th>' +
                '<th>Status</th>' +
                '<th>Actions</th>' +
                '</tr>' +
                '</thead>' +
                '<tbody>' +
                getCurrentPageDevices().map(device => 
                    '<tr>' +
                    '<td><span class="device-id">' + device.id + '</span></td>' +
                    '<td><span class="device-ip">' + device.ip + '</span></td>' +
                    '<td><span class="device-interface">' + (device.interface || 'N/A') + '</span></td>' +
                    '<td><span class="device-ports">SNMP:' + device.snmp_port + ' SSH:' + device.ssh_port + '</span></td>' +
                    '<td><span class="device-status ' + (device.running ? 'status-running' : 'status-stopped') + '">' +
                    (device.running ? '● RUNNING' : '● STOPPED') + '</span></td>' +
                    '<td><div class="device-actions">' +
                    '<button class="btn btn-small" data-action="test-ssh" data-ip="' + device.ip + '" data-port="' + device.ssh_port + '">🔗 SSH</button>' +
                    '<button class="btn btn-small" data-action="ping" data-ip="' + device.ip + '">📡 Ping</button>' +
                    '<button class="btn btn-danger btn-small" data-action="delete" data-device-id="' + device.id + '">🗑️ Delete</button>' +
                    '</div></td>' +
                    '</tr>'
                ).join('') +
                '</tbody>' +
                '</table>';
            
            elements.deviceTable.innerHTML = tableHTML;
            
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
            
            
            // Update pagination controls
            updatePaginationControls();
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

        elements.exportBtn.addEventListener('click', exportDevicesCSV);
        elements.routeScriptBtn.addEventListener('click', downloadRouteScript);
        elements.refreshBtn.addEventListener('click', loadDevices);
        elements.deleteAllBtn.addEventListener('click', deleteAllDevices);
        
        // Pagination event listeners
        elements.prevPageBtn.addEventListener('click', goToPreviousPage);
        elements.nextPageBtn.addEventListener('click', goToNextPage);
        
        // Filter event listeners (attached once during initialization)
        elements.filterDeviceId.addEventListener('input', applyFilters);
        elements.filterIp.addEventListener('input', applyFilters);
        elements.filterInterface.addEventListener('input', applyFilters);
        elements.filterPorts.addEventListener('input', applyFilters);
        elements.filterStatus.addEventListener('change', applyFilters);
        elements.clearFiltersBtn.addEventListener('click', clearAllFilters);
        
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
	api.HandleFunc("/devices/export", exportDevicesCSVHandler).Methods("GET")
	api.HandleFunc("/devices/routes", generateRouteScriptHandler).Methods("GET")
	api.HandleFunc("/devices/{id}", deleteDeviceHandler).Methods("DELETE")
	api.HandleFunc("/devices", deleteAllDevicesHandler).Methods("DELETE")

	// Health check
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}).Methods("GET")

	return router
}