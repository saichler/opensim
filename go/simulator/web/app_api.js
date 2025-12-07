// OpenSim Device Simulator - API Functions

const API_BASE = '/api/v1';
let devices = [];
let resources = [];
let isStatusPolling = false;

// Pagination state
const DEVICES_PER_PAGE = 50;
let currentPage = 1;

// Filter state
let filters = {
    id: '',
    ip: '',
    interface: '',
    deviceType: '',
    ports: '',
    status: ''
};

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

async function checkStatus() {
    try {
        const response = await apiCall('/status');
        const status = response.data;
        updateStatusDisplay(status);

        // Start/stop status polling based on activity
        if ((status.is_pre_allocating || status.is_creating_devices) && !isStatusPolling) {
            startStatusPolling();
        } else if (!status.is_pre_allocating && !status.is_creating_devices && isStatusPolling) {
            stopStatusPolling();
            // Refresh devices list when operations complete
            await loadDevices();
        }
    } catch (error) {
        console.error('Failed to check status:', error);
    }
}

function startStatusPolling() {
    if (isStatusPolling) return;
    isStatusPolling = true;
    const pollInterval = setInterval(async () => {
        if (!isStatusPolling) {
            clearInterval(pollInterval);
            return;
        }
        await checkStatus();
    }, 1000); // Poll every second during operations
}

function stopStatusPolling() {
    isStatusPolling = false;
}

function updateStatusDisplay(status) {
    if (status.is_pre_allocating) {
        const progress = status.pre_alloc_total > 0 ? Math.round((status.pre_alloc_progress / status.pre_alloc_total) * 100) : 0;
        showAlert('Pre-allocating TUN interfaces: ' + status.pre_alloc_progress + '/' + status.pre_alloc_total + ' (' + progress + '%)', 'warning');
    } else if (status.is_creating_devices) {
        const progress = status.device_create_total > 0 ? Math.round((status.device_create_progress / status.device_create_total) * 100) : 0;
        showAlert('Creating devices: ' + status.device_create_progress + '/' + status.device_create_total + ' (' + progress + '%)', 'warning');
    }
}

async function loadResources() {
    try {
        const response = await apiCall('/resources');
        resources = response.data || [];
        populateResourceSelect();
    } catch (error) {
        console.error('Failed to load resources: ' + error.message);
        showAlert('Failed to load device types: ' + error.message, 'warning');
    }
}

function populateResourceSelect() {
    const select = document.getElementById('resourceFile');
    // Clear existing options except default
    select.innerHTML = '<option value="">Default (Auto-detect)</option>';

    // Add resource file options
    resources.forEach(resource => {
        const option = document.createElement('option');
        option.value = resource.filename;
        option.textContent = resource.name + ' (' + resource.type + ')';
        select.appendChild(option);
    });
}

async function createDevices(startIp, deviceCount, netmask, resourceFile) {
    try {
        setLoading('createLoading', true);
        const requestData = {
            start_ip: startIp,
            device_count: parseInt(deviceCount),
            netmask: netmask
        };

        // Add resource file if selected
        if (resourceFile) {
            requestData.resource_file = resourceFile;
        }

        const response = await apiCall('/devices', {
            method: 'POST',
            body: JSON.stringify(requestData)
        });
        showAlert(response.message, 'success');

        // Start status polling to track progress
        startStatusPolling();

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

        showAlert('Permanent route script downloaded successfully! Routes will persist after reboot.', 'success');
    } catch (error) {
        showAlert('Failed to download route script: ' + error.message, 'error');
    } finally {
        setLoading('routeScriptLoading', false);
    }
}

function testConnection(ip, port) {
    showAlert('SSH test: ssh simadmin@' + ip + ' (password: simadmin)', 'warning');
}

function pingDevice(ip) {
    showAlert('Ping test for ' + ip + '. Check your terminal: ping ' + ip, 'warning');
}
