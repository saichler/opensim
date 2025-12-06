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
    filterDeviceType: document.getElementById('filterDeviceType'),
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

// Filter helper functions
function getFilteredDevices() {
    return devices.filter(device => {
        const matchesId = !filters.id || device.id.toLowerCase().includes(filters.id.toLowerCase());
        const matchesIp = !filters.ip || device.ip.includes(filters.ip);
        const matchesInterface = !filters.interface || (device.interface && device.interface.toLowerCase().includes(filters.interface.toLowerCase()));
        const matchesDeviceType = !filters.deviceType || (device.device_type && device.device_type.toLowerCase().includes(filters.deviceType.toLowerCase()));
        const matchesPorts = !filters.ports ||
            (device.snmp_port.toString().includes(filters.ports) ||
             device.ssh_port.toString().includes(filters.ports));
        const matchesStatus = !filters.status ||
            (filters.status === 'running' && device.running) ||
            (filters.status === 'stopped' && !device.running);

        return matchesId && matchesIp && matchesInterface && matchesDeviceType && matchesPorts && matchesStatus;
    });
}

function updateFiltersFromInputs() {
    filters.id = elements.filterDeviceId.value;
    filters.ip = elements.filterIp.value;
    filters.interface = elements.filterInterface.value;
    filters.deviceType = elements.filterDeviceType.value;
    filters.ports = elements.filterPorts.value;
    filters.status = elements.filterStatus.value;
}

function clearAllFilters() {
    filters.id = '';
    filters.ip = '';
    filters.interface = '';
    filters.deviceType = '';
    filters.ports = '';
    filters.status = '';

    elements.filterDeviceId.value = '';
    elements.filterIp.value = '';
    elements.filterInterface.value = '';
    elements.filterDeviceType.value = '';
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
        '<th>Device Type</th>' +
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
            '<td><span class="device-type">' + (device.device_type || 'Unknown') + '</span></td>' +
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
    const resourceFile = document.getElementById('resourceFile').value;
    if (!startIp || !deviceCount) {
        showAlert('Please fill in all required fields', 'error');
        return;
    }
    await createDevices(startIp, deviceCount, netmask, resourceFile);
    elements.createForm.reset();
    document.getElementById('deviceCount').value = '1';
    document.getElementById('netmask').value = '24';
    document.getElementById('resourceFile').value = '';
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
elements.filterDeviceType.addEventListener('input', applyFilters);
elements.filterPorts.addEventListener('input', applyFilters);
elements.filterStatus.addEventListener('change', applyFilters);
elements.clearFiltersBtn.addEventListener('click', clearAllFilters);

setInterval(loadDevices, 30000);

document.addEventListener('DOMContentLoaded', () => {
    loadDevices();
    loadResources();
    checkStatus(); // Initial status check
    showAlert('Network Device Simulator Web UI loaded successfully!', 'success');
});
