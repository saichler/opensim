// OpenSim Device Simulator - UI Functions

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

// Event listeners
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
