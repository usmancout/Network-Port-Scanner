// static/js/main.js
// Initialize Socket.IO connection
const socket = io();

// DOM Elements
const startScanBtn = document.getElementById('start-scan-btn');
const clearResultsBtn = document.getElementById('clear-results-btn');
const targetInput = document.getElementById('target');
const scanTypeSelect = document.getElementById('scan-type');
const portRangeInput = document.getElementById('port-range');
const scanStatus = document.getElementById('scan-status');
const resultsTbody = document.getElementById('results-tbody');
const resultsCount = document.getElementById('results-count');
const connectionStatus = document.getElementById('connection-status');

// Firewall Elements
const addRuleBtn = document.getElementById('add-rule-btn');
const rulesList = document.getElementById('rules-list');
const testTrafficBtn = document.getElementById('test-traffic-btn');
const testResult = document.getElementById('test-result');
const flowStatus = document.getElementById('flow-status');
const flowArrow = document.getElementById('flow-arrow');
const flowArrow2 = document.getElementById('flow-arrow-2');

let scanResults = [];
let firewallRules = [];

// Socket.IO Event Handlers
socket.on('connect', () => {
    updateConnectionStatus(true);
});

socket.on('disconnect', () => {
    updateConnectionStatus(false);
});

socket.on('scan_result', (data) => {
    addScanResult(data);
});

socket.on('scan_status', (data) => {
    updateScanStatus(data.status, data.message);
});

// Update connection status
function updateConnectionStatus(connected) {
    if (connected) {
        connectionStatus.innerHTML = '<i class="fas fa-circle"></i> Connected';
        connectionStatus.classList.remove('disconnected');
        connectionStatus.classList.add('connected');
    } else {
        connectionStatus.innerHTML = '<i class="fas fa-circle"></i> Disconnected';
        connectionStatus.classList.remove('connected');
        connectionStatus.classList.add('disconnected');
    }
}

// Start Scan
startScanBtn.addEventListener('click', async () => {
    const target = targetInput.value.trim();
    const scanType = scanTypeSelect.value;
    const portRange = portRangeInput.value.trim();
    
    if (!target) {
        alert('Please enter a target IP or hostname');
        return;
    }
    
    // Disable button and show scanning status
    startScanBtn.disabled = true;
    startScanBtn.innerHTML = '<i class="fas fa-spinner loading"></i> Scanning...';
    
    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                target: target,
                scan_type: scanType,
                port_range: portRange
            })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Scan failed');
        }
        
    } catch (error) {
        updateScanStatus('error', error.message);
        startScanBtn.disabled = false;
        startScanBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
    }
});

// Update scan status
function updateScanStatus(status, message) {
    scanStatus.className = 'scan-status ' + status;
    
    let icon = 'fa-info-circle';
    if (status === 'scanning') icon = 'fa-spinner fa-spin';
    else if (status === 'completed') icon = 'fa-check-circle';
    else if (status === 'error') icon = 'fa-exclamation-circle';
    
    scanStatus.innerHTML = `<i class="fas ${icon}"></i> ${message}`;
    
    if (status === 'completed' || status === 'error') {
        startScanBtn.disabled = false;
        startScanBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
    }
}

// Add scan result to table
function addScanResult(result) {
    // Remove "no results" row if it exists
    const noResults = resultsTbody.querySelector('.no-results');
    if (noResults) {
        noResults.remove();
    }
    
    scanResults.push(result);
    
    const row = document.createElement('tr');
    row.innerHTML = `
        <td>${result.ip}</td>
        <td>${result.port}</td>
        <td>${result.protocol}</td>
        <td><span class="state-badge state-${result.state}">${result.state}</span></td>
        <td>${result.service || 'unknown'}</td>
        <td>${result.version || '-'}</td>
    `;
    
    resultsTbody.appendChild(row);
    updateResultsCount();
}

// Update results count
function updateResultsCount() {
    resultsCount.textContent = `${scanResults.length} port${scanResults.length !== 1 ? 's' : ''} found`;
}

// Clear results
clearResultsBtn.addEventListener('click', () => {
    scanResults = [];
    resultsTbody.innerHTML = '<tr class="no-results"><td colspan="6">No scan results yet. Start a scan to see results.</td></tr>';
    updateResultsCount();
});

// Firewall Rule Management
addRuleBtn.addEventListener('click', async () => {
    const action = document.getElementById('fw-action').value;
    const ip = document.getElementById('fw-ip').value.trim();
    const port = document.getElementById('fw-port').value.trim();
    const protocol = document.getElementById('fw-protocol').value;
    const priority = parseInt(document.getElementById('fw-priority').value);
    
    if (!ip || !port) {
        alert('Please fill in all required fields');
        return;
    }
    
    try {
        const response = await fetch('/api/firewall/rules', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                action: action,
                ip: ip,
                port: port,
                protocol: protocol,
                priority: priority
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            loadFirewallRules();
            showNotification('Rule added successfully', 'success');
        } else {
            throw new Error(data.error || 'Failed to add rule');
        }
    } catch (error) {
        showNotification(error.message, 'error');
    }
});

// Load firewall rules
async function loadFirewallRules() {
    try {
        const response = await fetch('/api/firewall/rules');
        const data = await response.json();
        firewallRules = data.rules;
        displayFirewallRules();
    } catch (error) {
        console.error('Failed to load firewall rules:', error);
    }
}

// Display firewall rules
function displayFirewallRules() {
    if (firewallRules.length === 0) {
        rulesList.innerHTML = '<div class="no-rules">No firewall rules configured.</div>';
        return;
    }
    
    rulesList.innerHTML = '';
    
    firewallRules.forEach(rule => {
        const ruleItem = document.createElement('div');
        ruleItem.className = `rule-item ${rule.action}`;
        ruleItem.innerHTML = `
            <div class="rule-info">
                <div class="rule-action ${rule.action}">
                    <i class="fas fa-${rule.action === 'allow' ? 'check' : 'times'}"></i>
                    ${rule.action}
                </div>
                <div class="rule-details">
                    <span class="rule-priority">Priority: ${rule.priority}</span>
                    IP: ${rule.ip} | Port: ${rule.port} | Protocol: ${rule.protocol}
                </div>
            </div>
            <button class="btn btn-danger" onclick="deleteRule(${rule.id})">
                <i class="fas fa-trash"></i> Delete
            </button>
        `;
        rulesList.appendChild(ruleItem);
    });
}

// Delete firewall rule
async function deleteRule(ruleId) {
    if (!confirm('Are you sure you want to delete this rule?')) {
        return;
    }
    
    try {
        const response = await fetch(`/api/firewall/rules/${ruleId}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            loadFirewallRules();
            showNotification('Rule deleted successfully', 'success');
        } else {
            throw new Error('Failed to delete rule');
        }
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

// Test traffic
testTrafficBtn.addEventListener('click', async () => {
    const ip = document.getElementById('test-ip').value.trim();
    const port = document.getElementById('test-port').value.trim();
    const protocol = document.getElementById('test-protocol').value;
    
    if (!ip || !port) {
        alert('Please fill in IP and Port');
        return;
    }
    
    try {
        const response = await fetch('/api/firewall/test', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                ip: ip,
                port: port,
                protocol: protocol
            })
        });
        
        const data = await response.json();
        displayTestResult(data);
        visualizeTraffic(data);
    } catch (error) {
        showNotification(error.message, 'error');
    }
});

// Display test result
function displayTestResult(result) {
    const action = result.action;
    testResult.className = `test-result show ${action === 'allow' ? 'allowed' : 'blocked'}`;
    
    let message = `<strong>Traffic ${action === 'allow' ? 'ALLOWED' : 'BLOCKED'}</strong><br>`;
    message += `IP: ${result.ip} | Port: ${result.port} | Protocol: ${result.protocol}<br>`;
    
    if (result.matched_rule) {
        message += `Matched Rule: ${result.matched_rule.action.toUpperCase()} (Priority: ${result.matched_rule.priority})`;
    } else {
        message += `No matching rule found - Default policy applied`;
    }
    
    testResult.innerHTML = message;
}

// Visualize traffic flow
function visualizeTraffic(result) {
    const action = result.action;
    
    // Reset arrows
    flowArrow.className = 'flow-arrow';
    flowArrow2.className = 'flow-arrow';
    
    if (action === 'allow') {
        flowArrow.classList.add('allowed');
        flowArrow2.classList.add('allowed');
        flowStatus.className = 'flow-status allowed';
        flowStatus.innerHTML = '<i class="fas fa-check-circle"></i> Traffic Allowed - Packet forwarded to destination';
    } else {
        flowArrow.classList.add('blocked');
        flowArrow2.style.opacity = '0.3';
        flowStatus.className = 'flow-status blocked';
        flowStatus.innerHTML = '<i class="fas fa-times-circle"></i> Traffic Blocked - Packet dropped by firewall';
    }
    
    // Reset after animation
    setTimeout(() => {
        flowArrow2.style.opacity = '1';
    }, 1000);
}

// Show notification
function showNotification(message, type) {
    // You can implement a toast notification system here
    if (type === 'error') {
        alert('Error: ' + message);
    } else {
        console.log(message);
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    loadFirewallRules();
});