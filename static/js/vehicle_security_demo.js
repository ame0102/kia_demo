// Vehicle Security Demo - JavaScript Helper Functions

// Function to simulate the attack process for demonstration purposes
function simulateAttack(mode) {
    const isSecure = mode === 'secure';
    const apiUrl = `/api/simulate_attack/`;
    
    // Show the loading indicator
    document.getElementById('attack-progress').style.display = 'block';
    
    // Disable the attack button during simulation
    const attackButton = document.getElementById('attack-button');
    attackButton.disabled = true;
    attackButton.classList.add('cursor-not-allowed');
    attackButton.classList.add('bg-gray-300');
    
    fetch(apiUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            mode: mode,
            attack_type: 'ownership'
        }),
    })
    .then(response => response.json())
    .then(data => {
        console.log('Attack simulation response:', data);
        
        if (isSecure) {
            // Handle secure mode attack (will be blocked)
            showSecureAttackBlocked(data.blocking_feature);
        } else {
            // Handle insecure mode attack (will succeed)
            progressInsecureAttack();
        }
    })
    .catch(error => {
        console.error('Error simulating attack:', error);
        // Reset the attack simulation UI
        resetAttackSimulation();
    });
}

// Function to progress through the steps of an insecure attack
function progressInsecureAttack() {
    const progressBar = document.getElementById('attack-progress-bar');
    const statusMessage = document.getElementById('attack-status');
    let step = 0;
    
    const interval = setInterval(() => {
        step++;
        const progress = step * 25; // 4 steps to 100%
        progressBar.style.width = `${progress}%`;
        
        // Update status message based on current step
        switch(step) {
            case 1:
                statusMessage.textContent = "Step 1: Authentication bypass - Accessing dealer portal...";
                highlightComponent('attacker-component');
                break;
            case 2:
                statusMessage.textContent = "Step 2: Owner information leaked - Obtaining vehicle details...";
                highlightComponent('api-component');
                break;
            case 3:
                statusMessage.textContent = "Step 3: Owner permissions modified - Demoting legitimate owner...";
                highlightComponent('firmware-component');
                break;
            case 4:
                statusMessage.textContent = "Takeover complete - Attacker has full remote access!";
                statusMessage.classList.add('font-medium');
                highlightComponent('vehicle-component');
                
                // Add success icon
                const successIcon = document.createElement('span');
                successIcon.className = 'mr-2';
                successIcon.innerHTML = '✓';
                statusMessage.prepend(successIcon);
                
                clearInterval(interval);
                break;
        }
        
        if (step >= 4) {
            clearInterval(interval);
        }
    }, 1000);
}

// Function to show a secure attack being blocked
function showSecureAttackBlocked(blockingFeature) {
    const progressBar = document.getElementById('attack-progress-bar');
    const statusMessage = document.getElementById('attack-status');
    
    // Show attack attempt
    progressBar.style.width = '30%';
    statusMessage.textContent = "Attack attempt detected - Security systems responding...";
    statusMessage.className = 'mt-2 text-sm text-yellow-600';
    
    // Determine which security feature blocked the attack
    let featureComponent, featureMessage;
    
    switch(blockingFeature) {
        case 'OAuth + MFA Security':
            featureComponent = 'oauth-component';
            featureMessage = 'Authentication required: Attack blocked at API level';
            break;
        case 'TUF Firmware Security':
            featureComponent = 'tuf-component';
            featureMessage = 'Invalid signature: Firmware update rejected';
            break;
        default: // CAN Guardian
            featureComponent = 'can-component';
            featureMessage = 'Invalid CMAC: Unauthorized CAN frame blocked';
    }
    
    // Highlight the security component that blocked the attack
    highlightComponent(featureComponent, 'secure');
    
    // After a delay, show the attack being blocked
    setTimeout(() => {
        const attackBlockedDiv = document.createElement('div');
        attackBlockedDiv.className = 'absolute h-full bg-green-500 right-0 left-0 flex items-center justify-center';
        
        const xIcon = document.createElement('span');
        xIcon.className = 'text-white';
        xIcon.textContent = '✕';
        attackBlockedDiv.appendChild(xIcon);
        
        document.getElementById('progress-container').appendChild(attackBlockedDiv);
        
        // Update status message to show attack blocked
        statusMessage.innerHTML = `<span class="mr-2">✓</span><span class="font-medium">${featureMessage}</span>`;
        statusMessage.className = 'mt-2 text-sm text-green-600 flex items-center';
    }, 2000);
}

// Function to highlight a component in the UI
function highlightComponent(componentId, mode = 'insecure') {
    const component = document.getElementById(componentId);
    if (!component) return;
    
    if (mode === 'insecure') {
        component.classList.add('component-highlight');
    } else {
        component.classList.add('secure-pulse');
    }
    
    // Find the alert div inside the component and show it
    const alertDiv = component.querySelector('.component-alert');
    if (alertDiv) {
        alertDiv.style.display = 'flex';
    }
}

// Function to reset the attack simulation
function resetAttackSimulation() {
    // Reset the progress bar
    const progressBar = document.getElementById('attack-progress-bar');
    progressBar.style.width = '0%';
    
    // Clear any attack blocked overlay
    const progressContainer = document.getElementById('progress-container');
    const attackBlockedDiv = progressContainer.querySelector('.absolute');
    if (attackBlockedDiv) {
        progressContainer.removeChild(attackBlockedDiv);
    }
    
    // Reset the status message
    const statusMessage = document.getElementById('attack-status');
    statusMessage.textContent = '';
    statusMessage.className = 'mt-2 text-sm';
    
    // Reset all component highlights
    document.querySelectorAll('.component-highlight, .secure-pulse').forEach(el => {
        el.classList.remove('component-highlight', 'secure-pulse');
    });
    
    // Hide all component alerts
    document.querySelectorAll('.component-alert').forEach(el => {
        el.style.display = 'none';
    });
    
    // Re-enable the attack button
    const attackButton = document.getElementById('attack-button');
    attackButton.disabled = false;
    attackButton.classList.remove('cursor-not-allowed', 'bg-gray-300');
    
    // Clear the logs table
    refreshSecurityLogs();
}

// Function to refresh the security logs
function refreshSecurityLogs() {
    fetch('/api/logs/')
        .then(response => response.json())
        .then(data => {
            const logsTable = document.getElementById('security-logs-table');
            if (!logsTable) return;
            
            // Clear existing logs
            const tbody = logsTable.querySelector('tbody');
            tbody.innerHTML = '';
            
            // Add new logs
            data.forEach(log => {
                const tr = document.createElement('tr');
                
                // Format timestamp
                const timestamp = new Date(log.timestamp);
                const formattedTime = timestamp.toLocaleString();
                
                // Create table cells
                const timeCell = document.createElement('td');
                timeCell.className = 'px-4 py-2 text-xs';
                timeCell.textContent = formattedTime;
                
                const typeCell = document.createElement('td');
                typeCell.className = 'px-4 py-2 text-xs';
                
                // Create event type badge
                const typeBadge = document.createElement('span');
                typeBadge.className = 'px-2 py-1 rounded-full text-xs font-medium';
                
                // Set badge color based on event type
                if (log.event_type === 'ATTACK') {
                    typeBadge.className += ' bg-red-100 text-red-800';
                } else if (log.event_type === 'AUTH') {
                    typeBadge.className += ' bg-blue-100 text-blue-800';
                } else if (log.event_type === 'OTA') {
                    typeBadge.className += ' bg-yellow-100 text-yellow-800';
                } else if (log.event_type === 'CAN') {
                    typeBadge.className += ' bg-purple-100 text-purple-800';
                } else {
                    typeBadge.className += ' bg-gray-100 text-gray-800';
                }
                
                typeBadge.textContent = log.event_type;
                typeCell.appendChild(typeBadge);
                
                const descCell = document.createElement('td');
                descCell.className = 'px-4 py-2 text-xs';
                descCell.textContent = log.description;
                
                const statusCell = document.createElement('td');
                statusCell.className = 'px-4 py-2 text-xs';
                
                // Create status indicator
                const statusIcon = document.createElement('span');
                if (log.success) {
                    statusIcon.className = 'text-green-500';
                    statusIcon.textContent = '✓';
                } else {
                    statusIcon.className = 'text-red-500';
                    statusIcon.textContent = '✕';
                }
                statusCell.appendChild(statusIcon);
                
                // Add cells to row
                tr.appendChild(timeCell);
                tr.appendChild(typeCell);
                tr.appendChild(descCell);
                tr.appendChild(statusCell);
                
                // Add row to table
                tbody.appendChild(tr);
            });
        })
        .catch(error => console.error('Error fetching security logs:', error));
}

// Function to switch between secure and insecure modes
function switchMode(mode) {
    const insecureTab = document.getElementById('insecure-tab');
    const secureTab = document.getElementById('secure-tab');
    const insecureContent = document.getElementById('insecure-content');
    const secureContent = document.getElementById('secure-content');
    
    if (mode === 'insecure') {
        // Update tab styles
        insecureTab.classList.add('bg-red-500', 'text-white');
        insecureTab.classList.remove('bg-white', 'text-gray-700');
        secureTab.classList.add('bg-white', 'text-gray-700');
        secureTab.classList.remove('bg-green-500', 'text-white');
        
        // Show insecure content, hide secure content
        insecureContent.style.display = 'block';
        secureContent.style.display = 'none';
        
        // Update page title color
        document.getElementById('page-title').className = 'text-xl font-bold text-red-600 mb-4';
        
        // Update attack button style
        const attackButton = document.getElementById('attack-button');
        attackButton.className = 'px-4 py-2 rounded-lg font-medium bg-red-500 text-white hover:bg-red-600';
    } else {
        // Update tab styles
        secureTab.classList.add('bg-green-500', 'text-white');
        secureTab.classList.remove('bg-white', 'text-gray-700');
        insecureTab.classList.add('bg-white', 'text-gray-700');
        insecureTab.classList.remove('bg-red-500', 'text-white');
        
        // Show secure content, hide insecure content
        secureContent.style.display = 'block';
        insecureContent.style.display = 'none';
        
        // Update page title color
        document.getElementById('page-title').className = 'text-xl font-bold text-green-600 mb-4';
        
        // Update attack button style
        const attackButton = document.getElementById('attack-button');
        attackButton.className = 'px-4 py-2 rounded-lg font-medium bg-green-500 text-white hover:bg-green-600';
    }
    
    // Reset the attack simulation
    resetAttackSimulation();
    
    // Update the simulation container background
    const simulationContainer = document.getElementById('simulation-container');
    if (mode === 'insecure') {
        simulationContainer.className = 'mb-6 p-4 border rounded-lg bg-red-50 border-red-200';
    } else {
        simulationContainer.className = 'mb-6 p-4 border rounded-lg bg-green-50 border-green-200';
    }
}

// Initialize the demo when the page loads
document.addEventListener('DOMContentLoaded', function() {
    // Set initial mode to insecure
    switchMode('insecure');
    
    // Add event listeners to mode tabs
    document.getElementById('insecure-tab').addEventListener('click', () => switchMode('insecure'));
    document.getElementById('secure-tab').addEventListener('click', () => switchMode('secure'));
    
    // Add event listener to attack button
    document.getElementById('attack-button').addEventListener('click', function() {
        const activeTab = document.getElementById('insecure-tab').classList.contains('bg-red-500') ? 'insecure' : 'secure';
        simulateAttack(activeTab);
    });
    
    // Add event listener to reset button
    const resetButton = document.getElementById('reset-button');
    if (resetButton) {
        resetButton.addEventListener('click', function() {
            fetch('/api/reset_simulation/', { method: 'POST' })
                .then(() => resetAttackSimulation())
                .catch(error => console.error('Error resetting simulation:', error));
        });
    }
    
    // Initial fetch of security logs
    refreshSecurityLogs();
    
    // Set up periodic refresh of security logs
    setInterval(refreshSecurityLogs, 5000);
});