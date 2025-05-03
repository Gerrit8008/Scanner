"""
Scanner Template Generator

This module provides functions to generate and update customized scanner files for clients.
It creates HTML, CSS, and JavaScript templates based on client data and branding.
"""

import os
import json
import logging
import shutil
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("scanner_template.log"),
        logging.StreamHandler()
    ]
)

# Define paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
OUTPUT_DIR = os.path.join(BASE_DIR, 'generated_scanners')
CONFIG_DIR = os.path.join(BASE_DIR, 'configs')

# Ensure directories exist
os.makedirs(TEMPLATE_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

# Initialize Jinja2 environment
env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))

def generate_scanner(client_id, client_data):
    """
    Generate customized scanner files for a new client
    
    Args:
        client_id (int): The client's ID
        client_data (dict): Client data including branding information
    
    Returns:
        bool: True if generation was successful, False otherwise
    """
    try:
        # Create client output directory
        client_dir = os.path.join(OUTPUT_DIR, f"client_{client_id}")
        os.makedirs(client_dir, exist_ok=True)
        
        # Create config directory for this client
        config_path = os.path.join(CONFIG_DIR, f"client_{client_id}")
        os.makedirs(config_path, exist_ok=True)
        
        # Save client configuration
        config_file = os.path.join(config_path, 'scanner_config.json')
        
        # Prepare configuration data
        config_data = {
            'client_id': client_id,
            'business_name': client_data.get('business_name', ''),
            'business_domain': client_data.get('business_domain', ''),
            'scanner_name': client_data.get('scanner_name', 'Security Scanner'),
            'primary_color': client_data.get('primary_color', '#FF6900'),
            'secondary_color': client_data.get('secondary_color', '#808588'),
            'default_scans': client_data.get('default_scans', []),
            'logo_path': client_data.get('logo_path', ''),
            'favicon_path': client_data.get('favicon_path', ''),
            'created_at': datetime.now().isoformat(),
            'last_updated': datetime.now().isoformat(),
            'template_version': '1.0'
        }
        
        # Save configuration
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=4)
        
        # Generate HTML template
        html_template = env.get_template('scanner_template.html')
        html_output = html_template.render(
            client=config_data,
            year=datetime.now().year
        )
        
        # Save HTML file
        with open(os.path.join(client_dir, 'index.html'), 'w') as f:
            f.write(html_output)
        
        # Generate CSS template
        css_template = env.get_template('scanner_styles.css')
        css_output = css_template.render(
            primary_color=config_data['primary_color'],
            secondary_color=config_data['secondary_color']
        )
        
        # Save CSS file
        with open(os.path.join(client_dir, 'styles.css'), 'w') as f:
            f.write(css_output)
        
        # Generate JavaScript template
        js_template = env.get_template('scanner_script.js')
        js_output = js_template.render(
            client_id=client_id,
            business_domain=config_data['business_domain'],
            default_scans=config_data['default_scans']
        )
        
        # Save JavaScript file
        with open(os.path.join(client_dir, 'scanner.js'), 'w') as f:
            f.write(js_output)
        
        # Copy logo and favicon if available
        if config_data['logo_path'] and os.path.exists(config_data['logo_path']):
            logo_ext = os.path.splitext(config_data['logo_path'])[1]
            logo_dest = os.path.join(client_dir, f"logo{logo_ext}")
            shutil.copy(config_data['logo_path'], logo_dest)
        
        if config_data['favicon_path'] and os.path.exists(config_data['favicon_path']):
            favicon_ext = os.path.splitext(config_data['favicon_path'])[1]
            favicon_dest = os.path.join(client_dir, f"favicon{favicon_ext}")
            shutil.copy(config_data['favicon_path'], favicon_dest)
        
        # Update deployed_scanners in the database
        from client_db import update_deployment_status
        update_deployment_status(client_id, 'deployed', config_file)
        
        logging.info(f"Scanner generated successfully for client {client_id}")
        return True
    
    except Exception as e:
        logging.error(f"Error generating scanner for client {client_id}: {str(e)}")
        return False

def update_scanner(client_id, client_data):
    """
    Update existing scanner files for a client
    
    Args:
        client_id (int): The client's ID
        client_data (dict): Updated client data
    
    Returns:
        bool: True if update was successful, False otherwise
    """
    try:
        # Check if client directory exists
        client_dir = os.path.join(OUTPUT_DIR, f"client_{client_id}")
        config_path = os.path.join(CONFIG_DIR, f"client_{client_id}")
        
        if not os.path.exists(client_dir):
            # If directory doesn't exist, generate new scanner
            return generate_scanner(client_id, client_data)
        
        # Load existing configuration
        config_file = os.path.join(config_path, 'scanner_config.json')
        
        try:
            with open(config_file, 'r') as f:
                config_data = json.load(f)
        except:
            # If config doesn't exist, create a new one
            config_data = {
                'client_id': client_id,
                'created_at': datetime.now().isoformat(),
                'template_version': '1.0'
            }
        
        # Update configuration with new data
        config_data.update({
            'business_name': client_data.get('business_name', config_data.get('business_name', '')),
            'business_domain': client_data.get('business_domain', config_data.get('business_domain', '')),
            'scanner_name': client_data.get('scanner_name', config_data.get('scanner_name', 'Security Scanner')),
            'primary_color': client_data.get('primary_color', config_data.get('primary_color', '#FF6900')),
            'secondary_color': client_data.get('secondary_color', config_data.get('secondary_color', '#808588')),
            'last_updated': datetime.now().isoformat()
        })
        
        # Update default_scans if provided
        if 'default_scans' in client_data:
            config_data['default_scans'] = client_data['default_scans']
        elif 'default_scans' not in config_data:
            config_data['default_scans'] = []
        
        # Save updated configuration
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=4)
        
        # Update HTML template
        html_template = env.get_template('scanner_template.html')
        html_output = html_template.render(
            client=config_data,
            year=datetime.now().year
        )
        
        # Save HTML file
        with open(os.path.join(client_dir, 'index.html'), 'w') as f:
            f.write(html_output)
        
        # Update CSS template
        css_template = env.get_template('scanner_styles.css')
        css_output = css_template.render(
            primary_color=config_data['primary_color'],
            secondary_color=config_data['secondary_color']
        )
        
        # Save CSS file
        with open(os.path.join(client_dir, 'styles.css'), 'w') as f:
            f.write(css_output)
        
        # Update JavaScript template
        js_template = env.get_template('scanner_script.js')
        js_output = js_template.render(
            client_id=client_id,
            business_domain=config_data['business_domain'],
            default_scans=config_data['default_scans']
        )
        
        # Save JavaScript file
        with open(os.path.join(client_dir, 'scanner.js'), 'w') as f:
            f.write(js_output)
        
        # Update logo if provided
        if 'logo_path' in client_data and client_data['logo_path'] and os.path.exists(client_data['logo_path']):
            config_data['logo_path'] = client_data['logo_path']
            logo_ext = os.path.splitext(client_data['logo_path'])[1]
            logo_dest = os.path.join(client_dir, f"logo{logo_ext}")
            shutil.copy(client_data['logo_path'], logo_dest)
        
        # Update favicon if provided
        if 'favicon_path' in client_data and client_data['favicon_path'] and os.path.exists(client_data['favicon_path']):
            config_data['favicon_path'] = client_data['favicon_path']
            favicon_ext = os.path.splitext(client_data['favicon_path'])[1]
            favicon_dest = os.path.join(client_dir, f"favicon{favicon_ext}")
            shutil.copy(client_data['favicon_path'], favicon_dest)
        
        # Save final configuration
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=4)
        
        # Update deployment status
        from client_db import update_deployment_status
        update_deployment_status(client_id, 'deployed', config_file)
        
        logging.info(f"Scanner updated successfully for client {client_id}")
        return True
    
    except Exception as e:
        logging.error(f"Error updating scanner for client {client_id}: {str(e)}")
        return False

def create_default_templates():
    """
    Create default templates if they don't exist
    """
    try:
        # Create template directory if it doesn't exist
        os.makedirs(TEMPLATE_DIR, exist_ok=True)
        
        # Define default template files
        default_templates = {
            'scanner_template.html': '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ client.scanner_name }}</title>
    <link rel="stylesheet" href="styles.css">
    {% if client.favicon_path %}
    <link rel="icon" href="favicon.ico" type="image/x-icon">
    {% endif %}
</head>
<body>
    <header>
        <div class="logo-container">
            {% if client.logo_path %}
            <img src="logo.png" alt="{{ client.business_name }} Logo" class="logo">
            {% else %}
            <h1>{{ client.scanner_name }}</h1>
            {% endif %}
        </div>
        <nav>
            <ul>
                <li><a href="#" class="active">Dashboard</a></li>
                <li><a href="#">Scans</a></li>
                <li><a href="#">Reports</a></li>
                <li><a href="#">Settings</a></li>
            </ul>
        </nav>
    </header>
    
    <main>
        <section class="scanner-container">
            <h2>Security Scanner</h2>
            <div class="scan-form">
                <input type="text" id="target-input" placeholder="Enter target URL or domain" 
                       value="{{ client.business_domain }}">
                <div class="scan-options">
                    <h3>Scan Options</h3>
                    <div class="options-grid">
                        <label>
                            <input type="checkbox" name="scan_type" value="ssl" checked>
                            SSL/TLS Check
                        </label>
                        <label>
                            <input type="checkbox" name="scan_type" value="headers" checked>
                            HTTP Headers
                        </label>
                        <label>
                            <input type="checkbox" name="scan_type" value="vulnerabilities" checked>
                            Vulnerability Scan
                        </label>
                        <label>
                            <input type="checkbox" name="scan_type" value="ports">
                            Port Scan
                        </label>
                        <label>
                            <input type="checkbox" name="scan_type" value="malware">
                            Malware Detection
                        </label>
                        <label>
                            <input type="checkbox" name="scan_type" value="dns">
                            DNS Analysis
                        </label>
                    </div>
                </div>
                <button id="start-scan-btn" class="primary-btn">Start Scan</button>
            </div>
        </section>
        
        <section class="results-container" style="display: none;">
            <h2>Scan Results</h2>
            <div class="results-summary">
                <div class="summary-item">
                    <h3>Security Score</h3>
                    <div class="score">
                        <span id="security-score">0</span>/100
                    </div>
                </div>
                <div class="summary-item">
                    <h3>Issues Found</h3>
                    <div class="issues">
                        <span id="critical-issues">0</span> Critical
                        <span id="warning-issues">0</span> Warnings
                        <span id="info-issues">0</span> Info
                    </div>
                </div>
            </div>
            
            <div id="results-details" class="results-details">
                <!-- Results will be populated here -->
            </div>
            
            <div class="actions">
                <button id="download-report-btn" class="secondary-btn">Download Report</button>
                <button id="email-report-btn" class="secondary-btn">Email Report</button>
            </div>
        </section>
    </main>
    
    <footer>
        <p>&copy; {{ year }} {{ client.business_name }} - Powered by Security Scanner Platform</p>
    </footer>
    
    <script src="scanner.js"></script>
</body>
</html>''',
            
            'scanner_styles.css': '''/* Reset and base styles */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: #333;
    background-color: #f5f5f5;
}

/* Variables */
:root {
    --primary-color: {{ primary_color }};
    --secondary-color: {{ secondary_color }};
    --light-color: #ffffff;
    --dark-color: #333333;
    --gray-color: #f0f0f0;
    --border-color: #e0e0e0;
    --text-color: #333333;
}

/* Typography */
h1, h2, h3, h4 {
    margin-bottom: 1rem;
    color: var(--dark-color);
}

h1 {
    font-size: 2rem;
}

h2 {
    font-size: 1.5rem;
}

h3 {
    font-size: 1.2rem;
}

/* Layout */
header {
    background-color: var(--light-color);
    padding: 1rem 2rem;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

main {
    max-width: 1200px;
    margin: 2rem auto;
    padding: 0 2rem;
}

section {
    background-color: var(--light-color);
    border-radius: 5px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.05);
    padding: 2rem;
    margin-bottom: 2rem;
}

footer {
    background-color: var(--dark-color);
    color: var(--light-color);
    text-align: center;
    padding: 1rem;
    margin-top: 2rem;
}

/* Logo */
.logo-container {
    display: flex;
    align-items: center;
}

.logo {
    max-height: 50px;
    max-width: 200px;
}

/* Navigation */
nav ul {
    display: flex;
    list-style: none;
}

nav ul li {
    margin-left: 1.5rem;
}

nav ul li a {
    text-decoration: none;
    color: var(--text-color);
    font-weight: 500;
    padding: 0.5rem;
    transition: color 0.3s ease;
}

nav ul li a:hover {
    color: var(--primary-color);
}

nav ul li a.active {
    color: var(--primary-color);
    border-bottom: 2px solid var(--primary-color);
}

/* Form Elements */
input[type="text"] {
    width: 100%;
    padding: 0.8rem 1rem;
    margin-bottom: 1.5rem;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    font-size: 1rem;
}

input[type="text"]:focus {
    outline: none;
    border-color: var(--primary-color);
    box-shadow: 0 0 0 2px rgba(255, 105, 0, 0.1);
}

/* Buttons */
.primary-btn, .secondary-btn {
    padding: 0.8rem 1.5rem;
    border: none;
    border-radius: 4px;
    font-size: 1rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.3s ease;
}

.primary-btn {
    background-color: var(--primary-color);
    color: white;
}

.primary-btn:hover {
    background-color: var(--primary-color);
    opacity: 0.9;
}

.secondary-btn {
    background-color: var(--secondary-color);
    color: white;
    margin-right: 1rem;
}

.secondary-btn:hover {
    background-color: var(--secondary-color);
    opacity: 0.9;
}

/* Scanner Specific */
.scan-form {
    margin-top: 1rem;
}

.scan-options {
    margin-bottom: 1.5rem;
    padding: 1rem;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    background-color: var(--gray-color);
}

.options-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 1rem;
    margin-top: 1rem;
}

.options-grid label {
    display: flex;
    align-items: center;
    cursor: pointer;
}

.options-grid input[type="checkbox"] {
    margin-right: 0.5rem;
}

/* Results */
.results-summary {
    display: flex;
    justify-content: space-around;
    margin-bottom: 2rem;
    padding: 1rem;
    background-color: var(--gray-color);
    border-radius: 4px;
}

.summary-item {
    text-align: center;
}

.score {
    font-size: 2.5rem;
    font-weight: bold;
    color: var(--primary-color);
}

.issues span {
    margin-right: 1rem;
    font-weight: bold;
}

#critical-issues {
    color: #e74c3c;
}

#warning-issues {
    color: #f39c12;
}

#info-issues {
    color: #3498db;
}

.results-details {
    margin-bottom: 2rem;
}

.actions {
    display: flex;
    justify-content: flex-end;
}

/* Responsive */
@media (max-width: 768px) {
    header {
        flex-direction: column;
    }
    
    nav ul {
        margin-top: 1rem;
    }
    
    nav ul li {
        margin: 0 0.75rem;
    }
    
    .results-summary {
        flex-direction: column;
    }
    
    .summary-item {
        margin-bottom: 1rem;
    }
    
    .actions {
        flex-direction: column;
    }
    
    .secondary-btn {
        margin-right: 0;
        margin-bottom: 1rem;
    }
}''',
            
            'scanner_script.js': '''document.addEventListener('DOMContentLoaded', function() {
    // Elements
    const targetInput = document.getElementById('target-input');
    const startScanBtn = document.getElementById('start-scan-btn');
    const resultsContainer = document.querySelector('.results-container');
    const resultsDetails = document.getElementById('results-details');
    const securityScore = document.getElementById('security-score');
    const criticalIssues = document.getElementById('critical-issues');
    const warningIssues = document.getElementById('warning-issues');
    const infoIssues = document.getElementById('info-issues');
    const downloadReportBtn = document.getElementById('download-report-btn');
    const emailReportBtn = document.getElementById('email-report-btn');
    
    // Configuration
    const clientId = {{ client_id }};
    const defaultDomain = "{{ business_domain }}";
    const apiEndpoint = '/api/v1/scan';
    
    // Set default domain if available
    if (defaultDomain) {
        targetInput.value = defaultDomain;
    }
    
    // Set default scan options
    const defaultScans = {{ default_scans|tojson }};
    if (defaultScans && defaultScans.length > 0) {
        const checkboxes = document.querySelectorAll('input[name="scan_type"]');
        checkboxes.forEach(checkbox => {
            checkbox.checked = defaultScans.includes(checkbox.value);
        });
    }
    
    // Start scan button click handler
    startScanBtn.addEventListener('click', function() {
        const target = targetInput.value.trim();
        
        if (!target) {
            alert('Please enter a target URL or domain');
            return;
        }
        
        // Get selected scan types
        const selectedScans = [];
        document.querySelectorAll('input[name="scan_type"]:checked').forEach(checkbox => {
            selectedScans.push(checkbox.value);
        });
        
        if (selectedScans.length === 0) {
            alert('Please select at least one scan type');
            return;
        }
        
        // Disable start button and show loading
        startScanBtn.disabled = true;
        startScanBtn.textContent = 'Scanning...';
        
        // Prepare scan request
        const scanRequest = {
            target: target,
            scan_types: selectedScans,
            client_id: clientId
        };
        
        // Simulate API call and show results
        simulateScan(scanRequest)
            .then(results => {
                displayResults(results);
                startScanBtn.disabled = false;
                startScanBtn.textContent = 'Start Scan';
            })
            .catch(error => {
                alert('An error occurred during the scan: ' + error.message);
                startScanBtn.disabled = false;
                startScanBtn.textContent = 'Start Scan';
            });
    });
    
    // Download report button click handler
    downloadReportBtn.addEventListener('click', function() {
        alert('Report download functionality will be implemented here');
    });
    
    // Email report button click handler
    emailReportBtn.addEventListener('click', function() {
        alert('Email report functionality will be implemented here');
    });
    
    // Function to simulate a scan (will be replaced with actual API call)
    function simulateScan(scanRequest) {
        return new Promise((resolve, reject) => {
            // Simulate network delay
            setTimeout(() => {
                // Mock results
                const results = {
                    target: scanRequest.target,
                    scan_id: 'scan-' + Date.now(),
                    timestamp: new Date().toISOString(),
                    score: Math.floor(Math.random() * 100),
                    issues: {
                        critical: Math.floor(Math.random() * 5),
                        warnings: Math.floor(Math.random() * 10),
                        info: Math.floor(Math.random() * 15)
                    },
                    findings: []
                };
                
                // Generate mock findings based on selected scan types
                scanRequest.scan_types.forEach(scanType => {
                    switch(scanType) {
                        case 'ssl':
                            results.findings.push({
                                type: 'ssl',
                                title: 'SSL/TLS Configuration',
                                severity: getRandomSeverity(),
                                details: 'The server supports TLS 1.2 and 1.3 but also has older protocols enabled.'
                            });
                            break;
                        case 'headers':
                            results.findings.push({
                                type: 'headers',
                                title: 'HTTP Security Headers',
                                severity: getRandomSeverity(),
                                details: 'Missing important security headers: X-Content-Type-Options, X-Frame-Options'
                            });
                            break;
                        case 'vulnerabilities':
                            results.findings.push({
                                type: 'vulnerabilities',
                                title: 'Web Application Vulnerabilities',
                                severity: getRandomSeverity(),
                                details: 'Potential cross-site scripting (XSS) vulnerability detected in search form'
                            });
                            break;
                        case 'ports':
                            results.findings.push({
                                type: 'ports',
                                title: 'Open Ports',
                                severity: getRandomSeverity(),
                                details: 'Found open ports: 80, 443, 22, 25'
                            });
                            break;
                        case 'malware':
                            results.findings.push({
                                type: 'malware',
                                title: 'Malware Detection',
                                severity: 'info',
                                details: 'No malware detected on the website'
                            });
                            break;
                        case 'dns':
                            results.findings.push({
                                type: 'dns',
                                title: 'DNS Configuration',
                                severity: getRandomSeverity(),
                                details: 'SPF record is present but DMARC policy is missing'
                            });
                            break;
                    }
                });
                
                resolve(results);
            }, 2000);
        });
    }
    
    // Helper function to get random severity
    function getRandomSeverity() {
        const severities = ['critical', 'warning', 'info'];
        return severities[Math.floor(Math.random() * severities.length)];
    }
    
    // Function to display scan results
    function displayResults(results) {
        // Show results container
        resultsContainer.style.display = 'block';
        
        // Update summary
        securityScore.textContent = results.score;
        criticalIssues.textContent = results.issues.critical;
        warningIssues.textContent = results.issues.warnings;
        infoIssues.textContent = results.issues.info;
        
        // Clear previous results
        resultsDetails.innerHTML = '';
        
        // Add findings
        if (results.findings.length > 0) {
            const findingsList = document.createElement('ul');
            findingsList.className = 'findings-list';
            
            results.findings.forEach(finding => {
                const findingItem = document.createElement('li');
                findingItem.className = `finding ${finding.severity}`;
                
                findingItem.innerHTML = `
                    <div class="finding-header">
                        <h3>${finding.title}</h3>
                        <span class="severity ${finding.severity}">${finding.severity.toUpperCase()}</span>
                    </div>
                    <div class="finding-details">
                        <p>${finding.details}</p>
                    </div>
                `;
                
                findingsList.appendChild(findingItem);
            });
            
            resultsDetails.appendChild(findingsList);
            
            // Add some CSS for findings
            const style = document.createElement('style');
            style.textContent = `
                .findings-list {
                    list-style: none;
                    padding: 0;
                }
                
                .finding {
                    margin-bottom: 1rem;
                    padding: 1rem;
                    border-radius: 4px;
                    border-left: 4px solid #ccc;
                }
                
                .finding.critical {
                    border-left-color: #e74c3c;
                    background-color: rgba(231, 76, 60, 0.05);
                }
                
                .finding.warning {
                    border-left-color: #f39c12;
                    background-color: rgba(243, 156, 18, 0.05);
                }
                
                .finding.info {
                    border-left-color: #3498db;
                    background-color: rgba(52, 152, 219, 0.05);
                }
                
                .finding-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 0.5rem;
                }
                
                .finding-header h3 {
                    margin: 0;
                }
                
                .severity {
                    padding: 0.25rem 0.5rem;
                    border-radius: 4px;
                    font-size: 0.8rem;
                    font-weight: bold;
                    color: white;
                }
                
                .severity.critical {
                    background-color: #e74c3c;
                }
                
                .severity.warning {
                    background-color: #f39c12;
                }
                
                .severity.info {
                    background-color: #3498db;
                }
                
                .finding-details {
                    margin-top: 0.5rem;
                }
            `;
            
            document.head.appendChild(style);
        } else {
            resultsDetails.innerHTML = '<p>No issues found.</p>';
        }
        
        // Scroll to results
        resultsContainer.scrollIntoView({ behavior: 'smooth' });
    }
});'''
        }
        
        # Create default templates if they don't exist
        for filename, content in default_templates.items():
            file_path = os.path.join(TEMPLATE_DIR, filename)
            if not os.path.exists(file_path):
                with open(file_path, 'w') as f:
                    f.write(content)
                logging.info(f"Created default template: {filename}")
        
        return True
    except Exception as e:
        logging.error(f"Error creating default templates: {str(e)}")
        return False

# Create default templates when module is imported
create_default_templates()
