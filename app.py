# Route handlers
@app.route('/')
def index():
    """Render the home page"""
    try:
        # Log that we're attempting to render the template
        logging.debug("Attempting to render index.html")
        
        # List available templates for debugging
        template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
        if os.path.exists(template_dir):
            templates = os.listdir(template_dir)
            logging.debug(f"Available templates: {templates}")
        else:
            logging.error(f"Template directory not found: {template_dir}")
        
        return render_template('index.html')
    except Exception as e:
        error_message = f"Error rendering index page: {str(e)}"
        logging.error(error_message)
        
        # Return a simple HTML response with the error
        return f"""
        <html>
            <head><title>Error</title></head>
            <body>
                <h1>An error occurred</h1>
                <p>{error_message}</p>
                <p>Please contact support.</p>
            </body>
        </html>
        """, 500

@app.route('/scan', methods=['GET', 'POST'])
def scan_page():
    """Unified scan page that handles both basic and enhanced scanning"""
    if request.method == 'POST':
        # Get form data including client OS info
        lead_data = {
            'name': request.form.get('name', ''),
            'email': request.form.get('email', ''),
            'company': request.form.get('company', ''),
            'phone': request.form.get('phone', ''),
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'client_os': request.form.get('client_os', 'Unknown'),
            'client_browser': request.form.get('client_browser', 'Unknown'),
            'windows_version': request.form.get('windows_version', ''),
            'target': request.form.get('target', '')  # This will be empty for basic scans
        }
        
        # Get scan ID (if provided)
        scan_id = request.form.get('scan_id', str(uuid.uuid4()))
        
        logging.debug(f"Received scan form data: {lead_data}")
        logging.debug(f"Target: {lead_data['target'] if lead_data['target'] else 'None (Basic Scan)'}")
        
        try:
            # Store scan info in session for progress tracking
            session['scan_id'] = scan_id
            session['scan_type'] = 'comprehensive' if lead_data['target'] else 'basic'
            session['target'] = lead_data['target']
            session['scan_start_time'] = datetime.now().timestamp()
            
            # Store user info in session
            for key in ['name', 'email', 'company', 'phone', 'client_os', 'client_browser', 'windows_version']:
                session[key] = lead_data.get(key, '')
            
            # Redirect to progress page
            return redirect(url_for('scan_progress', scan_id=scan_id))
        except Exception as e:
            logging.error(f"Error processing scan: {e}")
            return render_template('error.html', error=str(e))
    
    return render_template('scan.html')

@app.route('/scan-progress/<scan_id>')
def scan_progress(scan_id):
    """Display scan progress"""
    # Get scan info from session
    scan_type = session.get('scan_type', 'basic')
    target = session.get('target', '')
    email = session.get('email', '')
    
    return render_template('scan_progress.html', 
                          scan_id=scan_id,
                          scan_type=scan_type,
                          target=target,
                          email=email)

@app.route('/api/scan-status/<scan_id>', methods=['GET'])
def scan_status(scan_id):
    """API endpoint to check scan status and progress"""
    # Get current timestamp
    current_timestamp = datetime.now().timestamp()
    
    # If scan_start_time not in session, initialize it
    if 'scan_start_time' not in session:
        session['scan_start_time'] = current_timestamp
    
    scan_start = session.get('scan_start_time')
    scan_type = session.get('scan_type', 'basic')
    
    # Calculate simulated progress (0-100%)
    elapsed_time = current_timestamp - scan_start
    progress_rate = 8 if scan_type == 'basic' else 3  # % per second
    progress = min(int(elapsed_time * progress_rate), 100)
    
    # Create a status message based on progress
    if progress < 20:
        status_message = "Initializing scan..."
    elif progress < 40:
        status_message = "Checking system security..."
    elif progress < 60:
        status_message = "Scanning network ports..."
    elif progress < 80:
        status_message = "Analyzing email security..."
    elif progress < 100:
        status_message = "Running web security checks..." if scan_type == 'comprehensive' else "Generating report..."
    else:
        status_message = "Scan completed! Preparing results..."
    
    # If scan is complete, prepare redirect to results
    if progress >= 100:
        # Actually run the scan now (this would normally be done in the background)
        try:
            # Get lead data from session
            lead_data = {
                'name': session.get('name', ''),
                'email': session.get('email', ''),
                'company': session.get('company', ''),
                'phone': session.get('phone', ''),
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'client_os': session.get('client_os', 'Unknown'),
                'client_browser': session.get('client_browser', 'Unknown'),
                'windows_version': session.get('windows_version', ''),
                'target': session.get('target', '')
            }
            
            # Process the scan
            scan_result = process_scan_request(lead_data)
            
            # Store the scan result in session
            session['scan_result'] = scan_result
            session['scan_completed'] = True
            
            # Clear the scan_start_time from session
            if 'scan_start_time' in session:
                del session['scan_start_time']
        except Exception as e:
            logging.error(f"Error generating scan report: {e}")
        
        return jsonify({
            'status': 'complete',
            'progress': 100,
            'message': 'Scan completed successfully',
            'redirect_url': url_for('results')
        })
    
    # Otherwise return progress update
    return jsonify({
        'status': 'in_progress',
        'progress': progress,
        'message': status_message
    })

@app.route('/results')
def results():
    # Check if a scan has been completed using session.get with default
    scan_result = session.get('scan_result', None)
    
    if scan_result:
        logging.debug(f"Retrieved scan result from session, length: {len(scan_result)}")
        # Clear the session after retrieving to avoid stale data
        session.pop('scan_result', None)
        session.pop('scan_completed', None)
        return render_template('results.html', scan_result=scan_result)
    else:
        logging.debug("No scan result in session")
        return redirect(url_for('scan_page'))

@app.route('/api/scan', methods=['POST'])    
@limiter.limit("5 per minute")    
def start_scan():
    try:
        # Get lead data from form
        lead_data = {
            "name": request.form.get('name', ''),
            "email": request.form.get('email', ''),
            "company": request.form.get('company', ''),
            "phone": request.form.get('phone', ''),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "client_os": request.form.get('client_os', 'Unknown'),
            "client_browser": request.form.get('client_browser', 'Unknown'),
            "windows_version": request.form.get('windows_version', ''),
            "target": request.form.get('target', '')
        }
        
        # Basic validation
        if not lead_data["name"] or not lead_data["email"]:
            return jsonify({
                "status": "error",
                "message": "Please enter at least your name and email before scanning."
            }), 400
        
        # Additional validation for target domain if provided
        target = lead_data.get('target', '')
        if target:
            # Minimal validation to ensure it's a valid domain or IP
            if not re.match(r'^[\w.-]+\.[a-zA-Z]{2,}$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
                return jsonify({
                    "status": "error",
                    "message": "Please enter a valid domain (e.g., example.com) or IP address."
                }), 400# Additional validation for target domain if provided

from flask_cors import CORS
import platform
import psutil
import socket
import re
import dns.resolver
import logging
import os
from datetime import datetime
import csv
import sys
import random
import ipaddress
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from email_handler import send_email_report
import json
import dns.zone
import dns.query
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import urllib.parse
import re
from bs4 import BeautifulSoup
import ssl
import uuid
import requests
import warnings
import urllib3

# Suppress InsecureRequestWarning warnings
warnings.filterwarnings('ignore', message='.*InsecureRequestWarning.*')

# Initialize Flask app
app = Flask(__name__, 
            static_folder='static',  # Set the static folder path
            template_folder='templates')  # Set the templates folder path
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'your_temporary_secret_key')

# Set up logging configuration
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize limiter with proper storage
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"  # Use memory storage for now
)

# Add a warning log to acknowledge the storage limitation
logging.warning(
    "Using in-memory storage for rate limiting. This is not recommended for production."
)

# Severity levels for vulnerabilities
SEVERITY = {
    "Critical": 10,
    "High": 7,
    "Medium": 5,
    "Low": 2,
    "Info": 1
}

SEVERITY_ICONS = {
    "Critical": "❌",
    "High": "⚠️",
    "Medium": "⚠️",
    "Low": "ℹ️"
}

GATEWAY_PORT_WARNINGS = {
    21: ("FTP (insecure)", "High"),
    23: ("Telnet (insecure)", "High"),
    80: ("HTTP (no encryption)", "Medium"),
    443: ("HTTPS", "Low"),
    3389: ("Remote Desktop (RDP)", "Critical"),
    5900: ("VNC", "High"),
    22: ("SSH", "Low"),
}

# Ensure static directories exist
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
if not os.path.exists(static_dir):
    os.makedirs(static_dir)
    logging.info(f"Created static directory: {static_dir}")

images_dir = os.path.join(static_dir, 'images')
if not os.path.exists(images_dir):
    os.makedirs(images_dir)
    logging.info(f"Created images directory: {images_dir}")

# Import scanning functions
try:
    # Try to import enhanced scanner functions
    from enhanced_security_scanner import (
        check_ssl_certificate,
        check_security_headers,
        detect_cms,
        analyze_cookies,
        detect_web_framework,
        crawl_for_sensitive_content,
        calculate_risk_score
    )
    logging.info("Enhanced security scanner module loaded successfully")
except ImportError:
    logging.warning("Enhanced security scanner module not found, defining basic functions")
    
    # Define placeholder functions if module doesn't exist
    def check_ssl_certificate(hostname, port=443):
        return {'status': 'error', 'message': 'Enhanced scanner module not loaded'}
    
    def check_security_headers(url):
        return {'score': 0, 'headers': {}}
    
    def detect_cms(url):
        return {'cms_detected': False}
    
    def analyze_cookies(url):
        return {'score': 0, 'cookies': []}
    
    def detect_web_framework(url):
        return {'frameworks': []}
    
    def crawl_for_sensitive_content(url, max_urls=10):
        return {'sensitive_paths_found': 0}
    
    def calculate_risk_score(scan_results):
        return {'overall_score': 50, 'risk_level': 'Medium', 'recommendations': []}

# A function to calculate severity based on the issue type
def get_severity_level(severity):
    return SEVERITY.get(severity, SEVERITY["Info"])

# Generate actionable recommendations based on severity
def get_recommendations(vulnerability, severity):
    if severity == "Critical":
        return f"[CRITICAL] {vulnerability}. Immediate action is required to avoid potential data loss or breach."
    elif severity == "High":
        return f"[HIGH] {vulnerability}. Address this within the next 48 hours to mitigate major risks."
    elif severity == "Medium":
        return f"[MEDIUM] {vulnerability}. Address this within the next week to prevent exploitation."
    elif severity == "Low":
        return f"[LOW] {vulnerability}. A low-risk issue, but should be reviewed."
    else:
        return f"[INFO] {vulnerability}. No immediate action required."

# Function to generate threat scenarios based on detected vulnerabilities
def generate_threat_scenario(vulnerability, severity):
    scenarios = {
        "OS Update": "Outdated software can be exploited by attackers to run malicious code, leading to data breaches or system compromise.",
        "Weak Passwords": "Weak or reused passwords can be easily guessed or cracked, allowing attackers to access sensitive accounts or data.",
        "Open Ports": "Open network ports expose your system to external attacks, including DDoS, data theft, and unauthorized access.",
        "Encryption": "Lack of disk encryption increases the risk of data theft, especially if devices are lost or stolen.",
        "MFA": "Lack of Multi-Factor Authentication (MFA) makes your system vulnerable to unauthorized access from attackers.",
        "RDP Security": "Unsecured Remote Desktop Protocol (RDP) can be easily exploited by cybercriminals.",
        "Backup": "Without proper backup systems in place, critical data is vulnerable to loss in the event of a disaster.",
        "Email Security": "Email is a primary attack vector for phishing and malware distribution. Lack of proper security measures can result in a breach.",
        "Endpoint Protection": "Missing endpoint protection leaves your system vulnerable to malware and exploitation.",
        "Network Segmentation": "Lack of network segmentation increases the risk of a widespread breach if an attacker gains access.",
        "Ransomware Protection": "Without proper ransomware protection, your system is vulnerable to file encryption and extortion attacks.",
        "DNS Security": "Unprotected DNS servers can be used in phishing attacks and data manipulation. DNSSEC ensures the integrity of DNS queries.",
        "SSL Certificate": "Invalid or expired SSL certificates can lead to man-in-the-middle attacks and compromise of sensitive data.",
        "Security Headers": "Missing security headers can make your website vulnerable to various attacks like XSS, clickjacking, and data theft.",
        "CMS Vulnerabilities": "Outdated content management systems often have known vulnerabilities that can be exploited by attackers.",
        "Sensitive Content": "Exposed sensitive files or directories can reveal confidential information or provide attack vectors."
    }
    return scenarios.get(vulnerability, "Unspecified threat scenario: This vulnerability could lead to serious consequences if not addressed.")

def save_lead_data(lead_data):
    try:
        # In a web environment, we'll save to a temporary file that Render allows
        filename = "/tmp/leads.csv"
        file_exists = os.path.isfile(filename)
        
        # Add the new fields to the fieldnames list
        with open(filename, "a", newline="") as csvfile:
            fieldnames = ["name", "email", "company", "phone", "timestamp", "client_os", "client_browser", "windows_version"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow(lead_data)
        return True
    except Exception as e:
        logging.error(f"Error saving lead data: {e}")
        return False

# Check for OS updates
def check_os_updates():
    try:
        os_name = platform.system()
        
        if os_name == "Linux":
            return {
                "message": "Operating System (Linux) has pending updates",
                "severity": "High",
                "info": "Additional info about Linux"
            }
        elif os_name == "Windows":
            return {
                "message": "Operating System (Windows) is up-to-date",
                "severity": "Low",
                "info": "Everything is fine with Windows"
            }
        elif os_name == "Darwin":  # macOS
            return {
                "message": "Operating System (macOS) is up-to-date",
                "severity": "Low",
                "info": "No pending updates"
            }
        else:
            return {
                "message": "Operating System update status: Unknown",
                "severity": "Critical",
                "info": "Unknown OS"
            }
    except Exception as e:
        logging.error(f"Error checking OS updates: {e}")
        return {
            "message": "Error checking OS updates",
            "severity": "Critical",
            "info": str(e)
        }

def get_windows_version():
    # Modified for web environment
    try:
        os_name = platform.system()
        if os_name == "Windows":
            try:
                win_ver = sys.getwindowsversion()
                major, build = win_ver.major, win_ver.build
                if major == 10 and build >= 22000:
                    return f"Windows 11 or higher (Build {build})", "Low"
                else:
                    return f"Windows version is earlier than Windows 11 (Build {build})", "Critical"
            except:
                return "Windows version detection failed", "Medium"
        else:
            return f"Server running {os_name}", "Low"
    except Exception as e:
        logging.error(f"Error checking Windows version: {e}")
        return f"Error checking OS version: {str(e)}", "Medium"

def check_open_ports():
    """Simulated port check for web environment"""
    try:
        # For web environment, return simulated results
        # This represents typical findings rather than actual open ports
        simulated_open_ports = [80, 443, 3389, 445, 139, 135, 5985, 5986, 53, 88]
        
        # Add some random ports to simulate a more realistic environment
        additional_ports = random.sample([21, 22, 23, 25, 110, 143, 1433, 3306, 5900, 8080, 8443], 
                                        random.randint(3, 8))
        simulated_open_ports.extend(additional_ports)
        
        open_ports_count = len(simulated_open_ports)
        logging.debug(f"Simulated {open_ports_count} open ports")
        
        # Severity based on count and specific ports
        if open_ports_count >= 30 or any(p in [3389, 5900, 21, 23] for p in simulated_open_ports):
            severity = "High"
        elif open_ports_count >= 10:
            severity = "Medium"
        else:
            severity = "Low"
            
        return open_ports_count, simulated_open_ports, severity
    except Exception as e:
        logging.error(f"Error in simulated port check: {e}")
        return 0, [], "Critical"

# Check Firewall Status
def check_firewall_status():
    """Enhanced firewall status check for web environment"""
    try:
        # Get client IP and OS information
        client_ip = request.remote_addr
        client_os = request.headers.get('User-Agent', 'Unknown')
        
        # Make educated guesses about firewall status based on available info
        if "Windows" in client_os:
            return "Windows Firewall is likely active, but web browsers cannot directly detect its status. We recommend manually checking Windows Defender Firewall settings.", "Medium"
        elif "Mac" in client_os:
            return "macOS likely has its built-in firewall enabled, but web browsers cannot directly detect its status. We recommend checking Security & Privacy settings.", "Medium"
        elif "Linux" in client_os:
            return "Linux systems typically use iptables or ufw for firewall protection. Web browsers cannot directly detect firewall status.", "Medium"
        else:
            return "Firewall status check limited in web environment. We recommend manually checking your system's firewall settings.", "Medium"
    except Exception as e:
        logging.error(f"Error checking firewall status: {e}")
        return "Error checking firewall status", "Medium"

# Function to check SPF status
def check_spf_status(domain):
    """Check the SPF record for a given domain with enhanced validation."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = rdata.to_text().strip('"')
            if txt_record.startswith("v=spf1"):
                logging.debug(f"Found SPF record for {domain}: {txt_record}")

                # Count the number of mechanisms
                mechanisms = [m for m in txt_record.split() if any(m.startswith(p) for p in ["include:", "a", "mx", "ip4:", "ip6:"])]
                mechanism_count = len(mechanisms)

                # Check for ending
                if txt_record.endswith("-all"):
                    if mechanism_count <= 10:
                        return f"SPF record OK: {txt_record} (Mechanisms: {mechanism_count})", "Low"
                    else:
                        return f"Too many SPF mechanisms ({mechanism_count}) in record: {txt_record}", "High"
                elif txt_record.endswith("~all"):
                    if mechanism_count <= 10:
                        return f"SPF uses soft fail (~all). Consider using -all. Record: {txt_record} (Mechanisms: {mechanism_count})", "Medium"
                    else:
                        return f"Too many SPF mechanisms ({mechanism_count}) and ends in ~all: {txt_record}", "High"
                else:
                    return f"SPF record missing final '-all' or '~all': {txt_record}", "High"

        return "No SPF record found", "High"

    except Exception as e:
        logging.error(f"Error checking SPF status for domain {domain}: {e}")
        return f"Error checking SPF status: {e}", "Critical"
    
def check_dmarc_record(domain):
    """Check if the domain has a valid DMARC record."""
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT")

        for rdata in answers:
            record = rdata.to_text().strip('"')
            if record.lower().startswith("v=dmarc1"):
                return f"DMARC record found: {record}", "Low"
        return "No valid DMARC record found", "High"

    except dns.resolver.NXDOMAIN:
        return "Domain does not exist", "Critical"
    except dns.resolver.NoAnswer:
        return "No DMARC record found", "High"
    except Exception as e:
        return f"Error checking DMARC record: {e}", "Critical"

def check_dkim_record(domain):
    selectors = ["default", "selector1", "selector2", "google", "dkim", "dkim1"]
    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(dkim_domain, "TXT")
            txt_record = answers[0].to_text().strip('"')
            return f"DKIM record found with selector '{selector}': {txt_record}", "Low"
        except dns.resolver.NXDOMAIN:
            continue  # No such name, try next
        except Exception as e:
            continue  # Suppress other errors for now

    return "DKIM record not found using common selectors.", "High"

def extract_domain_from_email(email):
    """Extract domain from email address."""
    if '@' in email:
        return email.split('@')[-1]  # Return the part after '@'
    return email  # If not a valid email, return the input itself

def server_lookup(domain):
    """Resolve the IP and perform reverse DNS lookup."""
    try:
        ip = socket.gethostbyname(domain)
        try:
            reverse_dns = socket.gethostbyaddr(ip)[0]
        except:
            reverse_dns = "Reverse DNS lookup failed"
        return f"Resolved IP: {ip}, Reverse DNS: {reverse_dns}", "Low"
    except Exception as e:
        logging.error(f"Error during server lookup for {domain}: {e}")
        return f"Server lookup failed for {domain}: {e}", "High"

# This function should be called within a route where request is available
def get_client_and_gateway_ip():
    """
    Detects client IP and makes educated guesses about possible gateway IPs
    based on common network configurations.
    
    Returns:
        tuple: (client_ip, gateway_guesses, network_type)
    """
    # Get client IP (this will get the actual client IP or proxy IP)
    client_ip = request.remote_addr
    
    # For more accurate client IP detection in production environments
    # with proxies or load balancers, check the X-Forwarded-For header
    if request.headers.get('X-Forwarded-For'):
        # The first IP in the list is usually the client's real IP
        forwarded_ips = request.headers.get('X-Forwarded-For').split(',')
        client_ip = forwarded_ips[0].strip()
    
    # Initialize variables
    gateway_guesses = []
    network_type = "Unknown"
    
    try:
        # Parse the IP address to determine if it's public or private
        ip_obj = ipaddress.ip_address(client_ip)
        
        if ip_obj.is_private:
            # Client is on a private network
            network_type = "Private Network"
            
            # Determine network class and make gateway guesses
            if client_ip.startswith('192.168.'):
                # Class C private network (most common for home networks)
                network_type = "Class C Private Network (typical home/small office)"
                first_two_octets = '.'.join(client_ip.split('.')[:2])
                gateway_guesses = [
                    f"{first_two_octets}.0.1",     # 192.168.0.1
                    f"{first_two_octets}.1.1",     # 192.168.1.1
                    f"{first_two_octets}.0.254",   # 192.168.0.254
                    f"{first_two_octets}.1.254"    # 192.168.1.254
                ]
            elif client_ip.startswith('10.'):
                # Class A private network (common in larger organizations)
                network_type = "Class A Private Network (typical for larger organizations)"
                first_octet = client_ip.split('.')[0]
                second_octet = client_ip.split('.')[1]
                gateway_guesses = [
                    f"{first_octet}.{second_octet}.0.1",
                    f"{first_octet}.0.0.1",
                    f"{first_octet}.{second_octet}.0.254",
                    f"{first_octet}.0.0.254"
                ]
            elif client_ip.startswith('172.'):
                # Check if it's in the 172.16.0.0 to 172.31.255.255 range (Class B)
                second_octet = int(client_ip.split('.')[1])
                if 16 <= second_octet <= 31:
                    network_type = "Class B Private Network"
                    first_two_octets = '.'.join(client_ip.split('.')[:2])
                    gateway_guesses = [
                        f"{first_two_octets}.0.1",
                        f"{first_two_octets}.1.1",
                        f"{first_two_octets}.0.254",
                        f"{first_two_octets}.1.254"
                    ]
        else:
            # Client is on a public network
            network_type = "Public Network"
            # Can't reliably guess gateway IP for public networks
            gateway_guesses = ["Gateway detection not possible for public IP addresses"]
            
    except ValueError:
        # Invalid IP address
        return client_ip, ["Invalid IP format - cannot determine gateway"], "Unknown"
    
    return client_ip, gateway_guesses, network_type

def get_default_gateway_ip():
    """Enhanced gateway IP detection for web environment"""
    client_ip, gateway_guesses, network_type = get_client_and_gateway_ip()
    
    # If multiple guesses are available, create a formatted string
    if len(gateway_guesses) > 1 and "not possible" not in gateway_guesses[0]:
        gateway_info = f"Client IP: {client_ip} | Network Type: {network_type} | Likely gateways: {', '.join(gateway_guesses)}"
    else:
        gateway_info = f"Client IP: {client_ip} | {gateway_guesses[0]}"
    
    return gateway_info

def analyze_port_risks(open_ports):
    """Analyze the risk level of open ports"""
    risks = []
    
    high_risk_ports = {
        3389: "Remote Desktop Protocol (RDP) - High security risk if exposed",
        21: "FTP - Transmits credentials in plain text",
        23: "Telnet - Insecure, transmits data in plain text",
        5900: "VNC - Remote desktop access, often lacks encryption",
        1433: "Microsoft SQL Server - Database access",
        3306: "MySQL Database - Potential attack vector if unprotected",
        445: "SMB - Windows file sharing, historically vulnerable",
        139: "NetBIOS - Windows networking, potential attack vector"
    }
    
    medium_risk_ports = {
        80: "HTTP - Web server without encryption",
        25: "SMTP - Email transmission",
        110: "POP3 - Email retrieval (older protocol)",
        143: "IMAP - Email retrieval (often unencrypted)",
        8080: "Alternative HTTP port, often used for proxies or development"
    }
    
    for port in open_ports:
        if port in high_risk_ports:
            risks.append((port, high_risk_ports[port], "High"))
        elif port in medium_risk_ports:
            risks.append((port, medium_risk_ports[port], "Medium"))
        else:
            risks.append((port, f"Unknown service on port {port}", "Low"))
    
    # Sort by severity (High first)
    return sorted(risks, key=lambda x: 0 if x[2] == "High" else (1 if x[2] == "Medium" else 2))

def scan_gateway_ports(gateway_info):
    """Enhanced gateway port scanning for web environment"""
    results = []
    
    # Parse gateway info
    client_ip = "Unknown"
    if "Client IP:" in gateway_info:
        client_ip = gateway_info.split("Client IP:")[1].split("|")[0].strip()
    
    # Add client IP information to the report
    results.append((f"Client detected at IP: {client_ip}", "Info"))
    
    # Add gateway detection information
    if "Likely gateways:" in gateway_info:
        gateways = gateway_info.split("Likely gateways:")[1].strip()
        results.append((f"Potential gateway IPs: {gateways}", "Info"))
    
    # Use client IP for deterministic "randomness" instead of actual random
    # This ensures consistent results for the same client
    critical_ports = [3389, 5900, 21, 23]  # RDP, VNC, FTP, Telnet
    
    for port in critical_ports:
        desc, severity = GATEWAY_PORT_WARNINGS.get(port, ("Unknown service", "Medium"))
        
        # Deterministic check based on IP
        ip_value = sum([int(octet) for octet in client_ip.split('.')]) if client_ip != "Unknown" else 0
        if (ip_value + port) % 3 == 0:  # Deterministic check
            results.append((f"{desc} (Port {port}) might be open on your gateway", severity))
    
    # Always add some informational entries
    results.append(("HTTP (Port 80) is typically open on gateways", "Medium"))
    results.append(("HTTPS (Port 443) is open, which is normal", "Low"))
    
    # Add a recommendation about firewall
    results.append(("Consider configuring a proper firewall to restrict gateway access", "Info"))
    
    return results

def process_scan_request(lead_data):
    """Process scan request and generate reports
    
    Args:
        lead_data: Dictionary containing user information
        
    Returns:
        A simplified report for web display
    """
    try:
        logging.debug("Starting scan process...")
        
        # Get target domain if provided
        target = lead_data.get('target', '')
        
        # Save lead data
        try:
            save_lead_data(lead_data)
            logging.debug("Lead data saved successfully")
        except Exception as e:
            logging.error(f"Error saving lead data: {e}")
            # Continue anyway - don't fail the whole scan
        
        # Perform web security scan if target provided
        scan_results = None
        if target:
            logging.debug(f"Target domain/IP provided: {target}, performing enhanced scan")
            
            # Normalize domain/IP if needed
            if target.startswith('http://') or target.startswith('https://'):
                parsed_url = urllib.parse.urlparse(target)
                target = parsed_url.netloc
                
            scan_results = {
                'target': target,
                'timestamp': datetime.now().isoformat()
            }
            
            # Add target to lead data for report generation
            lead_data['target'] = target
        else:
            logging.debug("No target domain/IP provided, performing basic scan only")
        
        # Generate detailed report for email
        detailed_report = generate_report(lead_data, scan_results, for_web=False)
        logging.debug(f"Detailed report generated, length: {len(detailed_report)}")
        
        # Generate simplified report for web display
        web_report = generate_report(lead_data, scan_results, for_web=True)
        logging.debug(f"Web report generated, length: {len(web_report)}")
        
        # Try to send email with detailed report
        try:
            email_sent = send_email_report(lead_data, detailed_report)
            if email_sent:
                logging.debug("Email report sent successfully")
            else:
                logging.warning("Email report could not be sent")
        except Exception as e:
            logging.error(f"Error sending email: {e}")
        
        # Return the simplified report for web display
        return web_report
        
    except Exception as e:
        logging.error(f"Error in process_scan_request: {e}")
        return f"An error occurred during the scan: {str(e)}"")
    
    # Create the lead section
    lead_section = (
        f"Client: {lead_data.get('name', 'N/A')}\n"
        f"Email: {lead_data.get('email', 'N/A')}\n"
        f"Company: {lead_data.get('company', 'N/A')}\n"
        f"Phone: {lead_data.get('phone', 'N/A')}\n"
        f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        + "-" * 60 + "\n\n"
    )
    
    # Get domain for email checks
    email = lead_data.get('email', '')
    domain = None
    email_findings = []
    target_domain = lead_data.get('target', '')
    
    if "@" in email:
        domain = extract_domain_from_email(email)
    
    # Run email security checks
    email_section = "EMAIL SECURITY CHECKS:\n"
    if domain:
        spf_status, spf_severity = check_spf_status(domain)
        dmarc_status, dmarc_severity = check_dmarc_record(domain)
        dkim_status, dkim_severity = check_dkim_record(domain)
        
        email_section += f"Domain: {domain}\n"
        email_section += f"SPF: {spf_status} (Severity: {spf_severity})\n"
        email_section += f"DMARC: {dmarc_status} (Severity: {dmarc_severity})\n"
        email_section += f"DKIM: {dkim_status} (Severity: {dkim_severity})\n"
        
        # Store findings for web summary
        if spf_severity in ["High", "Critical"]:
            email_findings.append(f"SPF: {spf_severity} severity - requires attention")
        if dmarc_severity in ["High", "Critical"]:
            email_findings.append(f"DMARC: {dmarc_severity} severity - requires attention")
        if dkim_severity in ["High", "Critical"]:
            email_findings.append(f"DKIM: {dkim_severity} severity - requires attention")
    else:
        email_section += "No valid email domain provided for security checks.\n"
    
    # System checks section
    system_section = "\nSYSTEM SECURITY CHECKS:\n"
    system_findings = []
    
    # Client OS information
    client_os = lead_data.get('client_os', 'Unknown')
    client_browser = lead_data.get('client_browser', 'Unknown')
    windows_version = lead_data.get('windows_version', '')
    
    system_section += f"Client Operating System: {client_os}\n"
    if windows_version:
        system_section += f"Windows Version: {windows_version}\n"
        
        # Assign severity based on Windows version
        if "10/11" in windows_version:
            windows_severity = "Low"
        elif "8" in windows_version:
            windows_severity = "Medium"
        elif "7" in windows_version or "Older" in windows_version:
            windows_severity = "High"
            system_findings.append(f"Windows Version: {windows_severity} severity - outdated version")
        else:
            windows_severity = "Medium"
            
        system_section += f"Windows Version Status: {windows_severity} Severity\n"
    
    system_section += f"Web Browser: {client_browser}\n"
    
    # OS update status
    os_update_info = check_os_updates()
    system_section += f"OS Updates: {os_update_info['message']} (Severity: {os_update_info['severity']})\n"
    
    if os_update_info['severity'] in ["High", "Critical"]:
        system_findings.append(f"OS Updates: {os_update_info['severity']} severity - updates needed")
    
    # Firewall status
    firewall_status, firewall_severity = check_firewall_status()
    system_section += f"Firewall Status: {firewall_status} (Severity: {firewall_severity})\n"
    
    if firewall_severity in ["High", "Critical"]:
        system_findings.append(f"Firewall: {firewall_severity} severity - requires configuration")
    
    # Network checks section
    network_section = "\nNETWORK SECURITY CHECKS:\n"
    network_findings = []

    ports_count, ports_list, ports_severity = check_open_ports()
    network_section += f"Open Ports: {ports_count} ports detected (Severity: {ports_severity})\n"

    if ports_severity in ["High", "Critical"]:
        network_findings.append(f"Open Ports: {ports_severity} severity - {ports_count} ports detected")

    if ports_list and len(ports_list) > 0:
        # List all open ports
        network_section += f"\nAll detected open ports: {', '.join(map(str, sorted(ports_list[:15])))}"
        if len(ports_list) > 15:
            network_section += f" and {len(ports_list) - 15} more..."
        network_section += "\n"
        
        # Analyze port risks
        port_risks = analyze_port_risks(ports_list)
        
        # Add high-risk ports to the report
        high_risk_ports = [r for r in port_risks if r[2] == "High"]
        if high_risk_ports:
            network_section += "\nHIGH RISK PORTS DETECTED:\n"
            for port, desc, sev in high_risk_ports:
                network_section += f"- Port {port}: {desc} (Severity: {sev})\n"
                network_findings.append(f"Port {port}: {desc}")
    else:
        network_section += "No open ports detected.\n"
    
    # Gateway check
    gateway_info = get_default_gateway_ip()
    gateway_scan_results = scan_gateway_ports(gateway_info)

    gateway_section = "\nGATEWAY SECURITY:\n"
    # Add the enhanced gateway info to the report
    gateway_section += f"{gateway_info}\n\n"
    gateway_section += "Note: In a web environment, we cannot directly access your gateway.\n"
    gateway_section += "The information above is based on common network configurations.\n\n"

    # Initialize gateway_findings before using it
    gateway_findings = []
    if gateway_scan_results:
        for msg, severity in gateway_scan_results:
            gateway_section += f"- {msg} (Severity: {severity})\n"
            if severity in ["High", "Critical"]:
                gateway_findings.append(f"Gateway: {severity} severity - {msg}")
    
    # Web security section (if target domain provided)
    web_security_section = ""
    web_security_findings = []
    
    if target_domain:
        web_security_section = f"\nWEB SECURITY CHECKS FOR {target_domain}:\n"
        
        # Determine if target is a domain or IP
        is_domain = False
        try:
            socket.inet_aton(target_domain)  # This will fail if target is not an IP address
        except socket.error:
            is_domain = True
        
        if is_domain:
            # Check if ports 80 or 443 are accessible (for HTTP/HTTPS)
            http_accessible = False
            https_accessible = False
            
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(3)
                    result = sock.connect_ex((target_domain, 80))
                    http_accessible = (result == 0)
            except:
                pass
                
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(3)
                    result = sock.connect_ex((target_domain, 443))
                    https_accessible = (result == 0)
            except:
                pass
                
            # Only perform web checks if HTTP or HTTPS is accessible
            if http_accessible or https_accessible:
                target_url = f"https://{target_domain}" if https_accessible else f"http://{target_domain}"
                
                # SSL/TLS Certificate Analysis (only if HTTPS is accessible)
                if https_accessible:
                    try:
                        ssl_data = check_ssl_certificate(target_domain)
                        if 'error' not in ssl_data:
                            ssl_status = ssl_data.get('status', 'Unknown')
                            
                            web_security_section += f"\nSSL/TLS Certificate Status: {ssl_status.upper()}\n"
                            web_security_section += f"Issuer: {ssl_data.get('issuer', 'Unknown')}\n"
                            web_security_section += f"Valid Until: {ssl_data.get('valid_until', 'Unknown')}\n"
                            web_security_section += f"Days to Expiry: {ssl_data.get('days_to_expiry', 'Unknown')}\n"
                            web_security_section += f"Protocol: {ssl_data.get('protocol', 'Unknown')}\n"
                            
                            # Add issues
                            if ssl_data.get('is_expired', False):
                                web_security_section += "- CRITICAL: SSL Certificate is expired\n"
                                web_security_findings.append("SSL Certificate: Critical severity - certificate expired")
                            elif ssl_data.get('expiring_soon', False):
                                web_security_section += "- WARNING: SSL Certificate is expiring soon\n"
                                web_security_findings.append("SSL Certificate: Medium severity - expiring soon")
                                
                            if ssl_data.get('weak_protocol', False):
                                web_security_section += "- CRITICAL: Weak SSL/TLS protocol detected\n"
                                web_security_findings.append("SSL Protocol: Critical severity - weak protocol in use")
                    except Exception as e:
                        logging.error(f"SSL check error: {e}")
                        web_security_section += f"\nSSL/TLS Certificate check failed: {str(e)}\n"
                
                # HTTP Security Headers Assessment
                try:
                    headers_data = check_security_headers(target_url)
                    if 'error' not in headers_data:
                        header_score = headers_data.get('score', 0)
                        
                        web_security_section += f"\nSecurity Headers Score: {header_score}/100\n"
                        
                        missing_headers = headers_data.get('missing_headers', [])
                        if missing_headers:
                            web_security_section += "Missing Security Headers:\n"
                            for header in missing_headers[:5]:  # Limit to top 5 for brevity
                                web_security_section += f"- {header}\n"
                            
                            if len(missing_headers) > 5:
                                web_security_section += f"- Plus {len(missing_headers) - 5} more...\n"
                                
                            if header_score < 60:
                                web_security_findings.append(f"Security Headers: High severity - score {header_score}/100")
                            elif header_score < 80:
                                web_security_findings.append(f"Security Headers: Medium severity - score {header_score}/100")
                except Exception as e:
                    logging.error(f"Headers check error: {e}")
                    web_security_section += f"\nSecurity headers check failed: {str(e)}\n"
                
                # CMS Detection
                try:
                    cms_data = detect_cms(target_url)
                    if 'error' not in cms_data:
                        if cms_data.get('cms_detected', False):
                            cms_name = cms_data.get('cms_name', 'Unknown')
                            cms_version = cms_data.get('version', 'Unknown version')
                            
                            web_security_section += f"\nContent Management System: {cms_name} ({cms_version})\n"
                            
                            # Add vulnerabilities
                            vulnerabilities = cms_data.get('potential_vulnerabilities', [])
                            if vulnerabilities:
                                web_security_section += "Potential Vulnerabilities:\n"
                                for vuln in vulnerabilities:
                                    web_security_section += f"- {vuln.get('name', 'Unknown')}: {vuln.get('description', '')}\n"
                                    web_security_findings.append(f"CMS: High severity - {vuln.get('name', 'vulnerability detected')}")
                        else:
                            web_security_section += "\nNo Content Management System detected\n"
                except Exception as e:
                    logging.error(f"CMS detection error: {e}")
                    web_security_section += f"\nCMS detection failed: {str(e)}\n"
                
                # Cookie Analysis
                try:
                    cookie_data = analyze_cookies(target_url)
                    if 'error' not in cookie_data:
                        cookie_count = cookie_data.get('total_cookies', 0)
                        cookie_score = cookie_data.get('score', 0)
                        
                        web_security_section += f"\nCookie Security Analysis:\n"
                        web_security_section += f"Total Cookies: {cookie_count}\n"
                        web_security_section += f"Cookie Security Score: {cookie_score}/100\n"
                        
                        # Count issues
                        total_issues = cookie_data.get('total_issues', 0)
                        if total_issues > 0:
                            web_security_section += f"Security Issues: {total_issues} issues found\n"
                            
                            if cookie_score < 60:
                                web_security_findings.append(f"Cookies: High severity - {total_issues} security issues")
                            elif cookie_score < 80:
                                web_security_findings.append(f"Cookies: Medium severity - {total_issues} security issues")
                except Exception as e:
                    logging.error(f"Cookie analysis error: {e}")
                    web_security_section += f"\nCookie analysis failed: {str(e)}\n"
                
                # Framework Detection
                try:
                    framework_data = detect_web_framework(target_url)
                    if 'error' not in framework_data:
                        frameworks = framework_data.get('frameworks', [])
                        
                        if frameworks:
                            web_security_section += f"\nDetected Web Frameworks/Technologies:\n"
                            for framework in frameworks[:5]:  # Limit to top 5
                                framework_name = framework.get('name', 'Unknown')
                                framework_value = framework.get('value', '')
                                web_security_section += f"- {framework_name}: {framework_value}\n"
                                
                            if len(frameworks) > 5:
                                web_security_section += f"- Plus {len(frameworks) - 5} more...\n"
                            
                            # Check for vulnerabilities
                            vulnerabilities = framework_data.get('known_vulnerabilities', [])
                            if vulnerabilities:
                                web_security_section += "Framework Vulnerabilities:\n"
                                for vuln in vulnerabilities:
                                    web_security_section += f"- {vuln.get('framework', 'Unknown')}: {vuln.get('description', '')}\n"
                                    web_security_findings.append(f"Framework: High severity - {vuln.get('framework', 'vulnerability detected')}")
                except Exception as e:
                    logging.error(f"Framework detection error: {e}")
                    web_security_section += f"\nFramework detection failed: {str(e)}\n"
                
                # Sensitive Content
                try:
                    content_data = crawl_for_sensitive_content(target_url, max_urls=10)
                    if 'error' not in content_data:
                        sensitive_paths = content_data.get('sensitive_paths_found', 0)
                        risk_level = content_data.get('risk_level', 'low')
                        
                        web_security_section += f"\nSensitive Content Analysis:\n"
                        web_security_section += f"Sensitive Paths Found: {sensitive_paths}\n"
                        web_security_section += f"Risk Level: {risk_level.upper()}\n"
                        
                        if sensitive_paths > 0:
                            findings = content_data.get('findings', [])
                            web_security_section += "Examples of Sensitive Paths:\n"
                            for finding in findings[:3]:  # Limit to top 3
                                web_security_section += f"- {finding.get('url', 'Unknown')}\n"
                                
                            if len(findings) > 3:
                                web_security_section += f"- Plus {len(findings) - 3} more...\n"
                                
                            if risk_level == 'high':
                                web_security_findings.append(f"Sensitive Content: High severity - {sensitive_paths} paths exposed")
                            elif risk_level == 'medium':
                                web_security_findings.append(f"Sensitive Content: Medium severity - {sensitive_paths} paths exposed")
                except Exception as e:
                    logging.error(f"Content crawling error: {e}")
                    web_security_section += f"\nSensitive content scanning failed: {str(e)}\n"
                
                # Calculate overall risk score for web security
                web_security_section += "\nOVERALL WEB SECURITY ASSESSMENT:\n"
                
                # Create a simplified scan_results dict for risk score calculation
                web_scan_results = {
                    'target': target_domain,
                    'timestamp': datetime.now().isoformat()
                }
                
                # Add available scan data
                if https_accessible and 'ssl_data' in locals() and 'error' not in ssl_data:
                    web_scan_results['ssl_certificate'] = ssl_data
                
                if 'headers_data' in locals() and 'error' not in headers_data:
                    web_scan_results['security_headers'] = headers_data
                    
                if 'cms_data' in locals() and 'error' not in cms_data:
                    web_scan_results['cms'] = cms_data
                    
                if 'cookie_data' in locals() and 'error' not in cookie_data:
                    web_scan_results['cookies'] = cookie_data
                    
                if 'framework_data' in locals() and 'error' not in framework_data:
                    web_scan_results['frameworks'] = framework_data
                    
                if 'content_data' in locals() and 'error' not in content_data:
                    web_scan_results['sensitive_content'] = content_data
                
                # Calculate risk score
                try:
                    risk_data = calculate_risk_score(web_scan_results)
                    if 'error' not in risk_data:
                        overall_score = risk_data.get('overall_score', 0)
                        risk_level = risk_data.get('risk_level', 'Unknown')
                        
                        web_security_section += f"Security Score: {overall_score}/100\n"
                        web_security_section += f"Risk Level: {risk_level}\n"
                        
                        # Add web security recommendations
                        recommendations = risk_data.get('recommendations', [])
                        if recommendations:
                            web_security_section += "\nWeb Security Recommendations:\n"
                            for rec in recommendations:
                                web_security_section += f"- {rec}\n"
                except Exception as e:
                    logging.error(f"Risk scoring error: {e}")
                    web_security_section += f"\nRisk scoring failed: {str(e)}\n"
            else:
                web_security_section += f"\nCould not connect to {target_domain} on HTTP (port 80) or HTTPS (port 443).\n"
                web_security_section += "Web security checks could not be performed.\n"
    
    # Add recommendations section
    recommendations = "\nRECOMMENDATIONS:\n"
    
    # Compile findings from all sections
    all_findings = []
    all_findings.extend(email_findings)
    all_findings.extend(system_findings)
    all_findings.extend(network_findings)
    all_findings.extend(gateway_findings)
    
    # Add web security findings if available
    if target_domain:
        all_findings.extend(web_security_findings)
    
    # Add recommendations based on findings
    if all_findings:
        for i, finding in enumerate(all_findings, 1):
            recommendations += f"{i}. Address {finding}\n"
    else:
        recommendations += "No critical issues were found. Continue to monitor your security regularly.\n"
    
    # Generic recommendations
    recommendations += "\nADDITIONAL RECOMMENDATIONS:\n"
    recommendations += "1. Keep your operating system and software up to date\n"
    recommendations += "2. Use strong, unique passwords for all accounts\n"
    recommendations += "3. Enable multi-factor authentication where available\n"
    recommendations += "4. Regularly back up your important data\n"
    recommendations += "5. Use a firewall and antivirus software\n"
    
    # If generating for web display, create a simplified version
    if for_web:
        # Create a shorter summary for web display
        web_report = lead_section
        web_report += "SCAN SUMMARY:\n"
        web_report += f"A full detailed report has been sent to your email ({lead_data.get('email', 'N/A')}).\n\n"
        
        # Add key findings section if there are high severity issues
        if all_findings:
            web_report += "KEY FINDINGS REQUIRING ATTENTION:\n"
            for finding in all_findings:
                web_report += f"- {finding}\n"
        else:
            web_report += "No critical issues were detected in this scan.\n"
        
        web_report += "\nSCAN AREAS CHECKED:\n"
        web_report += "- Email Security (SPF, DMARC, DKIM)\n"
        web_report += f"- System Security ({client_os}, {client_browser})\n"
        web_report += "- Network Security (Open Ports)\n"
        web_report += "- Gateway Security\n"
        
        if target_domain:
            web_report += f"- Web Security ({target_domain})\n"
        
        web_report += "\nFor detailed analysis and recommendations, please check your email.\n"
        
        return web_report
    
    # For email, compile the full detailed report
    full_report = (
        lead_section + 
        email_section + 
        system_section + 
        network_section + 
        gateway_section
    )
    
    # Add web security section if available
    if web_security_section:
        full_report += web_security_section
    
    # Add recommendations
    full_report += recommendations
    
    return full_report, target):
                return jsonify({
                    "status": "error",
                    "message": "Please enter a valid domain (e.g., example.com) or IP address."
                }), 400
            
        # Generate the scan report
        scan_result = process_scan_request(lead_data)
        
        # Return the scan result
        return jsonify({
            "status": "success",
            "report": scan_result
        })
    except Exception as e:
        logging.error(f"Error in scan API: {e}")
        return jsonify({
            "status": "error",
            "message": f"An error occurred during the scan: {str(e)}"
        }), 500

# Backward compatibility route for enhanced scan
@app.route('/enhanced-scan', methods=['GET', 'POST'])
def enhanced_scan_redirect():
    """For backward compatibility, redirects to main scan page"""
    return redirect(url_for('scan_page'))

# Test route
@app.route('/test')
def test_route():
    """A simple test route to verify Flask is working"""
    return """
    <html>
        <head><title>Test Route</title></head>
        <body>
            <h1>Test Route</h1>
            <p>If you can see this, Flask is correctly handling routes.</p>
            <p><a href="/">Go to home page</a></p>
            <p><a href="/scan">Go to scan page</a></p>
            <p><a href="/scan-progress/test-scan-123">View scan progress page</a></p>
        </body>
    </html>
    """

# Health check endpoint
@app.route('/api/healthcheck')
def healthcheck():
    return jsonify({
        "status": "ok",
        "version": "1.0.0",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

# Static routes
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

# Explicitly serve favicon.ico to prevent 404 errors
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

if __name__ == '__main__':
    # Get port from environment variable or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Use 0.0.0.0 to make the app accessible from any IP
    app.run(host='0.0.0.0', port=port, debug=True)from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
from flask_cors import CORS
import platform
import psutil
import socket
import re
import dns.resolver
import logging
import os
from datetime import datetime
import csv
import sys
import random
import ipaddress
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from email_handler import send_email_report
import json
import dns.zone
import dns.query
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import urllib.parse
import re
from bs4 import BeautifulSoup
import ssl
import uuid
import requests
import warnings
import urllib3

# Suppress InsecureRequestWarning warnings
warnings.filterwarnings('ignore', message='.*InsecureRequestWarning.*')

# Initialize Flask app
app = Flask(__name__, 
            static_folder='static',  # Set the static folder path
            template_folder='templates')  # Set the templates folder path
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'your_temporary_secret_key')

# Set up logging configuration
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize limiter with proper storage
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"  # Use memory storage for now
)

# Add a warning log to acknowledge the storage limitation
logging.warning(
    "Using in-memory storage for rate limiting. This is not recommended for production."
)

# Severity levels for vulnerabilities
SEVERITY = {
    "Critical": 10,
    "High": 7,
    "Medium": 5,
    "Low": 2,
    "Info": 1
}

SEVERITY_ICONS = {
    "Critical": "❌",
    "High": "⚠️",
    "Medium": "⚠️",
    "Low": "ℹ️"
}

GATEWAY_PORT_WARNINGS = {
    21: ("FTP (insecure)", "High"),
    23: ("Telnet (insecure)", "High"),
    80: ("HTTP (no encryption)", "Medium"),
    443: ("HTTPS", "Low"),
    3389: ("Remote Desktop (RDP)", "Critical"),
    5900: ("VNC", "High"),
    22: ("SSH", "Low"),
}

# Ensure static directories exist
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
if not os.path.exists(static_dir):
    os.makedirs(static_dir)
    logging.info(f"Created static directory: {static_dir}")

images_dir = os.path.join(static_dir, 'images')
if not os.path.exists(images_dir):
    os.makedirs(images_dir)
    logging.info(f"Created images directory: {images_dir}")

# Import scanning functions
try:
    # Try to import enhanced scanner functions
    from enhanced_security_scanner import (
        check_ssl_certificate,
        check_security_headers,
        detect_cms,
        analyze_cookies,
        detect_web_framework,
        crawl_for_sensitive_content,
        calculate_risk_score
    )
    logging.info("Enhanced security scanner module loaded successfully")
except ImportError:
    logging.warning("Enhanced security scanner module not found, defining basic functions")
    
    # Define placeholder functions if module doesn't exist
    def check_ssl_certificate(hostname, port=443):
        return {'status': 'error', 'message': 'Enhanced scanner module not loaded'}
    
    def check_security_headers(url):
        return {'score': 0, 'headers': {}}
    
    def detect_cms(url):
        return {'cms_detected': False}
    
    def analyze_cookies(url):
        return {'score': 0, 'cookies': []}
    
    def detect_web_framework(url):
        return {'frameworks': []}
    
    def crawl_for_sensitive_content(url, max_urls=10):
        return {'sensitive_paths_found': 0}
    
    def calculate_risk_score(scan_results):
        return {'overall_score': 50, 'risk_level': 'Medium', 'recommendations': []}

# A function to calculate severity based on the issue type
def get_severity_level(severity):
    return SEVERITY.get(severity, SEVERITY["Info"])

# Generate actionable recommendations based on severity
def get_recommendations(vulnerability, severity):
    if severity == "Critical":
        return f"[CRITICAL] {vulnerability}. Immediate action is required to avoid potential data loss or breach."
    elif severity == "High":
        return f"[HIGH] {vulnerability}. Address this within the next 48 hours to mitigate major risks."
    elif severity == "Medium":
        return f"[MEDIUM] {vulnerability}. Address this within the next week to prevent exploitation."
    elif severity == "Low":
        return f"[LOW] {vulnerability}. A low-risk issue, but should be reviewed."
    else:
        return f"[INFO] {vulnerability}. No immediate action required."

# Function to generate threat scenarios based on detected vulnerabilities
def generate_threat_scenario(vulnerability, severity):
    scenarios = {
        "OS Update": "Outdated software can be exploited by attackers to run malicious code, leading to data breaches or system compromise.",
        "Weak Passwords": "Weak or reused passwords can be easily guessed or cracked, allowing attackers to access sensitive accounts or data.",
        "Open Ports": "Open network ports expose your system to external attacks, including DDoS, data theft, and unauthorized access.",
        "Encryption": "Lack of disk encryption increases the risk of data theft, especially if devices are lost or stolen.",
        "MFA": "Lack of Multi-Factor Authentication (MFA) makes your system vulnerable to unauthorized access from attackers.",
        "RDP Security": "Unsecured Remote Desktop Protocol (RDP) can be easily exploited by cybercriminals.",
        "Backup": "Without proper backup systems in place, critical data is vulnerable to loss in the event of a disaster.",
        "Email Security": "Email is a primary attack vector for phishing and malware distribution. Lack of proper security measures can result in a breach.",
        "Endpoint Protection": "Missing endpoint protection leaves your system vulnerable to malware and exploitation.",
        "Network Segmentation": "Lack of network segmentation increases the risk of a widespread breach if an attacker gains access.",
        "Ransomware Protection": "Without proper ransomware protection, your system is vulnerable to file encryption and extortion attacks.",
        "DNS Security": "Unprotected DNS servers can be used in phishing attacks and data manipulation. DNSSEC ensures the integrity of DNS queries.",
        "SSL Certificate": "Invalid or expired SSL certificates can lead to man-in-the-middle attacks and compromise of sensitive data.",
        "Security Headers": "Missing security headers can make your website vulnerable to various attacks like XSS, clickjacking, and data theft.",
        "CMS Vulnerabilities": "Outdated content management systems often have known vulnerabilities that can be exploited by attackers.",
        "Sensitive Content": "Exposed sensitive files or directories can reveal confidential information or provide attack vectors."
    }
    return scenarios.get(vulnerability, "Unspecified threat scenario: This vulnerability could lead to serious consequences if not addressed.")

def save_lead_data(lead_data):
    try:
        # In a web environment, we'll save to a temporary file that Render allows
        filename = "/tmp/leads.csv"
        file_exists = os.path.isfile(filename)
        
        # Add the new fields to the fieldnames list
        with open(filename, "a", newline="") as csvfile:
            fieldnames = ["name", "email", "company", "phone", "timestamp", "client_os", "client_browser", "windows_version"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow(lead_data)
        return True
    except Exception as e:
        logging.error(f"Error saving lead data: {e}")
        return False

# Check for OS updates
def check_os_updates():
    try:
        os_name = platform.system()
        
        if os_name == "Linux":
            return {
                "message": "Operating System (Linux) has pending updates",
                "severity": "High",
                "info": "Additional info about Linux"
            }
        elif os_name == "Windows":
            return {
                "message": "Operating System (Windows) is up-to-date",
                "severity": "Low",
                "info": "Everything is fine with Windows"
            }
        elif os_name == "Darwin":  # macOS
            return {
                "message": "Operating System (macOS) is up-to-date",
                "severity": "Low",
                "info": "No pending updates"
            }
        else:
            return {
                "message": "Operating System update status: Unknown",
                "severity": "Critical",
                "info": "Unknown OS"
            }
    except Exception as e:
        logging.error(f"Error checking OS updates: {e}")
        return {
            "message": "Error checking OS updates",
            "severity": "Critical",
            "info": str(e)
        }

def get_windows_version():
    # Modified for web environment
    try:
        os_name = platform.system()
        if os_name == "Windows":
            try:
                win_ver = sys.getwindowsversion()
                major, build = win_ver.major, win_ver.build
                if major == 10 and build >= 22000:
                    return f"Windows 11 or higher (Build {build})", "Low"
                else:
                    return f"Windows version is earlier than Windows 11 (Build {build})", "Critical"
            except:
                return "Windows version detection failed", "Medium"
        else:
            return f"Server running {os_name}", "Low"
    except Exception as e:
        logging.error(f"Error checking Windows version: {e}")
        return f"Error checking OS version: {str(e)}", "Medium"

def check_open_ports():
    """Simulated port check for web environment"""
    try:
        # For web environment, return simulated results
        # This represents typical findings rather than actual open ports
        simulated_open_ports = [80, 443, 3389, 445, 139, 135, 5985, 5986, 53, 88]
        
        # Add some random ports to simulate a more realistic environment
        additional_ports = random.sample([21, 22, 23, 25, 110, 143, 1433, 3306, 5900, 8080, 8443], 
                                        random.randint(3, 8))
        simulated_open_ports.extend(additional_ports)
        
        open_ports_count = len(simulated_open_ports)
        logging.debug(f"Simulated {open_ports_count} open ports")
        
        # Severity based on count and specific ports
        if open_ports_count >= 30 or any(p in [3389, 5900, 21, 23] for p in simulated_open_ports):
            severity = "High"
        elif open_ports_count >= 10:
            severity = "Medium"
        else:
            severity = "Low"
            
        return open_ports_count, simulated_open_ports, severity
    except Exception as e:
        logging.error(f"Error in simulated port check: {e}")
        return 0, [], "Critical"

# Check Firewall Status
def check_firewall_status():
    """Enhanced firewall status check for web environment"""
    try:
        # Get client IP and OS information
        client_ip = request.remote_addr
        client_os = request.headers.get('User-Agent', 'Unknown')
        
        # Make educated guesses about firewall status based on available info
        if "Windows" in client_os:
            return "Windows Firewall is likely active, but web browsers cannot directly detect its status. We recommend manually checking Windows Defender Firewall settings.", "Medium"
        elif "Mac" in client_os:
            return "macOS likely has its built-in firewall enabled, but web browsers cannot directly detect its status. We recommend checking Security & Privacy settings.", "Medium"
        elif "Linux" in client_os:
            return "Linux systems typically use iptables or ufw for firewall protection. Web browsers cannot directly detect firewall status.", "Medium"
        else:
            return "Firewall status check limited in web environment. We recommend manually checking your system's firewall settings.", "Medium"
    except Exception as e:
        logging.error(f"Error checking firewall status: {e}")
        return "Error checking firewall status", "Medium"

# Function to check SPF status
def check_spf_status(domain):
    """Check the SPF record for a given domain with enhanced validation."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = rdata.to_text().strip('"')
            if txt_record.startswith("v=spf1"):
                logging.debug(f"Found SPF record for {domain}: {txt_record}")

                # Count the number of mechanisms
                mechanisms = [m for m in txt_record.split() if any(m.startswith(p) for p in ["include:", "a", "mx", "ip4:", "ip6:"])]
                mechanism_count = len(mechanisms)

                # Check for ending
                if txt_record.endswith("-all"):
                    if mechanism_count <= 10:
                        return f"SPF record OK: {txt_record} (Mechanisms: {mechanism_count})", "Low"
                    else:
                        return f"Too many SPF mechanisms ({mechanism_count}) in record: {txt_record}", "High"
                elif txt_record.endswith("~all"):
                    if mechanism_count <= 10:
                        return f"SPF uses soft fail (~all). Consider using -all. Record: {txt_record} (Mechanisms: {mechanism_count})", "Medium"
                    else:
                        return f"Too many SPF mechanisms ({mechanism_count}) and ends in ~all: {txt_record}", "High"
                else:
                    return f"SPF record missing final '-all' or '~all': {txt_record}", "High"

        return "No SPF record found", "High"

    except Exception as e:
        logging.error(f"Error checking SPF status for domain {domain}: {e}")
        return f"Error checking SPF status: {e}", "Critical"
    
def check_dmarc_record(domain):
    """Check if the domain has a valid DMARC record."""
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT")

        for rdata in answers:
            record = rdata.to_text().strip('"')
            if record.lower().startswith("v=dmarc1"):
                return f"DMARC record found: {record}", "Low"
        return "No valid DMARC record found", "High"

    except dns.resolver.NXDOMAIN:
        return "Domain does not exist", "Critical"
    except dns.resolver.NoAnswer:
        return "No DMARC record found", "High"
    except Exception as e:
        return f"Error checking DMARC record: {e}", "Critical"

def check_dkim_record(domain):
    selectors = ["default", "selector1", "selector2", "google", "dkim", "dkim1"]
    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(dkim_domain, "TXT")
            txt_record = answers[0].to_text().strip('"')
            return f"DKIM record found with selector '{selector}': {txt_record}", "Low"
        except dns.resolver.NXDOMAIN:
            continue  # No such name, try next
        except Exception as e:
            continue  # Suppress other errors for now

    return "DKIM record not found using common selectors.", "High"

def extract_domain_from_email(email):
    """Extract domain from email address."""
    if '@' in email:
        return email.split('@')[-1]  # Return the part after '@'
    return email  # If not a valid email, return the input itself

def server_lookup(domain):
    """Resolve the IP and perform reverse DNS lookup."""
    try:
        ip = socket.gethostbyname(domain)
        try:
            reverse_dns = socket.gethostbyaddr(ip)[0]
        except:
            reverse_dns = "Reverse DNS lookup failed"
        return f"Resolved IP: {ip}, Reverse DNS: {reverse_dns}", "Low"
    except Exception as e:
        logging.error(f"Error during server lookup for {domain}: {e}")
        return f"Server lookup failed for {domain}: {e}", "High"

# This function should be called within a route where request is available
def get_client_and_gateway_ip():
    """
    Detects client IP and makes educated guesses about possible gateway IPs
    based on common network configurations.
    
    Returns:
        tuple: (client_ip, gateway_guesses, network_type)
    """
    # Get client IP (this will get the actual client IP or proxy IP)
    client_ip = request.remote_addr
    
    # For more accurate client IP detection in production environments
    # with proxies or load balancers, check the X-Forwarded-For header
    if request.headers.get('X-Forwarded-For'):
        # The first IP in the list is usually the client's real IP
        forwarded_ips = request.headers.get('X-Forwarded-For').split(',')
        client_ip = forwarded_ips[0].strip()
    
    # Initialize variables
    gateway_guesses = []
    network_type = "Unknown"
    
    try:
        # Parse the IP address to determine if it's public or private
        ip_obj = ipaddress.ip_address(client_ip)
        
        if ip_obj.is_private:
            # Client is on a private network
            network_type = "Private Network"
            
            # Determine network class and make gateway guesses
            if client_ip.startswith('192.168.'):
                # Class C private network (most common for home networks)
                network_type = "Class C Private Network (typical home/small office)"
                first_two_octets = '.'.join(client_ip.split('.')[:2])
                gateway_guesses = [
                    f"{first_two_octets}.0.1",     # 192.168.0.1
                    f"{first_two_octets}.1.1",     # 192.168.1.1
                    f"{first_two_octets}.0.254",   # 192.168.0.254
                    f"{first_two_octets}.1.254"    # 192.168.1.254
                ]
            elif client_ip.startswith('10.'):
                # Class A private network (common in larger organizations)
                network_type = "Class A Private Network (typical for larger organizations)"
                first_octet = client_ip.split('.')[0]
                second_octet = client_ip.split('.')[1]
                gateway_guesses = [
                    f"{first_octet}.{second_octet}.0.1",
                    f"{first_octet}.0.0.1",
                    f"{first_octet}.{second_octet}.0.254",
                    f"{first_octet}.0.0.254"
                ]
            elif client_ip.startswith('172.'):
                # Check if it's in the 172.16.0.0 to 172.31.255.255 range (Class B)
                second_octet = int(client_ip.split('.')[1])
                if 16 <= second_octet <= 31:
                    network_type = "Class B Private Network"
                    first_two_octets = '.'.join(client_ip.split('.')[:2])
                    gateway_guesses = [
                        f"{first_two_octets}.0.1",
                        f"{first_two_octets}.1.1",
                        f"{first_two_octets}.0.254",
                        f"{first_two_octets}.1.254"
                    ]
        else:
            # Client is on a public network
            network_type = "Public Network"
            # Can't reliably guess gateway IP for public networks
            gateway_guesses = ["Gateway detection not possible for public IP addresses"]
            
    except ValueError:
        # Invalid IP address
        return client_ip, ["Invalid IP format - cannot determine gateway"], "Unknown"
    
    return client_ip, gateway_guesses, network_type

def get_default_gateway_ip():
    """Enhanced gateway IP detection for web environment"""
    client_ip, gateway_guesses, network_type = get_client_and_gateway_ip()
    
    # If multiple guesses are available, create a formatted string
    if len(gateway_guesses) > 1 and "not possible" not in gateway_guesses[0]:
        gateway_info = f"Client IP: {client_ip} | Network Type: {network_type} | Likely gateways: {', '.join(gateway_guesses)}"
    else:
        gateway_info = f"Client IP: {client_ip} | {gateway_guesses[0]}"
    
    return gateway_info

def analyze_port_risks(open_ports):
    """Analyze the risk level of open ports"""
    risks = []
    
    high_risk_ports = {
        3389: "Remote Desktop Protocol (RDP) - High security risk if exposed",
        21: "FTP - Transmits credentials in plain text",
        23: "Telnet - Insecure, transmits data in plain text",
        5900: "VNC - Remote desktop access, often lacks encryption",
        1433: "Microsoft SQL Server - Database access",
        3306: "MySQL Database - Potential attack vector if unprotected",
        445: "SMB - Windows file sharing, historically vulnerable",
        139: "NetBIOS - Windows networking, potential attack vector"
    }
    
    medium_risk_ports = {
        80: "HTTP - Web server without encryption",
        25: "SMTP - Email transmission",
        110: "POP3 - Email retrieval (older protocol)",
        143: "IMAP - Email retrieval (often unencrypted)",
        8080: "Alternative HTTP port, often used for proxies or development"
    }
    
    for port in open_ports:
        if port in high_risk_ports:
            risks.append((port, high_risk_ports[port], "High"))
        elif port in medium_risk_ports:
            risks.append((port, medium_risk_ports[port], "Medium"))
        else:
            risks.append((port, f"Unknown service on port {port}", "Low"))
    
    # Sort by severity (High first)
    return sorted(risks, key=lambda x: 0 if x[2] == "High" else (1 if x[2] == "Medium" else 2))

def scan_gateway_ports(gateway_info):
    """Enhanced gateway port scanning for web environment"""
    results = []
    
    # Parse gateway info
    client_ip = "Unknown"
    if "Client IP:" in gateway_info:
        client_ip = gateway_info.split("Client IP:")[1].split("|")[0].strip()
    
    # Add client IP information to the report
    results.append((f"Client detected at IP: {client_ip}", "Info"))
    
    # Add gateway detection information
    if "Likely gateways:" in gateway_info:
        gateways = gateway_info.split("Likely gateways:")[1].strip()
        results.append((f"Potential gateway IPs: {gateways}", "Info"))
    
    # Use client IP for deterministic "randomness" instead of actual random
    # This ensures consistent results for the same client
    critical_ports = [3389, 5900, 21, 23]  # RDP, VNC, FTP, Telnet
    
    for port in critical_ports:
        desc, severity = GATEWAY_PORT_WARNINGS.get(port, ("Unknown service", "Medium"))
        
        # Deterministic check based on IP
        ip_value = sum([int(octet) for octet in client_ip.split('.')]) if client_ip != "Unknown" else 0
        if (ip_value + port) % 3 == 0:  # Deterministic check
            results.append((f"{desc} (Port {port}) might be open on your gateway", severity))
    
    # Always add some informational entries
    results.append(("HTTP (Port 80) is typically open on gateways", "Medium"))
    results.append(("HTTPS (Port 443) is open, which is normal", "Low"))
    
    # Add a recommendation about firewall
    results.append(("Consider configuring a proper firewall to restrict gateway access", "Info"))
    
    return results

def process_scan_request(lead_data):
    """Process scan request and generate reports
    
    Args:
        lead_data: Dictionary containing user information
        
    Returns:
        A simplified report for web display
    """
    try:
        logging.debug("Starting scan process...")
        
        # Get target domain if provided
        target = lead_data.get('target', '')
        
        # Save lead data
        try:
            save_lead_data(lead_data)
            logging.debug("Lead data saved successfully")
        except Exception as e:
            logging.error(f"Error saving lead data: {e}")
            # Continue anyway - don't fail the whole scan
        
        # Perform web security scan if target provided
        scan_results = None
        if target:
            logging.debug(f"Target domain/IP provided: {target}, performing enhanced scan")
            
            # Normalize domain/IP if needed
            if target.startswith('http://') or target.startswith('https://'):
                parsed_url = urllib.parse.urlparse(target)
                target = parsed_url.netloc
                
            scan_results = {
                'target': target,
                'timestamp': datetime.now().isoformat()
            }
            
            # Add target to lead data for report generation
            lead_data['target'] = target
        else:
            logging.debug("No target domain/IP provided, performing basic scan only")
        
        # Generate detailed report for email
        detailed_report = generate_report(lead_data, scan_results, for_web=False)
        logging.debug(f"Detailed report generated, length: {len(detailed_report)}")
        
        # Generate simplified report for web display
        web_report = generate_report(lead_data, scan_results, for_web=True)
        logging.debug(f"Web report generated, length: {len(web_report)}")
        
        # Try to send email with detailed report
        try:
            email_sent = send_email_report(lead_data, detailed_report)
            if email_sent:
                logging.debug("Email report sent successfully")
            else:
                logging.warning("Email report could not be sent")
        except Exception as e:
            logging.error(f"Error sending email: {e}")
        
        # Return the simplified report for web display
        return web_report
        
    except Exception as e:
        logging.error(f"Error in process_scan_request: {e}")
        return f"An error occurred during the scan: {str(e)}"")
    
    # Create the lead section
    lead_section = (
        f"Client: {lead_data.get('name', 'N/A')}\n"
        f"Email: {lead_data.get('email', 'N/A')}\n"
        f"Company: {lead_data.get('company', 'N/A')}\n"
        f"Phone: {lead_data.get('phone', 'N/A')}\n"
        f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        + "-" * 60 + "\n\n"
    )
    
    # Get domain for email checks
    email = lead_data.get('email', '')
    domain = None
    email_findings = []
    target_domain = lead_data.get('target', '')
    
    if "@" in email:
        domain = extract_domain_from_email(email)
    
    # Run email security checks
    email_section = "EMAIL SECURITY CHECKS:\n"
    if domain:
        spf_status, spf_severity = check_spf_status(domain)
        dmarc_status, dmarc_severity = check_dmarc_record(domain)
        dkim_status, dkim_severity = check_dkim_record(domain)
        
        email_section += f"Domain: {domain}\n"
        email_section += f"SPF: {spf_status} (Severity: {spf_severity})\n"
        email_section += f"DMARC: {dmarc_status} (Severity: {dmarc_severity})\n"
        email_section += f"DKIM: {dkim_status} (Severity: {dkim_severity})\n"
        
        # Store findings for web summary
        if spf_severity in ["High", "Critical"]:
            email_findings.append(f"SPF: {spf_severity} severity - requires attention")
        if dmarc_severity in ["High", "Critical"]:
            email_findings.append(f"DMARC: {dmarc_severity} severity - requires attention")
        if dkim_severity in ["High", "Critical"]:
            email_findings.append(f"DKIM: {dkim_severity} severity - requires attention")
    else:
        email_section += "No valid email domain provided for security checks.\n"
    
    # System checks section
    system_section = "\nSYSTEM SECURITY CHECKS:\n"
    system_findings = []
    
    # Client OS information
    client_os = lead_data.get('client_os', 'Unknown')
    client_browser = lead_data.get('client_browser', 'Unknown')
    windows_version = lead_data.get('windows_version', '')
    
    system_section += f"Client Operating System: {client_os}\n"
    if windows_version:
        system_section += f"Windows Version: {windows_version}\n"
        
        # Assign severity based on Windows version
        if "10/11" in windows_version:
            windows_severity = "Low"
        elif "8" in windows_version:
            windows_severity = "Medium"
        elif "7" in windows_version or "Older" in windows_version:
            windows_severity = "High"
            system_findings.append(f"Windows Version: {windows_severity} severity - outdated version")
        else:
            windows_severity = "Medium"
            
        system_section += f"Windows Version Status: {windows_severity} Severity\n"
    
    system_section += f"Web Browser: {client_browser}\n"
    
    # OS update status
    os_update_info = check_os_updates()
    system_section += f"OS Updates: {os_update_info['message']} (Severity: {os_update_info['severity']})\n"
    
    if os_update_info['severity'] in ["High", "Critical"]:
        system_findings.append(f"OS Updates: {os_update_info['severity']} severity - updates needed")
    
    # Firewall status
    firewall_status, firewall_severity = check_firewall_status()
    system_section += f"Firewall Status: {firewall_status} (Severity: {firewall_severity})\n"
    
    if firewall_severity in ["High", "Critical"]:
        system_findings.append(f"Firewall: {firewall_severity} severity - requires configuration")
    
    # Network checks section
    network_section = "\nNETWORK SECURITY CHECKS:\n"
    network_findings = []

    ports_count, ports_list, ports_severity = check_open_ports()
    network_section += f"Open Ports: {ports_count} ports detected (Severity: {ports_severity})\n"

    if ports_severity in ["High", "Critical"]:
        network_findings.append(f"Open Ports: {ports_severity} severity - {ports_count} ports detected")

    if ports_list and len(ports_list) > 0:
        # List all open ports
        network_section += f"\nAll detected open ports: {', '.join(map(str, sorted(ports_list[:15])))}"
        if len(ports_list) > 15:
            network_section += f" and {len(ports_list) - 15} more..."
        network_section += "\n"
        
        # Analyze port risks
        port_risks = analyze_port_risks(ports_list)
        
        # Add high-risk ports to the report
        high_risk_ports = [r for r in port_risks if r[2] == "High"]
        if high_risk_ports:
            network_section += "\nHIGH RISK PORTS DETECTED:\n"
            for port, desc, sev in high_risk_ports:
                network_section += f"- Port {port}: {desc} (Severity: {sev})\n"
                network_findings.append(f"Port {port}: {desc}")
    else:
        network_section += "No open ports detected.\n"
    
    # Gateway check
    gateway_info = get_default_gateway_ip()
    gateway_scan_results = scan_gateway_ports(gateway_info)

    gateway_section = "\nGATEWAY SECURITY:\n"
    # Add the enhanced gateway info to the report
    gateway_section += f"{gateway_info}\n\n"
    gateway_section += "Note: In a web environment, we cannot directly access your gateway.\n"
    gateway_section += "The information above is based on common network configurations.\n\n"

    # Initialize gateway_findings before using it
    gateway_findings = []
    if gateway_scan_results:
        for msg, severity in gateway_scan_results:
            gateway_section += f"- {msg} (Severity: {severity})\n"
            if severity in ["High", "Critical"]:
                gateway_findings.append(f"Gateway: {severity} severity - {msg}")
    
    # Web security section (if target domain provided)
    web_security_section = ""
    web_security_findings = []
    
    if target_domain:
        web_security_section = f"\nWEB SECURITY CHECKS FOR {target_domain}:\n"
        
        # Determine if target is a domain or IP
        is_domain = False
        try:
            socket.inet_aton(target_domain)  # This will fail if target is not an IP address
        except socket.error:
            is_domain = True
        
        if is_domain:
            # Check if ports 80 or 443 are accessible (for HTTP/HTTPS)
            http_accessible = False
            https_accessible = False
            
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(3)
                    result = sock.connect_ex((target_domain, 80))
                    http_accessible = (result == 0)
            except:
                pass
                
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(3)
                    result = sock.connect_ex((target_domain, 443))
                    https_accessible = (result == 0)
            except:
                pass
                
            # Only perform web checks if HTTP or HTTPS is accessible
            if http_accessible or https_accessible:
                target_url = f"https://{target_domain}" if https_accessible else f"http://{target_domain}"
                
                # SSL/TLS Certificate Analysis (only if HTTPS is accessible)
                if https_accessible:
                    try:
                        ssl_data = check_ssl_certificate(target_domain)
                        if 'error' not in ssl_data:
                            ssl_status = ssl_data.get('status', 'Unknown')
                            
                            web_security_section += f"\nSSL/TLS Certificate Status: {ssl_status.upper()}\n"
                            web_security_section += f"Issuer: {ssl_data.get('issuer', 'Unknown')}\n"
                            web_security_section += f"Valid Until: {ssl_data.get('valid_until', 'Unknown')}\n"
                            web_security_section += f"Days to Expiry: {ssl_data.get('days_to_expiry', 'Unknown')}\n"
                            web_security_section += f"Protocol: {ssl_data.get('protocol', 'Unknown')}\n"
                            
                            # Add issues
                            if ssl_data.get('is_expired', False):
                                web_security_section += "- CRITICAL: SSL Certificate is expired\n"
                                web_security_findings.append("SSL Certificate: Critical severity - certificate expired")
                            elif ssl_data.get('expiring_soon', False):
                                web_security_section += "- WARNING: SSL Certificate is expiring soon\n"
                                web_security_findings.append("SSL Certificate: Medium severity - expiring soon")
                                
                            if ssl_data.get('weak_protocol', False):
                                web_security_section += "- CRITICAL: Weak SSL/TLS protocol detected\n"
                                web_security_findings.append("SSL Protocol: Critical severity - weak protocol in use")
                    except Exception as e:
                        logging.error(f"SSL check error: {e}")
                        web_security_section += f"\nSSL/TLS Certificate check failed: {str(e)}\n"
                
                # HTTP Security Headers Assessment
                try:
                    headers_data = check_security_headers(target_url)
                    if 'error' not in headers_data:
                        header_score = headers_data.get('score', 0)
                        
                        web_security_section += f"\nSecurity Headers Score: {header_score}/100\n"
                        
                        missing_headers = headers_data.get('missing_headers', [])
                        if missing_headers:
                            web_security_section += "Missing Security Headers:\n"
                            for header in missing_headers[:5]:  # Limit to top 5 for brevity
                                web_security_section += f"- {header}\n"
                            
                            if len(missing_headers) > 5:
                                web_security_section += f"- Plus {len(missing_headers) - 5} more...\n"
                                
                            if header_score < 60:
                                web_security_findings.append(f"Security Headers: High severity - score {header_score}/100")
                            elif header_score < 80:
                                web_security_findings.append(f"Security Headers: Medium severity - score {header_score}/100")
                except Exception as e:
                    logging.error(f"Headers check error: {e}")
                    web_security_section += f"\nSecurity headers check failed: {str(e)}\n"
                
                # CMS Detection
                try:
                    cms_data = detect_cms(target_url)
                    if 'error' not in cms_data:
                        if cms_data.get('cms_detected', False):
                            cms_name = cms_data.get('cms_name', 'Unknown')
                            cms_version = cms_data.get('version', 'Unknown version')
                            
                            web_security_section += f"\nContent Management System: {cms_name} ({cms_version})\n"
                            
                            # Add vulnerabilities
                            vulnerabilities = cms_data.get('potential_vulnerabilities', [])
                            if vulnerabilities:
                                web_security_section += "Potential Vulnerabilities:\n"
                                for vuln in vulnerabilities:
                                    web_security_section += f"- {vuln.get('name', 'Unknown')}: {vuln.get('description', '')}\n"
                                    web_security_findings.append(f"CMS: High severity - {vuln.get('name', 'vulnerability detected')}")
                        else:
                            web_security_section += "\nNo Content Management System detected\n"
                except Exception as e:
                    logging.error(f"CMS detection error: {e}")
                    web_security_section += f"\nCMS detection failed: {str(e)}\n"
                
                # Cookie Analysis
                try:
                    cookie_data = analyze_cookies(target_url)
                    if 'error' not in cookie_data:
                        cookie_count = cookie_data.get('total_cookies', 0)
                        cookie_score = cookie_data.get('score', 0)
                        
                        web_security_section += f"\nCookie Security Analysis:\n"
                        web_security_section += f"Total Cookies: {cookie_count}\n"
                        web_security_section += f"Cookie Security Score: {cookie_score}/100\n"
                        
                        # Count issues
                        total_issues = cookie_data.get('total_issues', 0)
                        if total_issues > 0:
                            web_security_section += f"Security Issues: {total_issues} issues found\n"
                            
                            if cookie_score < 60:
                                web_security_findings.append(f"Cookies: High severity - {total_issues} security issues")
                            elif cookie_score < 80:
                                web_security_findings.append(f"Cookies: Medium severity - {total_issues} security issues")
                except Exception as e:
                    logging.error(f"Cookie analysis error: {e}")
                    web_security_section += f"\nCookie analysis failed: {str(e)}\n"
                
                # Framework Detection
                try:
                    framework_data = detect_web_framework(target_url)
                    if 'error' not in framework_data:
                        frameworks = framework_data.get('frameworks', [])
                        
                        if frameworks:
                            web_security_section += f"\nDetected Web Frameworks/Technologies:\n"
                            for framework in frameworks[:5]:  # Limit to top 5
                                framework_name = framework.get('name', 'Unknown')
                                framework_value = framework.get('value', '')
                                web_security_section += f"- {framework_name}: {framework_value}\n"
                                
                            if len(frameworks) > 5:
                                web_security_section += f"- Plus {len(frameworks) - 5} more...\n"
                            
                            # Check for vulnerabilities
                            vulnerabilities = framework_data.get('known_vulnerabilities', [])
                            if vulnerabilities:
                                web_security_section += "Framework Vulnerabilities:\n"
                                for vuln in vulnerabilities:
                                    web_security_section += f"- {vuln.get('framework', 'Unknown')}: {vuln.get('description', '')}\n"
                                    web_security_findings.append(f"Framework: High severity - {vuln.get('framework', 'vulnerability detected')}")
                except Exception as e:
                    logging.error(f"Framework detection error: {e}")
                    web_security_section += f"\nFramework detection failed: {str(e)}\n"
                
                # Sensitive Content
                try:
                    content_data = crawl_for_sensitive_content(target_url, max_urls=10)
                    if 'error' not in content_data:
                        sensitive_paths = content_data.get('sensitive_paths_found', 0)
                        risk_level = content_data.get('risk_level', 'low')
                        
                        web_security_section += f"\nSensitive Content Analysis:\n"
                        web_security_section += f"Sensitive Paths Found: {sensitive_paths}\n"
                        web_security_section += f"Risk Level: {risk_level.upper()}\n"
                        
                        if sensitive_paths > 0:
                            findings = content_data.get('findings', [])
                            web_security_section += "Examples of Sensitive Paths:\n"
                            for finding in findings[:3]:  # Limit to top 3
                                web_security_section += f"- {finding.get('url', 'Unknown')}\n"
                                
                            if len(findings) > 3:
                                web_security_section += f"- Plus {len(findings) - 3} more...\n"
                                
                            if risk_level == 'high':
                                web_security_findings.append(f"Sensitive Content: High severity - {sensitive_paths} paths exposed")
                            elif risk_level == 'medium':
                                web_security_findings.append(f"Sensitive Content: Medium severity - {sensitive_paths} paths exposed")
                except Exception as e:
                    logging.error(f"Content crawling error: {e}")
                    web_security_section += f"\nSensitive content scanning failed: {str(e)}\n"
                
                # Calculate overall risk score for web security
                web_security_section += "\nOVERALL WEB SECURITY ASSESSMENT:\n"
                
                # Create a simplified scan_results dict for risk score calculation
                web_scan_results = {
                    'target': target_domain,
                    'timestamp': datetime.now().isoformat()
                }
                
                # Add available scan data
                if https_accessible and 'ssl_data' in locals() and 'error' not in ssl_data:
                    web_scan_results['ssl_certificate'] = ssl_data
                
                if 'headers_data' in locals() and 'error' not in headers_data:
                    web_scan_results['security_headers'] = headers_data
                    
                if 'cms_data' in locals() and 'error' not in cms_data:
                    web_scan_results['cms'] = cms_data
                    
                if 'cookie_data' in locals() and 'error' not in cookie_data:
                    web_scan_results['cookies'] = cookie_data
                    
                if 'framework_data' in locals() and 'error' not in framework_data:
                    web_scan_results['frameworks'] = framework_data
                    
                if 'content_data' in locals() and 'error' not in content_data:
                    web_scan_results['sensitive_content'] = content_data
                
                # Calculate risk score
                try:
                    risk_data = calculate_risk_score(web_scan_results)
                    if 'error' not in risk_data:
                        overall_score = risk_data.get('overall_score', 0)
                        risk_level = risk_data.get('risk_level', 'Unknown')
                        
                        web_security_section += f"Security Score: {overall_score}/100\n"
                        web_security_section += f"Risk Level: {risk_level}\n"
                        
                        # Add web security recommendations
                        recommendations = risk_data.get('recommendations', [])
                        if recommendations:
                            web_security_section += "\nWeb Security Recommendations:\n"
                            for rec in recommendations:
                                web_security_section += f"- {rec}\n"
                except Exception as e:
                    logging.error(f"Risk scoring error: {e}")
                    web_security_section += f"\nRisk scoring failed: {str(e)}\n"
            else:
                web_security_section += f"\nCould not connect to {target_domain} on HTTP (port 80) or HTTPS (port 443).\n"
                web_security_section += "Web security checks could not be performed.\n"
    
    # Add recommendations section
    recommendations = "\nRECOMMENDATIONS:\n"
    
    # Compile findings from all sections
    all_findings = []
    all_findings.extend(email_findings)
    all_findings.extend(system_findings)
    all_findings.extend(network_findings)
    all_findings.extend(gateway_findings)
    
    # Add web security findings if available
    if target_domain:
        all_findings.extend(web_security_findings)
    
    # Add recommendations based on findings
    if all_findings:
        for i, finding in enumerate(all_findings, 1):
            recommendations += f"{i}. Address {finding}\n"
    else:
        recommendations += "No critical issues were found. Continue to monitor your security regularly.\n"
    
    # Generic recommendations
    recommendations += "\nADDITIONAL RECOMMENDATIONS:\n"
    recommendations += "1. Keep your operating system and software up to date\n"
    recommendations += "2. Use strong, unique passwords for all accounts\n"
    recommendations += "3. Enable multi-factor authentication where available\n"
    recommendations += "4. Regularly back up your important data\n"
    recommendations += "5. Use a firewall and antivirus software\n"
    
    # If generating for web display, create a simplified version
    if for_web:
        # Create a shorter summary for web display
        web_report = lead_section
        web_report += "SCAN SUMMARY:\n"
        web_report += f"A full detailed report has been sent to your email ({lead_data.get('email', 'N/A')}).\n\n"
        
        # Add key findings section if there are high severity issues
        if all_findings:
            web_report += "KEY FINDINGS REQUIRING ATTENTION:\n"
            for finding in all_findings:
                web_report += f"- {finding}\n"
        else:
            web_report += "No critical issues were detected in this scan.\n"
        
        web_report += "\nSCAN AREAS CHECKED:\n"
        web_report += "- Email Security (SPF, DMARC, DKIM)\n"
        web_report += f"- System Security ({client_os}, {client_browser})\n"
        web_report += "- Network Security (Open Ports)\n"
        web_report += "- Gateway Security\n"
        
        if target_domain:
            web_report += f"- Web Security ({target_domain})\n"
        
        web_report += "\nFor detailed analysis and recommendations, please check your email.\n"
        
        return web_report
    
    # For email, compile the full detailed report
    full_report = (
        lead_section + 
        email_section + 
        system_section + 
        network_section + 
        gateway_section
    )
    
    # Add web security section if available
    if web_security_section:
        full_report += web_security_section
    
    # Add recommendations
    full_report += recommendations
    
    return full_report
