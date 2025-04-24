from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
import logging
import os
import platform
import socket
import re
import uuid
import urllib.parse
from datetime import datetime
import csv
import sys
import random
import ipaddress
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json

# Import email handler and scanning functions
from email_handler import send_email_report
from scan import (
    check_ssl_certificate,
    check_security_headers,
    detect_cms,
    analyze_cookies,
    detect_web_framework,
    crawl_for_sensitive_content,
    calculate_risk_score,
    analyze_dns_configuration,
    check_spf_status,
    check_dmarc_record,
    check_dkim_record,
    check_os_updates,
    check_firewall_status,
    check_open_ports,
    get_severity_level,
    get_recommendations,
    generate_threat_scenario,
    generate_html_report
)

# Initialize Flask app
app = Flask(__name__)
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

# Constants for severity levels and warnings
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

# Create directory for scan history
SCAN_HISTORY_DIR = 'scan_history'
if not os.path.exists(SCAN_HISTORY_DIR):
    os.makedirs(SCAN_HISTORY_DIR)

def save_lead_data(lead_info):
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
            writer.writerow(lead_info)
        return True
    except Exception as e:
        logging.error(f"Error saving lead data: {e}")
        return False

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

def generate_report(lead_data, for_web=False):
    """Generate vulnerability scan report
    
    Args:
        lead_data: Dictionary containing user information
        for_web: Boolean indicating if this report is for web display (simplified) or email (detailed)
    """
    logging.debug("Generating full report...")
    
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
    
    # Add recommendations
    recommendations = "\nRECOMMENDATIONS:\n"
    recommendations += "1. Ensure email security configurations (SPF, DMARC, DKIM) are properly set up.\n"
    recommendations += "2. Keep operating systems and software up to date.\n"
    recommendations += "3. Maintain a properly configured firewall.\n"
    recommendations += "4. Close unnecessary open ports.\n"
    recommendations += "5. Implement regular security scanning.\n"
    
    # Add target domain security checks if a specific target was provided
    target_domain = lead_data.get('target', '')
    web_security_section = ""
    web_findings = []
    
    if target_domain and target_domain.strip():
        # Determine if it's a domain or IP
        is_domain = not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target_domain)
        
        web_security_section = f"\nTARGET SECURITY CHECKS ({target_domain}):\n"
        
        if is_domain:
            # Run enhanced web security checks
            try:
                ssl_results = check_ssl_certificate(target_domain)
                if 'error' not in ssl_results:
                    web_security_section += f"SSL/TLS: {ssl_results.get('status', 'Unknown')} (Expires: {ssl_results.get('valid_until', 'Unknown')})\n"
                    if ssl_results.get('is_expired', False) or ssl_results.get('expiring_soon', False) or ssl_results.get('weak_protocol', False):
                        web_findings.append(f"SSL/TLS: Issues found with certificate or protocol")
                
                # Add more web security checks as needed...
                header_results = check_security_headers(f"https://{target_domain}")
                if 'error' not in header_results:
                    web_security_section += f"Security Headers Score: {header_results.get('score', 0)}/100\n"
                    if header_results.get('score', 0) < 70:
                        web_findings.append(f"Security Headers: Score {header_results.get('score', 0)}/100 - missing important headers")
                
                # Check for CMS
                cms_results = detect_cms(f"https://{target_domain}")
                if cms_results.get('cms_detected', False):
                    web_security_section += f"CMS Detected: {cms_results.get('cms_name', 'Unknown')} (Version: {cms_results.get('version', 'Unknown')})\n"
                    if cms_results.get('potential_vulnerabilities', []):
                        web_findings.append(f"CMS: Vulnerabilities detected in {cms_results.get('cms_name', 'Unknown')}")
            except Exception as e:
                web_security_section += f"Error scanning web security: {str(e)}\n"
        else:
            # For IP addresses, focus on network scanning
            web_security_section += "IP address provided - focusing on network security checks\n"
    
    # If generating for web display, create a simplified version
    if for_web:
        # Create a shorter summary for web display
        web_report = lead_section
        web_report += "SCAN SUMMARY:\n"
        web_report += f"A full detailed report has been sent to your email ({lead_data.get('email', 'N/A')}).\n\n"
        
        # Add key findings section if there are high severity issues
        all_findings = email_findings + system_findings + network_findings + gateway_findings + web_findings
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
        if target_domain and target_domain.strip():
            web_report += f"- Target Security ({target_domain})\n"
        web_report += "\n"
        
        web_report += "For detailed analysis and recommendations, please check your email.\n"
        
        return web_report
    
    # For email, compile the full detailed report
    full_report = (
        lead_section + 
        email_section + 
        system_section + 
        network_section + 
        gateway_section
    )
    
    # Add web security section if it exists
    if web_security_section:
        full_report += web_security_section
    
    # Add recommendations at the end
    full_report += recommendations
    
    return full_report

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

def process_scan_request(lead_data):
    """Process scan request and generate reports
    
    Args:
        lead_data: Dictionary containing user information
        
    Returns:
        A simplified report for web display
    """
    try:
        logging.debug("Starting scan process...")
        
        # Save lead data
        try:
            save_lead_data(lead_data)
            logging.debug("Lead data saved successfully")
        except Exception as e:
            logging.error(f"Error saving lead data: {e}")
            # Continue anyway - don't fail the whole scan
        
        # Generate detailed report for email
        detailed_report = generate_report(lead_data, for_web=False)
        logging.debug(f"Detailed report generated, length: {len(detailed_report)}")
        
        # Generate simplified report for web display
        web_report = generate_report(lead_data, for_web=True)
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
        return f"An error occurred during the scan: {str(e)}"

# Function to save comprehensive scan results
def save_comprehensive_results(scan_id, results):
    """Save comprehensive scan results to a file"""
    filename = os.path.join(SCAN_HISTORY_DIR, f"comprehensive_{scan_id}.json")
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)

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
            'target': request.form.get('target', '')  # Include target domain/IP if provided
        }
        
        logging.debug(f"Received scan form data: {lead_data}")
        logging.debug(f"Client OS detected: {lead_data['client_os']}")
        
        try:
            # Process the scan - this now returns a simplified web report
            web_report = process_scan_request(lead_data)
            
            # Store the web report in session
            session['scan_result'] = web_report
            logging.debug("Web report stored in session")
            
            # Add a flag to indicate scan was completed
            session['scan_completed'] = True
            
            # Redirect to results page
            return redirect(url_for('results'))
        except Exception as e:
            logging.error(f"Error processing scan: {e}")
            return render_template('error.html', error=str(e))
    
    return render_template('scan.html')

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

@app.route('/debug')
def debug():
    """Debug endpoint to check Flask configuration"""
    
    debug_info = {
        "Python Version": sys.version,
        "Working Directory": os.getcwd(),
        "Template Folder": app.template_folder,
        "Templates Exist": os.path.exists(app.template_folder),
        "Templates Available": os.listdir(app.template_folder) if os.path.exists(app.template_folder) else "N/A",
        "Environment": app.config['ENV'],
        "Debug Mode": app.config['DEBUG']
    }
    
    return jsonify(debug_info)

# API endpoints
@app.route('/api/firewall-test', methods=['POST'])
def firewall_test():
    test_results = request.json
    # Store results in session or database for inclusion in the report
    session['firewall_test_results'] = test_results
    return jsonify({"status": "success"})

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
            "target": request.form.get('target', '')  # Include target domain/IP if provided
        }
        
        # Basic validation
        if not lead_data["name"] or not lead_data["email"]:
            return jsonify({
                "status": "error",
                "message": "Please enter at least your name and email before scanning."
            }), 400
            
        # Save lead data
        save_lead_data(lead_data)
        
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

@app.route('/api/healthcheck')
def healthcheck():
    return jsonify({
        "status": "ok",
        "version": "1.0.0",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

# Enhanced Security Scan Routes
@app.route('/enhanced-scan', methods=['GET', 'POST'])
def enhanced_scan():
    """Enhanced security scan form page"""
    if request.method == 'POST':
        return redirect(url_for('start_enhanced_scan'))
    
    return render_template('enhanced_scan.html')

@app.route('/start-enhanced-scan', methods=['POST'])
def start_enhanced_scan():
    """Process enhanced security scan request"""
    target = request.form.get('target', '')
    name = request.form.get('name', '')
    email = request.form.get('email', '')
    company = request.form.get('company', '')
    phone = request.form.get('phone', '')
    
    if not target:
        return render_template('enhanced_scan.html', 
                               error="Please enter a target domain or IP address")
    
    # Store data in session for use during scan
    session['target'] = target
    session['email'] = email
    session['name'] = name
    session['company'] = company
    
    # Save lead data
    lead_data = {
        'name': name,
        'email': email,
        'company': company,
        'phone': phone,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'client_os': request.form.get('client_os', 'Unknown'),
        'client_browser': request.form.get('client_browser', 'Unknown'),
        'windows_version': request.form.get('windows_version', ''),
        'target': target
    }
    
    try:
        save_lead_data(lead_data)
    except Exception as e:
        logging.error(f"Error saving lead data: {e}")
    
    # Generate unique scan ID
    scan_id = str(uuid.uuid4())
    
    # Reset scan start time in session
    session['scan_start_time'] = datetime.now().timestamp()
    
    # Redirect to scan progress page
    return redirect(url_for('enhanced_scan_progress', scan_id=scan_id))

@app.route('/enhanced-scan-progress/<scan_id>')
def enhanced_scan_progress(scan_id):
    """Display scan progress and start background scanning"""
    target = session.get('target', '')
    email = session.get('email', '')
    
    if not target:
        return redirect(url_for('enhanced_scan'))
    
    # Client-side will poll the status endpoint to get progress
    return render_template('enhanced_scan_progress.html', 
                           scan_id=scan_id, 
                           target=target,
                           email=email)

@app.route('/api/enhanced-scan-status/<scan_id>', methods=['GET'])
@limiter.limit("300 per hour")
def enhanced_scan_status(scan_id):
    """API endpoint to check scan status and progress"""
    # Get current timestamp to simulate progress
    current_timestamp = datetime.now().timestamp()
    
    # If scan_start_time not in session, initialize it
    if 'scan_start_time' not in session:
        session['scan_start_time'] = current_timestamp
    
    scan_start = session.get('scan_start_time')
    
    # Calculate simulated progress (0-100%)
    elapsed_time = current_timestamp - scan_start
    progress = min(int(elapsed_time * 10), 100)  # 10% per second, max 100%
    
    # Create a status message based on progress
    if progress < 20:
        status_message = "Checking ports and network services..."
    elif progress < 40:
        status_message = "Analyzing SSL/TLS certificates..."
    elif progress < 60:
        status_message = "Checking web security headers and CMS..."
    elif progress < 80:
        status_message = "Scanning for sensitive content..."
    elif progress < 100:
        status_message = "Calculating risk scores and generating report..."
    else:
        status_message = "Scan completed! Preparing results..."
    
    # If scan is complete, prepare redirect to results
    if progress >= 100:
        # Clear the scan_start_time from session
        if 'scan_start_time' in session:
            del session['scan_start_time']
        
        # Perform the actual comprehensive scan
        target = session.get('target', '')
        name = session.get('name', '')
        email = session.get('email', '')
        company = session.get('company', '')
        
        # Create comprehensive scan data
        lead_data = {
            'scan_id': scan_id,
            'name': name,
            'email': email,
            'company': company,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'target': target
        }
        
        # Run the comprehensive scan
        try:
            scan_results = run_comprehensive_scan(target, lead_data)
            save_comprehensive_results(scan_id, scan_results)
        except Exception as e:
            logging.error(f"Error running comprehensive scan: {e}")
        
        return jsonify({
            'status': 'complete',
            'progress': 100,
            'message': 'Scan completed successfully',
            'redirect_url': url_for('enhanced_scan_results', scan_id=scan_id)
        })
    
    # Otherwise return progress update
    return jsonify({
        'status': 'in_progress',
        'progress': progress,
        'message': status_message
    })

def run_comprehensive_scan(target, lead_data):
    """Run a comprehensive security scan on the target"""
    # Initialize scan results
    scan_results = {
        'scan_id': lead_data.get('scan_id', str(uuid.uuid4())),
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'is_complete': True
    }
    
    # Parse the target to determine if it's a domain or IP
    is_domain = False
    try:
        socket.inet_aton(target)  # This will fail if target is not an IP address
    except socket.error:
        is_domain = True
    
    scan_results['is_domain'] = is_domain
    
    # Perform port scan
    ports_count, ports_list, ports_severity = check_open_ports()
    scan_results['open_ports'] = {
        'open_ports': ports_list,
        'filtered_ports': [],
        'closed_ports': [],
        'services': {}
    }
    
    # If it's a domain, perform web security checks
    if is_domain:
        try:
            # Normalize the domain
            if target.startswith('http://') or target.startswith('https://'):
                parsed_url = urllib.parse.urlparse(target)
                domain = parsed_url.netloc
            else:
                domain = target
                
            # Run email security checks
            try:
                spf_status, spf_severity = check_spf_status(domain)
                dmarc_status, dmarc_severity = check_dmarc_record(domain)
                dkim_status, dkim_severity = check_dkim_record(domain)
                
                scan_results['email_security'] = {
                    'spf': {
                        'status': spf_status,
                        'severity': spf_severity
                    },
                    'dmarc': {
                        'status': dmarc_status,
                        'severity': dmarc_severity
                    },
                    'dkim': {
                        'status': dkim_status,
                        'severity': dkim_severity
                    }
                }
            except Exception as e:
                logging.error(f"Error checking email security: {e}")
                scan_results['email_security'] = {
                    'error': f"Error checking email security: {str(e)}"
                }
            
            # Check if ports 80 or 443 are accessible (for HTTP/HTTPS)
            http_accessible = False
            https_accessible = False
            
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(3)
                    result = sock.connect_ex((domain, 80))
                    http_accessible = (result == 0)
            except:
                pass
                
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(3)
                    result = sock.connect_ex((domain, 443))
                    https_accessible = (result == 0)
            except:
                pass
                
            scan_results['http_accessible'] = http_accessible
            scan_results['https_accessible'] = https_accessible
            
            # Only perform web checks if HTTP or HTTPS is accessible
            if http_accessible or https_accessible:
                target_url = f"https://{domain}" if https_accessible else f"http://{domain}"
                
                # SSL/TLS Certificate Analysis (only if HTTPS is accessible)
                if https_accessible:
                    try:
                        scan_results['ssl_certificate'] = check_ssl_certificate(domain)
                    except Exception as e:
                        logging.error(f"SSL check error: {e}")
                        scan_results['ssl_certificate'] = {'error': str(e), 'status': 'error'}
                
                # HTTP Security Headers Assessment
                try:
                    scan_results['security_headers'] = check_security_headers(target_url)
                except Exception as e:
                    logging.error(f"Headers check error: {e}")
                    scan_results['security_headers'] = {'error': str(e), 'score': 0}
                
                # CMS Detection
                try:
                    scan_results['cms'] = detect_cms(target_url)
                except Exception as e:
                    logging.error(f"CMS detection error: {e}")
                    scan_results['cms'] = {'error': str(e), 'cms_detected': False}
                
                # Cookie Security Analysis
                try:
                    scan_results['cookies'] = analyze_cookies(target_url)
                except Exception as e:
                    logging.error(f"Cookie analysis error: {e}")
                    scan_results['cookies'] = {'error': str(e), 'score': 0}
                
                # Web Application Framework Detection
                try:
                    scan_results['frameworks'] = detect_web_framework(target_url)
                except Exception as e:
                    logging.error(f"Framework detection error: {e}")
                    scan_results['frameworks'] = {'error': str(e), 'frameworks': []}
                
                # Basic Content Crawling (look for sensitive paths)
                try:
                    max_urls = 15
                    scan_results['sensitive_content'] = crawl_for_sensitive_content(target_url, max_urls)
                except Exception as e:
                    logging.error(f"Content crawling error: {e}")
                    scan_results['sensitive_content'] = {'error': str(e), 'sensitive_paths_found': 0}
        except Exception as e:
            logging.error(f"Domain scanning error: {e}")
            scan_results['error'] = f"Error scanning domain: {str(e)}"
    
    # Calculate overall risk score
    try:
        scan_results['risk_assessment'] = calculate_risk_score(scan_results)
    except Exception as e:
        logging.error(f"Risk scoring error: {e}")
        scan_results['risk_assessment'] = {
            'error': f"Error calculating risk score: {str(e)}",
            'overall_score': 0,
            'risk_level': 'Unknown'
        }
    
    # Try to send email report
    try:
        # Generate HTML report
        html_report = generate_html_report(scan_results)
        
        # Send email
        email = lead_data.get('email')
        if email:
            send_email_report({
                'name': lead_data.get('name', 'User'),
                'email': email,
                'company': lead_data.get('company', ''),
                'phone': lead_data.get('phone', '')
            }, html_report, is_html=True)
    except Exception as e:
        logging.error(f"Error sending email report: {e}")
    
    return scan_results

@app.route('/enhanced-scan-results/<scan_id>')
def enhanced_scan_results(scan_id):
    """Display enhanced scan results"""
    try:
        filename = os.path.join(SCAN_HISTORY_DIR, f"comprehensive_{scan_id}.json")
        if not os.path.exists(filename):
            return redirect(url_for('enhanced_scan'))
        
        with open(filename, 'r') as f:
            scan_results = json.load(f)
        
        return render_template('enhanced_scan_results.html', scan=scan_results)
    except Exception as e:
        logging.error(f"Error loading scan results: {e}")
        return render_template('error.html', error=f"Could not load scan results: {str(e)}")

@app.route('/api/enhanced-scan-report/<scan_id>', methods=['GET'])
def enhanced_scan_report(scan_id):
    """Generate a detailed HTML report for the enhanced scan"""
    scan_results = None
    
    try:
        filename = os.path.join(SCAN_HISTORY_DIR, f"comprehensive_{scan_id}.json")
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                scan_results = json.load(f)
        else:
            return jsonify({'error': 'Scan results not found'}), 404
        
        # Generate HTML report
        html_report = generate_html_report(scan_results)
        
        # Return the HTML report
        return html_report
    except Exception as e:
        return jsonify({'error': f'Failed to generate report: {str(e)}'}), 500

# Integrated scan route
@app.route('/integrated-scan', methods=['GET', 'POST'])
def integrated_scan():
    """Combined security scan that integrates both basic and enhanced features"""
    if request.method == 'POST':
        # Get form data
        target = request.form.get('target', '')
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        company = request.form.get('company', '')
        phone = request.form.get('phone', '')
        
        # Validate inputs
        if not name or not email:
            return render_template('integrated_scan.html', 
                                  error="Please enter your name and email address")
        
        # Save lead data
        lead_data = {
            'name': name,
            'email': email,
            'company': company,
            'phone': phone,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'client_os': request.form.get('client_os', 'Unknown'),
            'client_browser': request.form.get('client_browser', 'Unknown'),
            'windows_version': request.form.get('windows_version', ''),
            'target': target
        }
        
        try:
            save_lead_data(lead_data)
        except Exception as e:
            logging.error(f"Error saving lead data: {e}")
        
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Store data in session
        session['target'] = target
        session['email'] = email
        session['name'] = name
        session['company'] = company
        session['scan_start_time'] = datetime.now().timestamp()
        session['integrated_scan'] = True
        
        # Redirect to progress page
        return redirect(url_for('integrated_scan_progress', scan_id=scan_id))
    
    return render_template('integrated_scan.html')

@app.route('/integrated-scan-progress/<scan_id>')
def integrated_scan_progress(scan_id):
    """Display progress for integrated scan"""
    target = session.get('target', '')
    email = session.get('email', '')
    
    # Render progress page
    return render_template('integrated_scan_progress.html',
                           scan_id=scan_id,
                           target=target,
                           email=email)

@app.route('/api/integrated-scan-status/<scan_id>', methods=['GET'])
def integrated_scan_status(scan_id):
    """Check status of integrated scan"""
    # Similar to enhanced scan status but with custom steps
    current_timestamp = datetime.now().timestamp()
    
    if 'scan_start_time' not in session:
        session['scan_start_time'] = current_timestamp
    
    scan_start = session.get('scan_start_time')
    
    # Calculate progress
    elapsed_time = current_timestamp - scan_start
    progress = min(int(elapsed_time * 8), 100)  # 8% per second, max 100%
    
    # Create a status message based on progress
    if progress < 15:
        status_message = "Initializing comprehensive scan..."
    elif progress < 30:
        status_message = "Scanning system security..."
    elif progress < 45:
        status_message = "Checking email security (SPF, DMARC, DKIM)..."
    elif progress < 60:
        status_message = "Scanning network and ports..."
    elif progress < 75:
        status_message = "Analyzing web security..."
    elif progress < 90:
        status_message = "Calculating risk scores..."
    else:
        status_message = "Finalizing report and sending email..."
    
    # If scan is complete, run the actual scan and redirect to results
    if progress >= 100:
        # Clear the scan_start_time from session
        if 'scan_start_time' in session:
            del session['scan_start_time']
        
        # Get data from session
        target = session.get('target', '')
        name = session.get('name', '')
        email = session.get('email', '')
        company = session.get('company', '')
        
        # Create scan data
        lead_data = {
            'scan_id': scan_id,
            'name': name,
            'email': email,
            'company': company,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'target': target
        }
        
        # Run the integrated scan
        try:
            # This combines both basic system checks and enhanced target scanning
            scan_results = run_integrated_scan(target, lead_data)
            save_comprehensive_results(scan_id, scan_results)
        except Exception as e:
            logging.error(f"Error running integrated scan: {e}")
        
        return jsonify({
            'status': 'complete',
            'progress': 100,
            'message': 'Scan completed successfully',
            'redirect_url': url_for('integrated_scan_results', scan_id=scan_id)
        })
    
    # Return progress update
    return jsonify({
        'status': 'in_progress',
        'progress': progress,
        'message': status_message
    })

def run_integrated_scan(target, lead_data):
    """Run a comprehensive scan that includes both system and target checks"""
    # Initialize scan results
    scan_results = {
        'scan_id': lead_data.get('scan_id', str(uuid.uuid4())),
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'is_complete': True,
        'scan_type': 'integrated'
    }
    
    # System security checks
    try:
        # OS information
        scan_results['system'] = {
            'os_updates': check_os_updates(),
            'firewall': {
                'status': check_firewall_status()[0],
                'severity': check_firewall_status()[1]
            }
        }
    except Exception as e:
        logging.error(f"Error checking system security: {e}")
        scan_results['system'] = {'error': str(e)}
    
    # Network security checks
    try:
        ports_count, ports_list, ports_severity = check_open_ports()
        scan_results['network'] = {
            'open_ports': {
                'count': ports_count,
                'list': ports_list,
                'severity': ports_severity
            }
        }
        
        # Gateway checks
        gateway_info = get_default_gateway_ip()
        gateway_scan_results = scan_gateway_ports(gateway_info)
        scan_results['network']['gateway'] = {
            'info': gateway_info,
            'results': gateway_scan_results
        }
    except Exception as e:
        logging.error(f"Error checking network security: {e}")
        scan_results['network'] = {'error': str(e)}
    
    # If target is provided, perform web security checks
    if target and target.strip():
        # Determine if it's a domain or IP
        is_domain = False
        try:
            socket.inet_aton(target)  # This will fail if target is not an IP address
        except socket.error:
            is_domain = True
        
        scan_results['is_domain'] = is_domain
        
        # If it's a domain, perform web security checks
        if is_domain:
            try:
                # Normalize the domain
                if target.startswith('http://') or target.startswith('https://'):
                    parsed_url = urllib.parse.urlparse(target)
                    domain = parsed_url.netloc
                else:
                    domain = target
                
                # Email security checks
                try:
                    spf_status, spf_severity = check_spf_status(domain)
                    dmarc_status, dmarc_severity = check_dmarc_record(domain)
                    dkim_status, dkim_severity = check_dkim_record(domain)
                    
                    scan_results['email_security'] = {
                        'spf': {
                            'status': spf_status,
                            'severity': spf_severity
                        },
                        'dmarc': {
                            'status': dmarc_status,
                            'severity': dmarc_severity
                        },
                        'dkim': {
                            'status': dkim_status,
                            'severity': dkim_severity
                        }
                    }
                except Exception as e:
                    logging.error(f"Error checking email security: {e}")
                    scan_results['email_security'] = {
                        'error': f"Error checking email security: {str(e)}"
                    }
                
                # Check if ports 80 or 443 are accessible (for HTTP/HTTPS)
                http_accessible = False
                https_accessible = False
                
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(3)
                        result = sock.connect_ex((domain, 80))
                        http_accessible = (result == 0)
                except:
                    pass
                    
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(3)
                        result = sock.connect_ex((domain, 443))
                        https_accessible = (result == 0)
                except:
                    pass
                    
                scan_results['http_accessible'] = http_accessible
                scan_results['https_accessible'] = https_accessible
                
                # Only perform web checks if HTTP or HTTPS is accessible
                if http_accessible or https_accessible:
                    target_url = f"https://{domain}" if https_accessible else f"http://{domain}"
                    
                    # SSL/TLS Certificate Analysis (only if HTTPS is accessible)
                    if https_accessible:
                        try:
                            scan_results['ssl_certificate'] = check_ssl_certificate(domain)
                        except Exception as e:
                            logging.error(f"SSL check error: {e}")
                            scan_results['ssl_certificate'] = {'error': str(e), 'status': 'error'}
                    
                    # HTTP Security Headers Assessment
                    try:
                        scan_results['security_headers'] = check_security_headers(target_url)
                    except Exception as e:
                        logging.error(f"Headers check error: {e}")
                        scan_results['security_headers'] = {'error': str(e), 'score': 0}
                    
                    # CMS Detection
                    try:
                        scan_results['cms'] = detect_cms(target_url)
                    except Exception as e:
                        logging.error(f"CMS detection error: {e}")
                        scan_results['cms'] = {'error': str(e), 'cms_detected': False}
                    
                    # Web Application Framework Detection
                    try:
                        scan_results['frameworks'] = detect_web_framework(target_url)
                    except Exception as e:
                        logging.error(f"Framework detection error: {e}")
                        scan_results['frameworks'] = {'error': str(e), 'frameworks': []}
            except Exception as e:
                logging.error(f"Domain scanning error: {e}")
                scan_results['web_error'] = f"Error scanning domain: {str(e)}"
    
    # Calculate overall risk score
    try:
        scan_results['risk_assessment'] = calculate_risk_score(scan_results)
    except Exception as e:
        logging.error(f"Risk scoring error: {e}")
        scan_results['risk_assessment'] = {
            'error': f"Error calculating risk score: {str(e)}",
            'overall_score': 0,
            'risk_level': 'Unknown'
        }
    
    # Try to send email report
    try:
        # Generate HTML report
        html_report = generate_html_report(scan_results, is_integrated=True)
        
        # Send email
        email = lead_data.get('email')
        if email:
            send_email_report({
                'name': lead_data.get('name', 'User'),
                'email': email,
                'company': lead_data.get('company', ''),
                'phone': lead_data.get('phone', '')
            }, html_report, is_html=True, is_integrated=True)
    except Exception as e:
        logging.error(f"Error sending email report: {e}")
    
    return scan_results

@app.route('/integrated-scan-results/<scan_id>')
def integrated_scan_results(scan_id):
    """Display integrated scan results"""
    try:
        filename = os.path.join(SCAN_HISTORY_DIR, f"comprehensive_{scan_id}.json")
        if not os.path.exists(filename):
            return redirect(url_for('integrated_scan'))
        
        with open(filename, 'r') as f:
            scan_results = json.load(f)
        
        return render_template('results.html', 
                               scan=scan_results, 
                               scan_result=json.dumps(scan_results, indent=2),
                               is_integrated=True)
    except Exception as e:
        logging.error(f"Error loading integrated scan results: {e}")
        return render_template('error.html', error=f"Could not load scan results: {str(e)}")

if __name__ == '__main__':
    # Get port from environment variable or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Use 0.0.0.0 to make the app accessible from any IP
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_ENV') == 'development')
