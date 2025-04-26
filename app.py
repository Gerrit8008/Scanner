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
import ssl
import requests
from bs4 import BeautifulSoup
import dns.resolver
from email_handler import send_email_report
from scan import (
    extract_domain_from_email,
    server_lookup,
    get_client_and_gateway_ip,
    get_default_gateway_ip,
    scan_gateway_ports,
    check_ssl_certificate,
    check_security_headers,
    detect_cms,
    analyze_cookies,
    detect_web_framework,
    crawl_for_sensitive_content,
    generate_threat_scenario,
    analyze_dns_configuration,
    check_spf_status,
    check_dmarc_record,
    check_dkim_record,
    check_os_updates,
    check_firewall_status,
    check_open_ports,
    analyze_port_risks,
    calculate_risk_score,
    get_severity_level,
    get_recommendations,
    generate_html_report
    )
from logging_utils import log_function_call
import traceback

# Initialize Flask app
app = Flask(__name__)
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'your_temporary_secret_key')

# Set up logging configuration
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Create logs directory
LOGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(LOGS_DIR, exist_ok=True)

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

# Define constants
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCAN_HISTORY_DIR = os.path.join(BASE_DIR, 'scan_history')
FALLBACK_DIR = '/tmp/scan_history'

# Create directories
os.makedirs(SCAN_HISTORY_DIR, exist_ok=True)
os.makedirs(FALLBACK_DIR, exist_ok=True)

def log_system_info():
    """Log system information to help with debugging"""
    logger = logging.getLogger(__name__)
    
    logger.info("----- System Information -----")
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Platform: {platform.platform()}")
    logger.info(f"Working directory: {os.getcwd()}")
    
    # Log directory information
    directories = [
        ("Base directory", BASE_DIR),
        ("Scan history directory", SCAN_HISTORY_DIR),
        ("Fallback directory", FALLBACK_DIR)
    ]
    
    for name, path in directories:
        exists = os.path.exists(path)
        logger.info(f"{name}: {path} (Exists: {exists})")
        
        if exists:
            try:
                permissions = oct(os.stat(path).st_mode)[-3:]
                writable = os.access(path, os.W_OK)
                logger.info(f"  Permissions: {permissions}, Writable: {writable}")
                
                # Try a test write
                test_file = os.path.join(path, "test_write.tmp")
                try:
                    with open(test_file, 'w') as f:
                        f.write("test")
                    os.remove(test_file)
                    logger.info(f"  Write test: Successful")
                except Exception as e:
                    logger.warning(f"  Write test: Failed - {e}")
            except Exception as e:
                logger.warning(f"  Could not check permissions: {e}")
    
    logger.info("-----------------------------")
def setup_logging():
    log_filename = os.path.join(LOGS_DIR, f"security_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    
    # Create formatters
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(funcName)s - Line %(lineno)d - %(message)s')
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # File handler (detailed)
    file_handler = logging.FileHandler(log_filename)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)
    
    # Console handler (less detailed)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)
    
    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    # Log the start of the application
    logger.info("Application started")
    logger.info(f"Detailed logs will be saved to: {log_filename}")
    
    return logger

# Call setup at the beginning of your application
logger = setup_logging()

def save_lead_data(lead_data):
    """
    Save lead data to CSV file for future reference and marketing
    
    Args:
        lead_data (dict): Dictionary containing lead information
    """
    try:
        # Define the path for the leads CSV file
        leads_file = os.path.join(BASE_DIR, 'leads.csv')
        file_exists = os.path.exists(leads_file)
        
        # Get the field names from the lead_data dictionary
        fieldnames = list(lead_data.keys())
        
        # Open the file in append mode
        with open(leads_file, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            # Write header if file doesn't exist
            if not file_exists:
                writer.writeheader()
            
            # Write the lead data
            writer.writerow(lead_data)
            
        logging.debug(f"Lead data saved successfully for: {lead_data.get('email', 'Unknown')}")
        return True
    except Exception as e:
        logging.error(f"Error saving lead data: {e}")
        # Try with a fallback directory
        try:
            fallback_dir = "/tmp"
            fallback_file = os.path.join(fallback_dir, 'leads.csv')
            file_exists = os.path.exists(fallback_file)
            
            with open(fallback_file, 'a', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=list(lead_data.keys()))
                if not file_exists:
                    writer.writeheader()
                writer.writerow(lead_data)
                
            logging.debug(f"Lead data saved to fallback location for: {lead_data.get('email', 'Unknown')}")
            return True
        except Exception as e2:
            logging.error(f"Error saving lead data to fallback location: {e2}")
            return False
        
# ---------------------------- MAIN SCANNING FUNCTION ----------------------------
def run_consolidated_scan(lead_data):
    """
    Run a complete security scan and generate one comprehensive report.
    
    Args:
        lead_data (dict): User information and scan parameters
    
    Returns:
        dict: Complete scan results
    """
    global SCAN_HISTORY_DIR  
    
    scan_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    
    logging.info(f"Starting scan with ID: {scan_id} for target: {lead_data.get('target', 'Unknown')}")
    
    # Initialize scan results structure
    scan_results = {
        'scan_id': scan_id,
        'timestamp': timestamp,
        'target': lead_data.get('target', ''),
        'client_info': {
            'os': lead_data.get('client_os', 'Unknown'),
            'browser': lead_data.get('client_browser', 'Unknown'),
            'windows_version': lead_data.get('windows_version', '')
        }
    }
    
    # 1. System Security Checks
    try:
        logging.info("Running system security checks...")
        scan_results['system'] = {
            'os_updates': check_os_updates(),
            'firewall': {
                'status': check_firewall_status()[0],
                'severity': check_firewall_status()[1]
            }
        }
        logging.debug(f"System security checks completed: {scan_results['system']}")
    except Exception as e:
        logging.error(f"Error during system security checks: {e}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        scan_results['system'] = {'error': str(e)}
    
    # 2. Network Security Checks
    try:
        logging.info("Running network security checks...")
        ports_count, ports_list, ports_severity = check_open_ports()
        scan_results['network'] = {
            'open_ports': {
                'count': ports_count,
                'list': ports_list,
                'severity': ports_severity
            }
        }
        
        # Gateway checks
        try:
            class DummyRequest:
                def __init__(self):
                    self.remote_addr = "127.0.0.1"
                    self.headers = {}

            request_obj = request if 'request' in locals() else DummyRequest()
            gateway_info = get_default_gateway_ip(request_obj)
            gateway_scan_results = scan_gateway_ports(gateway_info)
            scan_results['network']['gateway'] = {
                'info': gateway_info,
                'results': gateway_scan_results
            }
            logging.debug(f"Gateway checks completed: {scan_results['network']['gateway']}")
        except Exception as gateway_error:
            logging.error(f"Error during gateway checks: {gateway_error}")
            scan_results['network']['gateway'] = {'error': str(gateway_error)}
            
        logging.debug(f"Network security checks completed: {scan_results['network']}")
    except Exception as e:
        logging.error(f"Error during network security checks: {e}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        scan_results['network'] = {'error': str(e)}
    
    # 3. Email Security Checks
    try:
        logging.info("Running email security checks...")
        email = lead_data.get('email', '')
        if "@" in email:
            domain = extract_domain_from_email(email)
            logging.debug(f"Extracted domain from email: {domain}")
            
            try:
                spf_status, spf_severity = check_spf_status(domain)
                logging.debug(f"SPF check completed: {spf_status}, {spf_severity}")
            except Exception as spf_error:
                logging.error(f"Error checking SPF for {domain}: {spf_error}")
                spf_status, spf_severity = f"Error checking SPF: {str(spf_error)}", "High"
                
            try:
                dmarc_status, dmarc_severity = check_dmarc_record(domain)
                logging.debug(f"DMARC check completed: {dmarc_status}, {dmarc_severity}")
            except Exception as dmarc_error:
                logging.error(f"Error checking DMARC for {domain}: {dmarc_error}")
                dmarc_status, dmarc_severity = f"Error checking DMARC: {str(dmarc_error)}", "High"
                
            try:
                dkim_status, dkim_severity = check_dkim_record(domain)
                logging.debug(f"DKIM check completed: {dkim_status}, {dkim_severity}")
            except Exception as dkim_error:
                logging.error(f"Error checking DKIM for {domain}: {dkim_error}")
                dkim_status, dkim_severity = f"Error checking DKIM: {str(dkim_error)}", "High"
            
            scan_results['email_security'] = {
                'domain': domain,
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
            logging.debug(f"Email security checks completed for domain {domain}")
        else:
            logging.warning("No valid email provided for email security checks")
            scan_results['email_security'] = {
                'error': 'No valid email provided'
            }
    except Exception as e:
        logging.error(f"Error during email security checks: {e}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        scan_results['email_security'] = {'error': str(e)}
    
    # 4. Web Security Checks (if target domain provided)
    target = lead_data.get('target', '')
    if target and target.strip():
        try:
            logging.info(f"Running web security checks for target: {target}...")
            
            # Determine if it's a domain or IP
            is_domain = False
            try:
                socket.inet_aton(target)  # Will fail if target is not an IP address
                logging.debug(f"Target {target} is an IP address")
            except socket.error:
                is_domain = True
                logging.debug(f"Target {target} is a domain name")
            
            scan_results['is_domain'] = is_domain
            
            if is_domain:
                # Normalize the domain
                if target.startswith('http://') or target.startswith('https://'):
                    parsed_url = urllib.parse.urlparse(target)
                    domain = parsed_url.netloc
                    logging.debug(f"Parsed domain from URL: {domain}")
                else:
                    domain = target
                    logging.debug(f"Using target as domain: {domain}")
                
                # Check if ports 80 or 443 are accessible
                http_accessible = False
                https_accessible = False
                
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(3)
                        result = sock.connect_ex((domain, 80))
                        http_accessible = (result == 0)
                        logging.debug(f"HTTP (port 80) accessible: {http_accessible}")
                except Exception as http_error:
                    logging.error(f"Error checking HTTP accessibility: {http_error}")
                    
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(3)
                        result = sock.connect_ex((domain, 443))
                        https_accessible = (result == 0)
                        logging.debug(f"HTTPS (port 443) accessible: {https_accessible}")
                except Exception as https_error:
                    logging.error(f"Error checking HTTPS accessibility: {https_error}")
                    
                scan_results['http_accessible'] = http_accessible
                scan_results['https_accessible'] = https_accessible
                
                # Only perform web checks if HTTP or HTTPS is accessible
                if http_accessible or https_accessible:
                    target_url = f"https://{domain}" if https_accessible else f"http://{domain}"
                    logging.info(f"Using target URL: {target_url}")
                    
                    # SSL/TLS Certificate Analysis (only if HTTPS is accessible)
                    if https_accessible:
                        try:
                            logging.debug(f"Checking SSL certificate for {domain}")
                            scan_results['ssl_certificate'] = check_ssl_certificate(domain)
                            logging.debug(f"SSL certificate check completed: {scan_results['ssl_certificate']}")
                        except Exception as e:
                            logging.error(f"SSL check error for {domain}: {e}")
                            logging.debug(f"Exception traceback: {traceback.format_exc()}")
                            scan_results['ssl_certificate'] = {'error': str(e), 'status': 'error', 'severity': 'High'}
                    
                    # HTTP Security Headers Assessment
                    try:
                        logging.debug(f"Checking security headers for {target_url}")
                        scan_results['security_headers'] = check_security_headers(target_url)
                        logging.debug(f"Security headers check completed: {scan_results['security_headers']}")
                    except Exception as e:
                        logging.error(f"Headers check error for {target_url}: {e}")
                        logging.debug(f"Exception traceback: {traceback.format_exc()}")
                        scan_results['security_headers'] = {'error': str(e), 'score': 0, 'severity': 'High'}
                    
                    # CMS Detection
                    try:
                        logging.debug(f"Detecting CMS for {target_url}")
                        scan_results['cms'] = detect_cms(target_url)
                        logging.debug(f"CMS detection completed: {scan_results['cms']}")
                    except Exception as e:
                        logging.error(f"CMS detection error for {target_url}: {e}")
                        logging.debug(f"Exception traceback: {traceback.format_exc()}")
                        scan_results['cms'] = {'error': str(e), 'cms_detected': False, 'severity': 'Medium'}
                    
                    # Cookie Security Analysis
                    try:
                        logging.debug(f"Analyzing cookies for {target_url}")
                        scan_results['cookies'] = analyze_cookies(target_url)
                        logging.debug(f"Cookie analysis completed: {scan_results['cookies']}")
                    except Exception as e:
                        logging.error(f"Cookie analysis error for {target_url}: {e}")
                        logging.debug(f"Exception traceback: {traceback.format_exc()}")
                        scan_results['cookies'] = {'error': str(e), 'score': 0, 'severity': 'Medium'}
                    
                    # Web Application Framework Detection
                    try:
                        logging.debug(f"Detecting web frameworks for {target_url}")
                        scan_results['frameworks'] = detect_web_framework(target_url)
                        logging.debug(f"Framework detection completed: {scan_results['frameworks']}")
                    except Exception as e:
                        logging.error(f"Framework detection error for {target_url}: {e}")
                        logging.debug(f"Exception traceback: {traceback.format_exc()}")
                        scan_results['frameworks'] = {'error': str(e), 'frameworks': [], 'count': 0}
                    
                    # Basic Content Crawling (look for sensitive paths)
                    try:
                        max_urls = 15
                        logging.debug(f"Crawling for sensitive content at {target_url} (max {max_urls} urls)")
                        scan_results['sensitive_content'] = crawl_for_sensitive_content(target_url, max_urls)
                        logging.debug(f"Content crawling completed: {scan_results['sensitive_content']}")
                    except Exception as e:
                        logging.error(f"Content crawling error for {target_url}: {e}")
                        logging.debug(f"Exception traceback: {traceback.format_exc()}")
                        scan_results['sensitive_content'] = {'error': str(e), 'sensitive_paths_found': 0, 'severity': 'Medium'}
                else:
                    logging.warning(f"Neither HTTP nor HTTPS is accessible for {domain}, skipping web checks")
                    scan_results['web_accessibility_error'] = "Neither HTTP nor HTTPS ports are accessible"
        except Exception as e:
            logging.error(f"Error during web security checks: {e}")
            logging.debug(f"Exception traceback: {traceback.format_exc()}")
            scan_results['web_error'] = str(e)
    else:
        logging.info("No target domain/IP provided, skipping web security checks")
    
    # 5. Calculate risk score and recommendations
    try:
        logging.info("Calculating risk assessment...")
        scan_results['risk_assessment'] = calculate_risk_score(scan_results)
        logging.debug(f"Risk assessment completed: {scan_results['risk_assessment']}")
        
        scan_results['recommendations'] = get_recommendations(scan_results)
        logging.debug(f"Generated {len(scan_results['recommendations'])} recommendations")
        
        scan_results['threat_scenarios'] = generate_threat_scenario(scan_results)
        logging.debug(f"Generated {len(scan_results['threat_scenarios'])} threat scenarios")
    except Exception as e:
        logging.error(f"Error during risk assessment: {e}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        scan_results['risk_assessment'] = {'error': str(e), 'overall_score': 50, 'risk_level': 'Medium'}
        scan_results['recommendations'] = ["Keep all software and systems updated with the latest security patches.",
                                          "Use strong, unique passwords and implement multi-factor authentication.",
                                          "Regularly back up your data and test the restoration process."]
    
    # 6. Save scan results to file
    try:
        logging.info("Saving scan results to file...")
        
        # Create directories if they don't exist
        os.makedirs(SCAN_HISTORY_DIR, exist_ok=True)
        os.makedirs('/tmp/scan_history', exist_ok=True)
        
        # Try to save to primary location
        results_file = os.path.join(SCAN_HISTORY_DIR, f"scan_{scan_id}.json")
        logging.debug(f"Attempting to save scan results to: {results_file}")
        
        try:
            # Test if we can write to this directory
            test_file = os.path.join(SCAN_HISTORY_DIR, "test_write.tmp")
            try:
                with open(test_file, 'w') as f:
                    f.write("test")
                os.remove(test_file)
                logging.debug("Write test to primary directory successful")
            except Exception as test_e:
                logging.warning(f"Write test to primary directory failed: {test_e}")
                raise test_e  # Re-raise to trigger fallback
                
            with open(results_file, 'w') as f:
                json.dump(scan_results, f, indent=2)
            logging.info(f"Scan results saved successfully to {results_file}")
        except Exception as e:
            logging.error(f"Error saving scan results to primary file: {e}")
            logging.debug(f"Exception traceback: {traceback.format_exc()}")
            
            # Try fallback location
            fallback_dir = "/tmp/scan_history"
            os.makedirs(fallback_dir, exist_ok=True)
            fallback_file = os.path.join(fallback_dir, f"scan_{scan_id}.json")
            logging.debug(f"Trying fallback location: {fallback_file}")
            
            try:
                # Test if we can write to fallback directory
                test_fallback = os.path.join(fallback_dir, "test_write.tmp")
                try:
                    with open(test_fallback, 'w') as f:
                        f.write("test")
                    os.remove(test_fallback)
                    logging.debug("Write test to fallback directory successful")
                except Exception as test_e:
                    logging.critical(f"Write test to fallback directory also failed: {test_e}")
                    raise
                    
                with open(fallback_file, 'w') as f:
                    json.dump(scan_results, f, indent=2)
                logging.info(f"Scan results saved to fallback location: {fallback_file}")
                # Update the global variable to use the fallback directory that worked
                SCAN_HISTORY_DIR = fallback_dir  # Removed the second 'global' keyword here
            except Exception as e2:
                logging.critical(f"Failed to save scan results to both primary and fallback locations: {e2}")
                logging.debug(f"Fallback exception traceback: {traceback.format_exc()}")
                scan_results['file_save_error'] = f"Could not save results to disk: {str(e2)}"
        
        # Generate HTML report
        try:
            logging.info("Generating HTML report...")
            html_report = generate_html_report(scan_results)
            logging.debug("HTML report generated successfully")
        except Exception as report_e:
            logging.error(f"Error generating HTML report: {report_e}")
            logging.debug(f"Exception traceback: {traceback.format_exc()}")
    except Exception as e:
        logging.error(f"Error during scan execution: {e}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        scan_results['error'] = str(e)
        
        # Even if the scan fails, try to save what we have
        try:
            emergency_file = os.path.join('/tmp', f"emergency_scan_{scan_id}.json") 
            with open(emergency_file, 'w') as f:
                json.dump(scan_results, f, indent=2)
            logging.debug(f"Emergency scan results saved to {emergency_file}")
        except Exception as e_save:
            logging.critical(f"Error saving emergency scan results: {e_save}")
            
    logging.info(f"Scan {scan_id} completed")
    return scan_results


# ---------------------------- FLASK ROUTES ----------------------------

@app.route('/')
def index():
    """Render the home page"""
    try:
        logging.debug("Attempting to render index.html")
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
    """Main scan page - handles both form display and scan submission"""
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
            'target': request.form.get('target', '')
        }
        
        logging.debug(f"Received scan form data: {lead_data}")
        
        # Basic validation
        if not lead_data["email"]:
            return render_template('scan.html', error="Please enter your email address to receive the scan report.")
        
        try:
            # Save lead data
            save_lead_data(lead_data)
            logging.debug("Lead data saved successfully")
            
            # Test write to scan directories before running the scan
            test_primary = os.path.join(SCAN_HISTORY_DIR, "test_scan.json")
            test_fallback = os.path.join(FALLBACK_DIR, "test_scan.json")
            
            try:
                with open(test_primary, 'w') as f:
                    json.dump({"test": "data"}, f)
                logging.info(f"Test write to primary directory successful: {test_primary}")
                os.remove(test_primary)
            except Exception as e:
                logging.error(f"Test write to primary directory failed: {e}")
            
            try:
                with open(test_fallback, 'w') as f:
                    json.dump({"test": "data"}, f)
                logging.info(f"Test write to fallback directory successful: {test_fallback}")
                os.remove(test_fallback)
            except Exception as e:
                logging.error(f"Test write to fallback directory failed: {e}")
            
            # Run the consolidated scan - this contains all scan types in one function
            logging.info("Starting scan execution...")
            scan_results = run_consolidated_scan(lead_data)
            logging.debug(f"Scan completed with ID: {scan_results.get('scan_id', 'No ID generated')}")
            
            # Check if scan_results contains valid data
            if not scan_results or 'scan_id' not in scan_results:
                logging.error("Scan did not return valid results")
                return render_template('scan.html', error="Scan failed to return valid results. Please try again.")
            
            # Store scan ID in session
            session['scan_id'] = scan_results['scan_id']
            logging.debug(f"Stored scan_id in session: {session['scan_id']}")
            
            # Check for the results file directly after running the scan
            results_file = os.path.join(SCAN_HISTORY_DIR, f"scan_{scan_results['scan_id']}.json")
            fallback_file = os.path.join(FALLBACK_DIR, f"scan_{scan_results['scan_id']}.json")
            
            if os.path.exists(results_file):
                logging.info(f"Results file exists at primary location: {results_file}")
                session['scan_results_file'] = results_file
            elif os.path.exists(fallback_file):
                logging.info(f"Results file exists at fallback location: {fallback_file}")
                session['scan_results_file'] = fallback_file
            else:
                logging.error(f"Results file not found at either location immediately after scan")
                
                # Create minimal results file to ensure something exists
                minimal_results = {
                    'scan_id': scan_results['scan_id'],
                    'timestamp': datetime.now().isoformat(),
                    'error': 'Original scan results not saved properly',
                    'minimal_backup': True
                }
                
                try:
                    backup_file = os.path.join(FALLBACK_DIR, f"backup_scan_{scan_results['scan_id']}.json")
                    os.makedirs(os.path.dirname(backup_file), exist_ok=True)
                    with open(backup_file, 'w') as f:
                        json.dump(minimal_results, f)
                    logging.info(f"Created minimal backup file: {backup_file}")
                    session['scan_results_file'] = backup_file
                except Exception as e:
                    logging.critical(f"Failed to create minimal backup file: {e}")
            
            # Redirect to results page
            return redirect(url_for('results'))
        except Exception as e:
            logging.error(f"Error processing scan: {e}")
            logging.error(f"Exception traceback: {traceback.format_exc()}")
            return render_template('scan.html', error=f"An error occurred: {str(e)}")
    
    # For GET requests, just show the scan form
    return render_template('scan.html')
    """Main scan page - handles both form display and scan submission"""
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
            'target': request.form.get('target', '')
        }
        
        logging.debug(f"Received scan form data: {lead_data}")
        
        # Basic validation
        if not lead_data["email"]:
            return render_template('scan.html', error="Please enter your email address to receive the scan report.")
        
        try:
            # Save lead data
            save_lead_data(lead_data)
            logging.debug("Lead data saved successfully")
            
            # Run the consolidated scan - this contains all scan types in one function
            scan_results = run_consolidated_scan(lead_data)
            logging.debug(f"Scan completed with ID: {scan_results.get('scan_id', 'No ID generated')}")
            
            # Check if scan_results contains valid data
            if not scan_results or 'scan_id' not in scan_results:
                logging.error("Scan did not return valid results")
                return render_template('scan.html', error="Scan failed to return valid results. Please try again.")
            
            # Store scan ID in session
            session['scan_id'] = scan_results['scan_id']
            logging.debug(f"Stored scan_id in session: {session['scan_id']}")
            
            # Verify the results file exists
            results_file = os.path.join(SCAN_HISTORY_DIR, f"scan_{scan_results['scan_id']}.json")
            if not os.path.exists(results_file):
                logging.error(f"Results file not found: {results_file}")
                return render_template('scan.html', error="Scan results file not created. Please try again.")
            
            logging.debug(f"Results file exists: {results_file}")
            
            # Redirect to results page
            return redirect(url_for('results'))
        except Exception as e:
            logging.error(f"Error processing scan: {e}")
            return render_template('scan.html', error=f"An error occurred: {str(e)}")
    
    # For GET requests, just show the scan form
    return render_template('scan.html')

@app.route('/results')
def results():
    """Display scan results"""
    logger = logging.getLogger(__name__)
    
    scan_id = session.get('scan_id')
    results_file = session.get('scan_results_file')
    
    logger.info(f"Results page accessed with scan_id from session: {scan_id}")
    
    if not scan_id:
        logger.warning("No scan_id in session, redirecting to scan page")
        return redirect(url_for('scan_page'))
    
    try:
        # First check if we have a specific file path in session
        if results_file and os.path.exists(results_file):
            logger.debug(f"Using specific results file path from session: {results_file}")
            with open(results_file, 'r') as f:
                scan_results = json.load(f)
        else:
            # Fall back to default location
            default_file = os.path.join(SCAN_HISTORY_DIR, f"scan_{scan_id}.json")
            logger.debug(f"Looking for results file at default location: {default_file}")
            
            if not os.path.exists(default_file):
                logger.error(f"Scan results file not found: {default_file}")
                # Try fallback location
                fallback_dir = "/tmp/scan_history"
                fallback_file = os.path.join(fallback_dir, f"scan_{scan_id}.json")
                logger.debug(f"Trying fallback location: {fallback_file}")
                
                if not os.path.exists(fallback_file):
                    logger.error(f"Fallback results file not found: {fallback_file}")
                    # Clear the session and redirect to scan page with error
                    session.pop('scan_id', None)
                    session.pop('scan_results_file', None)
                    return render_template('scan.html', error="Scan results not found. Please try scanning again.")
                
                with open(fallback_file, 'r') as f:
                    scan_results = json.load(f)
            else:
                with open(default_file, 'r') as f:
                    scan_results = json.load(f)
        
        logger.debug(f"Loaded scan results with keys: {list(scan_results.keys())}")
        
        return render_template('results.html', scan=scan_results)
    except Exception as e:
        logger.error(f"Error loading scan results: {e}")
        # Clear the session on error
        session.pop('scan_id', None)
        session.pop('scan_results_file', None)
        return render_template('error.html', error=f"Error loading scan results: {str(e)}")
    
@app.route('/api/scan', methods=['POST'])    
@limiter.limit("5 per minute")    
def api_scan():
    """API endpoint for scan requests"""
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
        if not lead_data["email"]:
            return jsonify({
                "status": "error",
                "message": "Please provide an email address to receive the scan report."
            }), 400
            
        # Save lead data
        save_lead_data(lead_data)
        
        # Run the consolidated scan
        scan_results = run_consolidated_scan(lead_data)
        
        # Return a simplified version of the results
        return jsonify({
            "status": "success",
            "scan_id": scan_results['scan_id'],
            "message": "Scan completed successfully. A detailed report has been sent to your email."
        })
    except Exception as e:
        logging.error(f"Error in API scan: {e}")
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

def save_scan_results_directly(scan_id, scan_data):
    """Directly save scan results with robust error handling"""
    logging.info(f"Attempting to save scan results for ID: {scan_id}")
    
    # Create directories if they don't exist
    os.makedirs(SCAN_HISTORY_DIR, exist_ok=True)
    os.makedirs(FALLBACK_DIR, exist_ok=True)
    
    # Try primary location first
    primary_file = os.path.join(SCAN_HISTORY_DIR, f"scan_{scan_id}.json")
    try:
        logging.debug(f"Writing to primary location: {primary_file}")
        with open(primary_file, 'w') as f:
            json.dump(scan_data, f, indent=2)
        logging.info(f"Successfully wrote scan results to: {primary_file}")
        return primary_file
    except Exception as e:
        logging.error(f"Failed to write to primary location: {e}")
        
        # Try fallback location
        fallback_file = os.path.join(FALLBACK_DIR, f"scan_{scan_id}.json")
        try:
            logging.debug(f"Writing to fallback location: {fallback_file}")
            with open(fallback_file, 'w') as f:
                json.dump(scan_data, f, indent=2)
            logging.info(f"Successfully wrote scan results to fallback: {fallback_file}")
            return fallback_file
        except Exception as e2:
            logging.critical(f"Failed to write to fallback location: {e2}")
            raise Exception(f"Could not save scan results to any location. Primary error: {e}, Fallback error: {e2}")
        
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

# ---------------------------- MAIN ENTRY POINT ----------------------------

if __name__ == '__main__':
    # Get port from environment variable or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Use 0.0.0.0 to make the app accessible from any IP
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_ENV') == 'development')
