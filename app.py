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

# Call this at application startup
log_system_info()

# Configure logging with file and console handlers
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
    
    logging.debug(f"Starting scan with ID: {scan_id}")
    
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
    except Exception as e:
        logging.error(f"Error during system security checks: {e}")
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
    except Exception as e:
        logging.error(f"Error during network security checks: {e}")
        scan_results['network'] = {'error': str(e)}
    
    # 3. Email Security Checks
    try:
        logging.info("Running email security checks...")
        email = lead_data.get('email', '')
        if "@" in email:
            domain = extract_domain_from_email(email)
            spf_status, spf_severity = check_spf_status(domain)
            dmarc_status, dmarc_severity = check_dmarc_record(domain)
            dkim_status, dkim_severity = check_dkim_record(domain)
            
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
        else:
            scan_results['email_security'] = {
                'error': 'No valid email provided'
            }
    except Exception as e:
        logging.error(f"Error during email security checks: {e}")
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
            except socket.error:
                is_domain = True
            
            scan_results['is_domain'] = is_domain
            
            if is_domain:
                # Normalize the domain
                if target.startswith('http://') or target.startswith('https://'):
                    parsed_url = urllib.parse.urlparse(target)
                    domain = parsed_url.netloc
                else:
                    domain = target
                
                # Check if ports 80 or 443 are accessible
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
            logging.error(f"Error during web security checks: {e}")
            scan_results['web_error'] = str(e)
    
    # 5. Calculate risk score and recommendations
    try:
        logging.info("Calculating risk assessment...")
        scan_results['risk_assessment'] = calculate_risk_score(scan_results)
        scan_results['recommendations'] = get_recommendations(scan_results)
        scan_results['threat_scenarios'] = generate_threat_scenario(scan_results)
    except Exception as e:
        logging.error(f"Error during risk assessment: {e}")
        scan_results['risk_assessment'] = {'error': str(e)}
    
    # 6. Generate and send email report
    try:
        logging.info("Generating HTML report...")
        html_report = generate_html_report(scan_results)
        
        # Save scan results to file
        results_file = os.path.join(SCAN_HISTORY_DIR, f"scan_{scan_id}.json")
        logging.debug(f"Saving scan results to: {results_file}")
        try:
            with open(results_file, 'w') as f:
                json.dump(scan_results, f, indent=2)
            logging.debug(f"Scan results saved successfully to {results_file}")
        except Exception as e:
            logging.error(f"Error saving scan results to file: {e}")
            # Try with a different directory if the main one fails
            fallback_dir = "/tmp/scan_history"
            os.makedirs(fallback_dir, exist_ok=True)
            fallback_file = os.path.join(fallback_dir, f"scan_{scan_id}.json")
            logging.debug(f"Trying fallback location: {fallback_file}")
            with open(fallback_file, 'w') as f:
                json.dump(scan_results, f, indent=2)
            logging.debug(f"Scan results saved to fallback location: {fallback_file}")
            # Update the SCAN_HISTORY_DIR to the fallback location that worked
            SCAN_HISTORY_DIR = fallback_dir
            
        return scan_results
        
    except Exception as e:
        logging.error(f"Error during scan execution: {e}")
        scan_results['error'] = str(e)
        
        # Even if the scan fails, try to save what we have
        results_file = os.path.join(SCAN_HISTORY_DIR, f"scan_{scan_id}.json") 
        try:
            with open(results_file, 'w') as f:
                json.dump(scan_results, f, indent=2)
            logging.debug(f"Partial scan results saved to {results_file}")
        except Exception as e_save:
            logging.error(f"Error saving partial scan results: {e_save}")
            
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
    logger.debug(f"Results file path from session: {results_file}")
    
    if not scan_id:
        logger.warning("No scan_id in session, redirecting to scan page")
        return redirect(url_for('scan_page'))
    
    try:
        # First check if we have a specific file path in session
        if results_file and os.path.exists(results_file):
            logger.debug(f"Using specific results file path from session: {results_file}")
            logger.debug(f"File size: {os.path.getsize(results_file)} bytes")
            
            with open(results_file, 'r') as f:
                scan_results = json.load(f)
                logger.debug(f"Successfully loaded JSON from {results_file}")
        else:
            # Fall back to default location
            default_file = os.path.join(SCAN_HISTORY_DIR, f"scan_{scan_id}.json")
            logger.debug(f"Looking for results file at default location: {default_file}")
            
            if os.path.exists(default_file):
                logger.debug(f"Default file exists. Size: {os.path.getsize(default_file)} bytes")
            else:
                logger.error(f"Scan results file not found: {default_file}")
            
            if not os.path.exists(default_file):
                # Try fallback location
                fallback_dir = FALLBACK_DIR
                fallback_file = os.path.join(fallback_dir, f"scan_{scan_id}.json")
                logger.debug(f"Trying fallback location: {fallback_file}")
                
                if os.path.exists(fallback_file):
                    logger.debug(f"Fallback file exists. Size: {os.path.getsize(fallback_file)} bytes")
                else:
                    logger.error(f"Fallback results file not found: {fallback_file}")
                
                if not os.path.exists(fallback_file):
                    # Do a directory listing to see what files are available
                    try:
                        primary_files = os.listdir(SCAN_HISTORY_DIR)
                        logger.debug(f"Files in primary directory: {primary_files}")
                    except Exception as e:
                        logger.warning(f"Could not list primary directory: {e}")
                    
                    try:
                        fallback_files = os.listdir(FALLBACK_DIR)
                        logger.debug(f"Files in fallback directory: {fallback_files}")
                    except Exception as e:
                        logger.warning(f"Could not list fallback directory: {e}")
                    
                    logger.error("No results file found in any location")
                    return render_template('error.html', error="Scan results not found. Please try scanning again.")
                
                with open(fallback_file, 'r') as f:
                    scan_results = json.load(f)
                    logger.debug(f"Successfully loaded JSON from fallback location")
            else:
                with open(default_file, 'r') as f:
                    scan_results = json.load(f)
                    logger.debug(f"Successfully loaded JSON from default location")
        
        logger.debug(f"Loaded scan results with keys: {list(scan_results.keys())}")
        
        return render_template('results.html', scan=scan_results)
    except Exception as e:
        logger.error(f"Error loading scan results: {e}")
        logger.debug(f"Exception traceback: {traceback.format_exc()}")
        return render_template('error.html', error=f"Error loading scan results: {str(e)}")
    """Display scan results"""
    scan_id = session.get('scan_id')
    results_file = session.get('scan_results_file')  # Check for fallback file location
    
    logging.debug(f"Results page accessed with scan_id from session: {scan_id}")
    
    if not scan_id:
        logging.warning("No scan_id in session, redirecting to scan page")
        return redirect(url_for('scan_page'))
    
    try:
        # First check if we have a specific file path in session
        if results_file and os.path.exists(results_file):
            logging.debug(f"Using specific results file path from session: {results_file}")
            with open(results_file, 'r') as f:
                scan_results = json.load(f)
        else:
            # Fall back to default location
            default_file = os.path.join(SCAN_HISTORY_DIR, f"scan_{scan_id}.json")
            logging.debug(f"Looking for results file at default location: {default_file}")
            
            if not os.path.exists(default_file):
                logging.error(f"Scan results file not found: {default_file}")
                # Try fallback location
                fallback_dir = "/tmp/scan_history"
                fallback_file = os.path.join(fallback_dir, f"scan_{scan_id}.json")
                logging.debug(f"Trying fallback location: {fallback_file}")
                
                if not os.path.exists(fallback_file):
                    logging.error(f"Fallback results file not found: {fallback_file}")
                    return render_template('error.html', error="Scan results not found. Please try scanning again.")
                
                with open(fallback_file, 'r') as f:
                    scan_results = json.load(f)
            else:
                with open(default_file, 'r') as f:
                    scan_results = json.load(f)
        
        logging.debug(f"Loaded scan results with keys: {list(scan_results.keys())}")
        
        return render_template('results.html', scan=scan_results)
    except Exception as e:
        logging.error(f"Error loading scan results: {e}")
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

@log_function_call
def save_scan_results(scan_id, scan_results):
    """Dedicated function to save scan results to file with robust error handling"""
    logger = logging.getLogger(__name__)
    
    # Primary location
    primary_path = os.path.join(SCAN_HISTORY_DIR, f"scan_{scan_id}.json")
    
    # Log path details and directory permissions
    logger.debug(f"Primary save path: {primary_path}")
    logger.debug(f"Directory exists: {os.path.exists(os.path.dirname(primary_path))}")
    
    try:
        if os.path.exists(os.path.dirname(primary_path)):
            logger.debug(f"Directory permissions: {oct(os.stat(os.path.dirname(primary_path)).st_mode)[-3:]}")
    except Exception as e:
        logger.warning(f"Could not check directory permissions: {e}")
    
    try:
        # Create directory if needed
        os.makedirs(os.path.dirname(primary_path), exist_ok=True)
        
        # Test if we can write to this directory
        test_file = os.path.join(os.path.dirname(primary_path), "test_write.tmp")
        try:
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
            logger.debug("Write test to primary directory successful")
        except Exception as e:
            logger.warning(f"Write test to primary directory failed: {e}")
            raise  # Re-raise to trigger fallback
        
        # Save the actual results
        with open(primary_path, 'w') as f:
            json.dump(scan_results, f, indent=2)
        
        logger.info(f"Scan results saved successfully to {primary_path}")
        return primary_path
    except Exception as e:
        logger.error(f"Failed to save to primary location: {e}")
        logger.debug(f"Exception details: {traceback.format_exc()}")
        
        # Try fallback location
        fallback_path = os.path.join(FALLBACK_DIR, f"scan_{scan_id}.json")
        logger.debug(f"Trying fallback location: {fallback_path}")
        
        try:
            os.makedirs(os.path.dirname(fallback_path), exist_ok=True)
            
            with open(fallback_path, 'w') as f:
                json.dump(scan_results, f, indent=2)
            
            logger.info(f"Scan results saved to fallback location: {fallback_path}")
            return fallback_path
        except Exception as e2:
            logger.critical(f"Failed to save to fallback location as well: {e2}")
            logger.debug(f"Fallback exception details: {traceback.format_exc()}")
            raise Exception(f"Could not save scan results: {e}. Fallback also failed: {e2}")

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
