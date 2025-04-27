# app.py - Main Flask application
import logging
import os
import sqlite3
import platform
import socket
import re
import uuid
import urllib.parse
from datetime import datetime
import json
import sys
import traceback
import requests
from datetime import timedelta
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Import scan functionality
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

# Import database functionality
from db import init_db, save_scan_results, get_scan_results, save_lead_data, DB_PATH

# Constants
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

# Setup logging
def setup_logging():
    """Configure application logging"""
    # Create logs directory
    logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    
    log_filename = os.path.join(logs_dir, f"security_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    
    # Remove any existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
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
    
    logger.info("Application started")
    logger.info(f"Detailed logs will be saved to: {log_filename}")
    
    return logger

# Log system information
def log_system_info():
    """Log details about the system environment"""
    logger = logging.getLogger(__name__)
    
    logger.info("----- System Information -----")
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Platform: {platform.platform()}")
    logger.info(f"Working directory: {os.getcwd()}")
    logger.info(f"Database path: {DB_PATH}")
    
    # Test database connection
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT sqlite_version()")
        version = cursor.fetchone()
        logger.info(f"SQLite version: {version[0]}")
        conn.close()
        logger.info("Database connection successful")
    except Exception as e:
        logger.warning(f"Database connection failed: {e}")
    
    logger.info("-----------------------------")

# Initialize Flask app
app = Flask(__name__)
# Use a strong secret key - don't rely on environment variables in this case
app.secret_key = 'your_strong_secret_key_here'  # Replace with a secure random string
app.config['SESSION_TYPE'] = 'filesystem'  # Store sessions in files
app.config['SESSION_PERMANENT'] = True  # Make sessions permanent
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Sessions last 1 hour
CORS(app, supports_credentials=True)
app.secret_key = os.environ.get('SECRET_KEY', 'your_temporary_secret_key')

# Initialize limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)
logging.warning("Using in-memory storage for rate limiting. Not recommended for production.")

# Initialize logging and database
logger = setup_logging()
init_db()
log_system_info()

def get_scan_id_from_request():
    """Get scan_id from session or query parameters"""
    # Try to get from session first
    scan_id = session.get('scan_id')
    if scan_id:
        logging.debug(f"Found scan_id in session: {scan_id}")
        return scan_id
    
    # If not in session, try query parameters
    scan_id = request.args.get('scan_id')
    if scan_id:
        logging.debug(f"Found scan_id in query parameters: {scan_id}")
        return scan_id
    
    logging.warning("No scan_id found in session or query parameters")
    return None

# ---------------------------- MAIN SCANNING FUNCTION ----------------------------

def run_consolidated_scan(lead_data):
    """Run a complete security scan and generate one comprehensive report"""
    scan_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    
    logging.info(f"Starting scan with ID: {scan_id} for target: {lead_data.get('target', 'Unknown')}")
    
    # Initialize scan results structure 
    scan_results = {
        'scan_id': scan_id,
        'timestamp': timestamp,
        'target': lead_data.get('target', ''),
        'email': lead_data.get('email', ''),
        'client_info': {
            'os': lead_data.get('client_os', 'Unknown'),
            'browser': lead_data.get('client_browser', 'Unknown'),
            'windows_version': lead_data.get('windows_version', '')
        }
    }
    
    # Add this debug line to check the initial scan results structure
    logging.debug(f"Initial scan_results structure: {json.dumps(scan_results, default=str)}")
    
    
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
            logging.debug(f"Gateway checks completed")
        except Exception as gateway_error:
            logging.error(f"Error during gateway checks: {gateway_error}")
            scan_results['network']['gateway'] = {'error': str(gateway_error)}
            
        logging.debug(f"Network security checks completed")
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
                logging.debug(f"SPF check completed")
            except Exception as spf_error:
                logging.error(f"Error checking SPF for {domain}: {spf_error}")
                spf_status, spf_severity = f"Error checking SPF: {str(spf_error)}", "High"
                
            try:
                dmarc_status, dmarc_severity = check_dmarc_record(domain)
                logging.debug(f"DMARC check completed")
            except Exception as dmarc_error:
                logging.error(f"Error checking DMARC for {domain}: {dmarc_error}")
                dmarc_status, dmarc_severity = f"Error checking DMARC: {str(dmarc_error)}", "High"
                
            try:
                dkim_status, dkim_severity = check_dkim_record(domain)
                logging.debug(f"DKIM check completed")
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
                            logging.debug(f"SSL certificate check completed")
                        except Exception as e:
                            logging.error(f"SSL check error for {domain}: {e}")
                            logging.debug(f"Exception traceback: {traceback.format_exc()}")
                            scan_results['ssl_certificate'] = {'error': str(e), 'status': 'error', 'severity': 'High'}
                    
                    # HTTP Security Headers Assessment
                    try:
                        logging.debug(f"Checking security headers for {target_url}")
                        scan_results['security_headers'] = check_security_headers(target_url)
                        logging.debug(f"Security headers check completed")
                    except Exception as e:
                        logging.error(f"Headers check error for {target_url}: {e}")
                        logging.debug(f"Exception traceback: {traceback.format_exc()}")
                        scan_results['security_headers'] = {'error': str(e), 'score': 0, 'severity': 'High'}
                    
                    # CMS Detection
                    try:
                        logging.debug(f"Detecting CMS for {target_url}")
                        scan_results['cms'] = detect_cms(target_url)
                        logging.debug(f"CMS detection completed")
                    except Exception as e:
                        logging.error(f"CMS detection error for {target_url}: {e}")
                        logging.debug(f"Exception traceback: {traceback.format_exc()}")
                        scan_results['cms'] = {'error': str(e), 'cms_detected': False, 'severity': 'Medium'}
                    
                    # Cookie Security Analysis
                    try:
                        logging.debug(f"Analyzing cookies for {target_url}")
                        scan_results['cookies'] = analyze_cookies(target_url)
                        logging.debug(f"Cookie analysis completed")
                    except Exception as e:
                        logging.error(f"Cookie analysis error for {target_url}: {e}")
                        logging.debug(f"Exception traceback: {traceback.format_exc()}")
                        scan_results['cookies'] = {'error': str(e), 'score': 0, 'severity': 'Medium'}
                    
                    # Web Application Framework Detection
                    try:
                        logging.debug(f"Detecting web frameworks for {target_url}")
                        scan_results['frameworks'] = detect_web_framework(target_url)
                        logging.debug(f"Framework detection completed")
                    except Exception as e:
                        logging.error(f"Framework detection error for {target_url}: {e}")
                        logging.debug(f"Exception traceback: {traceback.format_exc()}")
                        scan_results['frameworks'] = {'error': str(e), 'frameworks': [], 'count': 0}
                    
                    # Basic Content Crawling (look for sensitive paths)
                    try:
                        max_urls = 15
                        logging.debug(f"Crawling for sensitive content at {target_url} (max {max_urls} urls)")
                        scan_results['sensitive_content'] = crawl_for_sensitive_content(target_url, max_urls)
                        logging.debug(f"Content crawling completed")
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
        logging.debug(f"Risk assessment completed")
        
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
    
    # 6. Generate HTML report
    try:
        logging.info("Generating HTML report...")
        html_report = generate_html_report(scan_results)
        scan_results['html_report'] = html_report
        logging.debug("HTML report generated successfully")
    except Exception as report_e:
        logging.error(f"Error generating HTML report: {report_e}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        scan_results['html_report_error'] = str(report_e)
    
    # 7. Save to database
    try:
        logging.info("Saving scan results to database...")
        saved_scan_id = save_scan_results(scan_results)
        
        if not saved_scan_id:
            logging.error("Database save function returned None or False")
            scan_results['database_error'] = "Failed to save scan results to database"
        else:
            logging.info(f"Scan results saved to database with ID: {saved_scan_id}")
    except Exception as db_error:
        logging.error(f"Exception during database save: {str(db_error)}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        scan_results['database_error'] = f"Database error: {str(db_error)}"
    
    logging.info(f"Scan {scan_id} completed")
    logging.debug(f"Final scan_results keys: {list(scan_results.keys())}")

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
        try:
            # Get form data
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
            
            # Save lead data
            saved_lead = save_lead_data(lead_data)
            logging.debug(f"Result of save_lead_data: {saved_lead}")
            
            # Run the scan with detailed logging
            logging.info(f"Starting scan execution for {lead_data['email']}...")
            
            # This is the critical line - run the scan
            scan_results = run_consolidated_scan(lead_data)
            
            # Add detailed logging
            if scan_results:
                logging.info(f"Scan completed with ID: {scan_results.get('scan_id', 'MISSING')}")
                logging.info(f"Available keys: {list(scan_results.keys())}")
            else:
                logging.error("Scan results are None")
                return render_template('scan.html', error="Scan failed to complete. Please try again.")
            
            # Save scan results to database with detailed logging
            try:
                logging.info(f"Saving scan results to database for ID: {scan_results['scan_id']}")
                saved_scan_id = save_scan_results(scan_results)
                logging.info(f"Save result: {saved_scan_id}")
                
                if not saved_scan_id:
                    logging.error("Failed to save scan results to database")
                    return render_template('scan.html', error="Failed to save scan results. Please try again.")
            except Exception as db_error:
                logging.error(f"Exception during database save: {str(db_error)}")
                logging.debug(f"Exception traceback: {traceback.format_exc()}")
                return render_template('scan.html', error=f"Database error: {str(db_error)}")
            
            # Try to store scan_id in session
            try:
                session['scan_id'] = scan_results['scan_id']
                logging.info(f"Stored scan_id in session: {scan_results['scan_id']}")
            except Exception as session_error:
                logging.error(f"Failed to store scan_id in session: {str(session_error)}")
            
            # Always redirect to the direct URL
            direct_url = url_for('results_direct', scan_id=scan_results['scan_id'])
            logging.info(f"Redirecting to: {direct_url}")
            return redirect(direct_url)
        except Exception as e:
            logging.error(f"Error processing scan: {e}")
            logging.debug(f"Exception traceback: {traceback.format_exc()}")
            return render_template('scan.html', error=f"An error occurred: {str(e)}")
    
    # For GET requests, show the scan form
    error = request.args.get('error')
    return render_template('scan.html', error=error)

@app.route('/results')
def results():
    """Display scan results"""
    # Get scan_id from either session or query parameters
    scan_id = get_scan_id_from_request()
    logging.info(f"Results page accessed with scan_id: {scan_id}")
    
    if not scan_id:
        logging.warning("No scan_id found, redirecting to scan page")
        return redirect(url_for('scan_page', error="No scan ID found. Please run a new scan."))
    
    try:
        # Get scan results from database
        scan_results = get_scan_results(scan_id)
        
        if not scan_results:
            logging.error(f"No scan results found for ID: {scan_id}")
            # Clear the session and redirect
            session.pop('scan_id', None)
            return redirect(url_for('scan_page', error="Scan results not found. Please try running a new scan."))
        
        logging.debug(f"Loaded scan results with keys: {list(scan_results.keys())}")
        return render_template('results.html', scan=scan_results)
    except Exception as e:
        logging.error(f"Error loading scan results: {e}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        return render_template('error.html', error=f"Error loading scan results: {str(e)}")
    
@app.route('/db_check')
def db_check():
    """Check if the database is set up and working properly"""
    try:
        # Try to connect to the database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        # Get count of records in each table
        table_counts = {}
        for table in tables:
            table_name = table[0]
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            count = cursor.fetchone()[0]
            table_counts[table_name] = count
        
        conn.close()
        
        return jsonify({
            "status": "success",
            "database_path": DB_PATH,
            "tables": [table[0] for table in tables],
            "record_counts": table_counts,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e),
            "trace": traceback.format_exc()
        })

@app.route('/test_db_write')
def test_db_write():
    """Test direct database write functionality"""
    try:
        # Create test data
        test_data = {
            'scan_id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'target': 'test.com',
            'email': 'test@example.com',
            'test_field': 'This is a test'
        }
        
        # Try to save to database
        saved_id = save_scan_results(test_data)
        
        if saved_id:
            # Try to retrieve it
            retrieved = get_scan_results(saved_id)
            
            return jsonify({
                'status': 'success',
                'message': 'Database write and read successful',
                'saved_id': saved_id,
                'retrieved': retrieved is not None,
                'record_matches': retrieved is not None and retrieved.get('test_field') == test_data['test_field']
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Database write failed - save_scan_results returned None or False'
            })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Exception during database test: {str(e)}',
            'traceback': traceback.format_exc()
        })

@app.route('/clear_session')
def clear_session():
    """Clear the current session to start fresh"""
    # Clear existing session data
    session.clear()
    logging.info("Session cleared")
    
    return jsonify({
        "status": "success",
        "message": "Session cleared successfully. You can now run a new scan.",
        "redirect": url_for('scan_page')
    })

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
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        return jsonify({
            "status": "error",
            "message": f"An error occurred during the scan: {str(e)}"
        }), 500

@app.route('/results_direct')
def results_direct():
    """Display scan results directly from query parameter"""
    scan_id = request.args.get('scan_id')
    
    if not scan_id:
        return "No scan ID provided", 400
    
    try:
        # Get results from database
        scan_results = get_scan_results(scan_id)
        
        if not scan_results:
            return f"No results found for scan ID: {scan_id}", 404
        
        # Return a simplified view of the results
        return f"""
        <html>
            <head>
                <title>Scan Results</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .section {{ margin-bottom: 20px; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }}
                </style>
            </head>
            <body>
                <h1>Scan Results</h1>
                
                <div class="section">
                    <h2>Scan Information</h2>
                    <p><strong>Scan ID:</strong> {scan_results['scan_id']}</p>
                    <p><strong>Timestamp:</strong> {scan_results['timestamp']}</p>
                    <p><strong>Email:</strong> {scan_results['email']}</p>
                </div>
                
                <div class="section">
                    <h2>Risk Assessment</h2>
                    <p><strong>Overall Score:</strong> {scan_results['risk_assessment']['overall_score']}</p>
                    <p><strong>Risk Level:</strong> {scan_results['risk_assessment']['risk_level']}</p>
                </div>
                
                <div class="section">
                    <h2>Recommendations</h2>
                    <ul>
                        {''.join([f'<li>{r}</li>' for r in scan_results['recommendations']])}
                    </ul>
                </div>
                
                <a href="/scan">Run another scan</a>
            </body>
        </html>
        """
    except Exception as e:
        return f"Error loading results: {str(e)}", 500
    
@app.route('/quick_scan', methods=['GET', 'POST'])
def quick_scan():
    """A simplified scan form for testing"""
    if request.method == 'POST':
        try:
            email = request.form.get('email', '')
            target = request.form.get('target', '')
            
            if not email:
                return "Email is required", 400
            
            # Create minimal test data
            test_data = {
                'name': 'Test User',
                'email': email,
                'company': 'Test Company',
                'phone': '555-1234',
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'client_os': 'Test OS',
                'client_browser': 'Test Browser',
                'windows_version': '',
                'target': target
            }
            
            logging.info(f"Starting quick scan for {email}...")
            scan_results = run_consolidated_scan(test_data)
            
            if not scan_results or 'scan_id' not in scan_results:
                return "Scan failed to complete", 500
            
            # Save to database
            saved_id = save_scan_results(scan_results)
            if not saved_id:
                return "Failed to save scan results", 500
            
            # Redirect to results
            return redirect(url_for('results_direct', scan_id=scan_results['scan_id']))
        except Exception as e:
            logging.error(f"Error in quick_scan: {e}")
            return f"Error: {str(e)}", 500
    
    # Simple form for GET requests
    return """
    <html>
        <head><title>Quick Scan Test</title></head>
        <body>
            <h1>Quick Scan Test</h1>
            <form method="post">
                <div>
                    <label>Email: <input type="email" name="email" required></label>
                </div>
                <div>
                    <label>Target (optional): <input type="text" name="target"></label>
                </div>
                <button type="submit">Run Quick Scan</button>
            </form>
        </body>
    </html>
    """
@app.route('/debug_post', methods=['POST'])  
def debug_post():
    """Debug endpoint to check POST data"""
    try:
        # Log all form data
        form_data = {key: request.form.get(key) for key in request.form}
        logging.info(f"Received POST data: {form_data}")
        
        # Return a success response
        return jsonify({
            "status": "success",
            "received_data": form_data
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e)
        })
        
@app.route('/debug_db')
def debug_db():
    """Debug endpoint to check database contents"""
    try:
        # Connect to the database
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        # Get sample rows from each table
        samples = {}
        for table in tables:
            try:
                cursor.execute(f"SELECT * FROM {table} LIMIT 5")
                rows = cursor.fetchall()
                if rows:
                    # Convert rows to dictionaries
                    samples[table] = [dict(row) for row in rows]
                else:
                    samples[table] = []
            except Exception as table_error:
                samples[table] = f"Error: {str(table_error)}"
        
        conn.close()
        
        # Generate HTML response
        output = f"""
        <html>
            <head>
                <title>Database Debug</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                </style>
            </head>
            <body>
                <h1>Database Debug Information</h1>
                <p><strong>Database Path:</strong> {DB_PATH}</p>
                <h2>Tables:</h2>
                <ul>
        """
        
        for table in tables:
            row_count = len(samples[table]) if isinstance(samples[table], list) else "Error"
            output += f"<li>{table} ({row_count} sample rows)</li>\n"
        
        output += "</ul>\n"
        
        # Show sample data from each table
        for table in tables:
            output += f"<h2>Sample data from {table}:</h2>\n"
            
            if isinstance(samples[table], list):
                if samples[table]:
                    # Get column names from first row
                    columns = samples[table][0].keys()
                    
                    output += "<table>\n<tr>\n"
                    for col in columns:
                        output += f"<th>{col}</th>\n"
                    output += "</tr>\n"
                    
                    # Add data rows
                    for row in samples[table]:
                        output += "<tr>\n"
                        for col in columns:
                            # Limit large values and convert non-strings to strings
                            value = str(row[col])
                            if len(value) > 100:
                                value = value[:100] + "..."
                            output += f"<td>{value}</td>\n"
                        output += "</tr>\n"
                    
                    output += "</table>\n"
                else:
                    output += "<p>No data in this table</p>\n"
            else:
                output += f"<p>{samples[table]}</p>\n"
        
        output += """
                <p><a href="/scan">Return to Scan Page</a></p>
            </body>
        </html>
        """
        
        return output
    except Exception as e:
        return f"""
        <html>
            <head><title>Database Error</title></head>
            <body>
                <h1>Database Debug Error</h1>
                <p>An error occurred while accessing the database: {str(e)}</p>
                <p><pre>{traceback.format_exc()}</pre></p>
            </body>
        </html>
        """
                
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

@app.route('/debug_session')
def debug_session():
    """Debug endpoint to verify session functionality"""
    # Get existing scan_id if any
    scan_id = session.get('scan_id')
    
    # Set a test value in session
    session['test_value'] = str(datetime.now())
    
    return jsonify({
        "session_working": True,
        "current_scan_id": scan_id,
        "test_value_set": session['test_value'],
        "all_keys": list(session.keys())
    })

@app.route('/test_scan')
def test_scan():
    """Test scan execution directly"""
    try:
        # Create test lead data
        test_data = {
            'name': 'Test User',
            'email': 'test@example.com',
            'company': 'Test Company',
            'phone': '555-1234',
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'client_os': 'Test OS',
            'client_browser': 'Test Browser',
            'windows_version': 'Test Windows',
            'target': 'example.com'
        }
        
        # Run scan
        logging.info("Starting test scan execution...")
        scan_results = run_consolidated_scan(test_data)
        
        # Check if we got a valid result
        if scan_results and 'scan_id' in scan_results:
            # Try to save to database
            try:
                saved_id = save_scan_results(scan_results)
                db_status = f"Successfully saved to database with ID: {saved_id}" if saved_id else "Failed to save to database"
            except Exception as db_error:
                db_status = f"Database error: {str(db_error)}"
            
            # Return success output
            return f"""
            <html>
                <head><title>Test Scan Success</title></head>
                <body>
                    <h1>Test Scan Completed Successfully</h1>
                    <p><strong>Scan ID:</strong> {scan_results['scan_id']}</p>
                    <p><strong>Database Status:</strong> {db_status}</p>
                    <p><strong>Available Keys:</strong> {', '.join(list(scan_results.keys()))}</p>
                    <p><a href="/results_direct?scan_id={scan_results['scan_id']}">View Results</a></p>
                </body>
            </html>
            """
        else:
            # Return error output
            return f"""
            <html>
                <head><title>Test Scan Failed</title></head>
                <body>
                    <h1>Test Scan Failed</h1>
                    <p>The scan did not return valid results.</p>
                    <p><pre>{json.dumps(scan_results, indent=2, default=str) if scan_results else 'None'}</pre></p>
                </body>
            </html>
            """
    except Exception as e:
        return f"""
        <html>
            <head><title>Test Scan Error</title></head>
            <body>
                <h1>Test Scan Error</h1>
                <p>An error occurred during the test scan: {str(e)}</p>
                <p><pre>{traceback.format_exc()}</pre></p>
            </body>
        </html>
        """

@app.route('/debug_scan_test')
def debug_scan_test():
    """Run a simplified scan and redirect to results"""
    try:
        # Create test lead data
        test_data = {
            'name': 'Debug User',
            'email': 'debug@example.com',
            'company': 'Debug Company',
            'phone': '555-1234',
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'client_os': 'Debug OS',
            'client_browser': 'Debug Browser',
            'windows_version': '',
            'target': 'example.com'
        }
        
        # Run simplified scan
        scan_results = debug_scan(test_data)
        
        if scan_results and 'scan_id' in scan_results:
            # Redirect to direct results page
            return redirect(f"/results_direct?scan_id={scan_results['scan_id']}")
        else:
            return "Scan failed: No valid results returned", 500
    except Exception as e:
        return f"Scan failed with error: {str(e)}", 500
            
def debug_scan(lead_data):
    """Debug version of the scan function with more verbose logging"""
    scan_id = str(uuid.uuid4())
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    logging.info(f"[DEBUG SCAN] Starting scan with ID: {scan_id}")
    logging.info(f"[DEBUG SCAN] Lead data: {lead_data}")
    
    # Create basic scan results structure
    scan_results = {
        'scan_id': scan_id,
        'timestamp': timestamp,
        'target': lead_data.get('target', ''),
        'email': lead_data.get('email', ''),
        'client_info': {
            'os': lead_data.get('client_os', 'Unknown'),
            'browser': lead_data.get('client_browser', 'Unknown'),
            'windows_version': lead_data.get('windows_version', '')
        },
        # Add some minimal results for testing
        'recommendations': [
            'Keep all software updated with the latest security patches',
            'Use strong, unique passwords for all accounts',
            'Enable multi-factor authentication where available'
        ],
        'risk_assessment': {
            'overall_score': 75,
            'risk_level': 'Medium'
        }
    }
    
    logging.info(f"[DEBUG SCAN] Created basic scan results structure")
    
    # Skip actual scanning functionality for testing
    
    # Save the results directly
    try:
        logging.info(f"[DEBUG SCAN] Attempting to save scan results to database")
        saved_id = save_scan_results(scan_results)
        
        if saved_id:
            logging.info(f"[DEBUG SCAN] Successfully saved to database with ID: {saved_id}")
        else:
            logging.error(f"[DEBUG SCAN] Database save function returned None or False")
    except Exception as e:
        logging.error(f"[DEBUG SCAN] Database save error: {str(e)}")
        logging.debug(f"[DEBUG SCAN] Exception traceback: {traceback.format_exc()}")
    
    logging.info(f"[DEBUG SCAN] Completed, returning results with scan_id: {scan_id}")
    return scan_results
               
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
        "Debug Mode": app.config['DEBUG'],
        "Database Path": DB_PATH,
        "Database Connection": "Unknown"
    }
    
    try:
        # Test database connection
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT sqlite_version()")
        version = cursor.fetchone()
        conn.close()
        debug_info["Database Connection"] = f"Success, SQLite version: {version[0]}"
    except Exception as e:
        debug_info["Database Connection"] = f"Failed: {str(e)}"
    
    return jsonify(debug_info)


# ---------------------------- MAIN ENTRY POINT ----------------------------

if __name__ == '__main__':
    # Get port from environment variable or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Use 0.0.0.0 to make the app accessible from any IP
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_ENV') == 'development')
