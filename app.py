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
CORS(app)
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
            # Save lead data to database
            if not save_lead_data(lead_data):
                logging.warning("Failed to save lead data")
            
            # Run the consolidated scan
            logging.info("Starting scan execution...")
            scan_results = run_consolidated_scan(lead_data)
            
            # Check if scan_results contains valid data
            if not scan_results or 'scan_id' not in scan_results:
                logging.error("Scan did not return valid results")
                return render_template('scan.html', error="Scan failed to return valid results. Please try again.")
            
            # Store scan ID in session
            session['scan_id'] = scan_results['scan_id']
            logging.debug(f"Stored scan_id in session: {session['scan_id']}")
            
            # Redirect to results page
            return redirect(url_for('results'))
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
    scan_id = session.get('scan_id')
    logging.info(f"Results page accessed with scan_id from session: {scan_id}")
    
    if not scan_id:
        logging.warning("No scan_id in session, redirecting to scan page")
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
