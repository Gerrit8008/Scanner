# app.py - Main Flask application
import logging
import os
import sqlite3
import platform
import socket
import re
import uuid
from werkzeug.utils import secure_filename
import urllib.parse
from datetime import datetime
import json
import sys
import traceback
import requests
from datetime import timedelta
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from email_handler import send_email_report
from config import get_config
from dotenv import load_dotenv
from flask import Blueprint
from api import api_bp  # Import the new API blueprint
from client_db import init_client_db, CLIENT_DB_PATH
from scanner_router import scanner_bp
from auth import auth_bp
from admin import admin_bp
from api import api_bp
from scanner_router import scanner_bp
from setup_admin import configure_admin
from client import client_bp  
from flask_login import LoginManager, current_user
from auth_routes import auth_bp
from debug_middleware import register_debug_middleware
from auth_helper import create_user

# Import scan functionality
from scan import (
    extract_domain_from_email,
    server_lookup,
    get_client_and_gateway_ip,
    categorize_risks_by_services,
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
    generate_html_report,
    determine_industry,
    get_industry_benchmarks,
    calculate_industry_percentile
)

# Define upload folder for file uploads
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Make sure the directory exists
os.makedirs(os.path.dirname(CLIENT_DB_PATH), exist_ok=True)

# Check if this is first run (database doesn't exist)
if not os.path.exists(CLIENT_DB_PATH):
    from setup import setup_database
    setup_database()
    
# Import database functionality
from db import init_db, save_scan_results, get_scan_results, save_lead_data, DB_PATH

# Register blueprints after initializing the app
def create_app():
    """Create and configure the Flask application"""
    
    # Specify multiple template folders
    app = Flask(__name__, template_folder='templates')
    
    config = get_config()
    config.init_app(app)
    
    # Use a strong secret key 
    app.secret_key = os.environ.get('SECRET_KEY', 'your_strong_secret_key_here')
    app.config['SESSION_TYPE'] = 'filesystem'  # Store sessions in files
    app.config['SESSION_PERMANENT'] = True  # Make sessions permanent
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Sessions last 1 hour
    
    # Configure CORS
    CORS(app, supports_credentials=True)
    
    # Initialize limiter
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=[f"{app.config.get('RATE_LIMIT_PER_DAY', 200)} per day", 
                       f"{app.config.get('RATE_LIMIT_PER_HOUR', 50)} per hour"],
        storage_uri="memory://"
    )
    logging.warning("Using in-memory storage for rate limiting. Not recommended for production.")
    
    # Initialize database
    init_db()
    init_client_db()  # Initialize client database
    create_user("admin", "admin@example.com", "admin123", "admin")
    
    return app, limiter

# Initialize app
app, limiter = create_app()
# Apply admin configuration
app = configure_admin(app)
register_debug_middleware(app)
# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(api_bp)
app.register_blueprint(scanner_bp)
app.register_blueprint(client_bp) 

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

def ensure_users_table():
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Create users table if not exists
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT DEFAULT 'client',
            full_name TEXT,
            created_at TEXT,
            last_login TEXT,
            active INTEGER DEFAULT 1
        )
        ''')
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error ensuring users table: {e}")
        return False
        
@app.before_request
def debug_auth_flow():
    """Debug middleware specifically for authentication flow"""
    if request.path.startswith('/auth/login'):
        app.logger.debug(f"Auth request: {request.method} {request.path}")
        app.logger.debug(f"Session data: {session}")
        app.logger.debug(f"Form data: {request.form}")
        app.logger.debug(f"Args: {request.args}")

@app.after_request
def debug_auth_response(response):
    """Debug middleware for authentication responses"""
    if request.path.startswith('/auth/login'):
        app.logger.debug(f"Auth response: {response.status_code}")
        if response.status_code in (301, 302, 303, 307, 308):
            app.logger.debug(f"Redirect location: {response.location}")
    return response
    
@app.route('/auth_status')
def auth_status():
    """Route to check authentication system status"""
    return {
        "status": "ok",
        "blueprints_registered": list(app.blueprints.keys()),
        "auth_blueprint": {
            "registered": "auth" in app.blueprints,
            "url_prefix": getattr(app.blueprints.get("auth"), "url_prefix", None)
        }
    }

# Add this debug route to list all registered routes
@app.route('/routes')
def list_routes():
    """List all registered routes for debugging"""
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            'endpoint': rule.endpoint,
            'methods': list(rule.methods),
            'rule': str(rule)
        })
    return jsonify(routes)

@login_manager.user_loader
def load_user(user_id):
    # This function should return a user object or None
    # Based on your code structure, you might need to:
    conn = sqlite3.connect(CLIENT_DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user if user else None

# Load environment variables
load_dotenv()
    
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

# Set up logging and log system info
logger = setup_logging()
log_system_info()

@app.route('/db_fix')
def direct_db_fix():
    results = []
    try:
        # Define database path - make sure this matches your actual database path
        CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')
        results.append(f"Working with database at: {CLIENT_DB_PATH}")
        results.append(f"Database exists: {os.path.exists(CLIENT_DB_PATH)}")
        
        # Connect to the database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Check database structure
        results.append("Checking database tables...")
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        results.append(f"Found tables: {[table[0] for table in tables]}")
        
        # Create a new admin user with simple password
        results.append("Creating/updating admin user...")
        
        # Generate password hash
        salt = secrets.token_hex(16)
        password = 'password123'
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt.encode(), 
            100000
        ).hex()
        
        # Check if admin user exists
        cursor.execute("SELECT id FROM users WHERE username = 'superadmin'")
        admin_user = cursor.fetchone()
        
        if admin_user:
            # Update existing admin
            cursor.execute('''
            UPDATE users SET 
                password_hash = ?, 
                salt = ?,
                role = 'admin',
                active = 1
            WHERE username = 'superadmin'
            ''', (password_hash, salt))
            results.append("Updated existing superadmin user")
        else:
            # Create a new admin user
            cursor.execute('''
            INSERT INTO users (
                username, 
                email, 
                password_hash, 
                salt, 
                role, 
                full_name, 
                created_at, 
                active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            ''', ('superadmin', 'superadmin@example.com', password_hash, salt, 'admin', 'Super Administrator', datetime.now().isoformat()))
            results.append("Created new superadmin user")
        
        # Commit changes
        conn.commit()
        
        # Verify creation
        cursor.execute("SELECT id, username, email, role FROM users WHERE username = 'superadmin'")
        user = cursor.fetchone()
        if user:
            results.append(f"Superadmin user verified: ID={user[0]}, username={user[1]}, email={user[2]}, role={user[3]}")
        
        # Close connection
        conn.close()
        
        results.append("Database fix completed!")
        results.append("You can now login with:")
        results.append("Username: superadmin")
        results.append("Password: password123")
        
        return "<br>".join(results)
    except Exception as e:
        results.append(f"Error: {str(e)}")
        return "<br>".join(results)
        
@app.errorhandler(404)
def handle_404(error):
    # Pass current_user explicitly in the context
    return render_template('error.html', message="Page not found", current_user=current_user), 404
        
@app.route('/login')
def login_redirect():
    """Redirect to auth login page"""
    return redirect(url_for('auth.login'))
    
# Add a route for the customization form
@app.route('/customize', methods=['GET', 'POST'])
def customize_scanner():
    """Render the scanner customization form"""
    # Check if this is a POST request
    if request.method == 'POST':
        try:
            # Check if payment was processed (from form hidden field)
            payment_processed = request.form.get('payment_processed', '0')
            
            # Extract form data
            client_data = {
                'business_name': request.form.get('business_name', ''),
                'business_domain': request.form.get('business_domain', ''),
                'contact_email': request.form.get('contact_email', ''),
                'contact_phone': request.form.get('contact_phone', ''),
                'scanner_name': request.form.get('scanner_name', ''),
                'primary_color': request.form.get('primary_color', '#FF6900'),
                'secondary_color': request.form.get('secondary_color', '#808588'),
                'email_subject': request.form.get('email_subject', 'Your Security Scan Report'),
                'email_intro': request.form.get('email_intro', ''),
                'subscription': request.form.get('subscription', 'basic'),
                'default_scans': request.form.getlist('default_scans[]')
            }
            
            logging.info(f"Received form data: {client_data}")
            
            # Use admin user ID 1 for scanner creation
            user_id = 1  
            
            # Handle file uploads
            if 'logo' in request.files and request.files['logo'].filename:
                logo_file = request.files['logo']
                logo_filename = secure_filename(f"{uuid.uuid4()}_{logo_file.filename}")
                logo_path = os.path.join(UPLOAD_FOLDER, logo_filename)
                logo_file.save(logo_path)
                client_data['logo_path'] = logo_path
                logging.info(f"Logo saved at {logo_path}")
            
            if 'favicon' in request.files and request.files['favicon'].filename:
                favicon_file = request.files['favicon']
                favicon_filename = secure_filename(f"{uuid.uuid4()}_{favicon_file.filename}")
                favicon_path = os.path.join(UPLOAD_FOLDER, favicon_filename)
                favicon_file.save(favicon_path)
                client_data['favicon_path'] = favicon_path
                logging.info(f"Favicon saved at {favicon_path}")
            
            # Create client in database
            from client_db import create_client
            
            logging.info("Creating client in database...")
            result = create_client(client_data, user_id)
            
            if not result or result.get('status') != 'success':
                error_msg = result.get('message', 'Unknown error') if result else 'Failed to create client'
                logging.error(f"Error creating client: {error_msg}")
                flash(f"Error creating scanner: {error_msg}", 'danger')
                return render_template('admin/customization-form.html')
            
            # Generate scanner templates
            from scanner_template import generate_scanner
            
            logging.info(f"Generating scanner templates for client ID: {result['client_id']}")
            scanner_result = generate_scanner(result['client_id'], client_data)
            
            if not scanner_result:
                logging.warning("Scanner created but templates could not be generated")
                flash("Scanner created but templates could not be generated", 'warning')
            else:
                logging.info("Scanner templates generated successfully")
                flash("Scanner created successfully!", 'success')
            
            # Process payment or handle payment status (only if needed)
            if payment_processed == '1':
                logging.info("Payment processed successfully")
                
                # If you need to do any additional payment processing, do it here
                # For example, you might want to update the subscription status in the database
                
                try:
                    # Update any subscription details if needed
                    pass
                except Exception as payment_error:
                    logging.error(f"Payment processing error: {str(payment_error)}")
                    # Continue anyway since the scanner was created successfully
            
            # Always redirect to dashboard after successful client creation
            logging.info("Redirecting to admin dashboard")
            return redirect(url_for('admin_dashboard'))  # Make sure this matches your dashboard endpoint name
            
        except Exception as e:
            # Log the full error with traceback
            logging.error(f"Error processing form: {str(e)}")
            import traceback
            logging.error(traceback.format_exc())
            
            # Return error page
            flash(f"Error creating scanner: {str(e)}", 'danger')
            return render_template('admin/customization-form.html')
    
    # For GET requests, render the template
    logging.info("Rendering customization form")
    return render_template('admin/customization-form.html')
    
    # For GET requests, render the template
    return render_template('admin/customization-form.html')

# Add a route for the admin dashboard
@app.route('/admin/dashboard', methods=['GET'])
def admin_dashboard():
    """Render the admin dashboard"""
    return render_template('admin/admin-dashboard.html')

# Log registered routes
@app.before_first_request
def log_registered_routes():
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append(f"{rule.endpoint}: {', '.join(rule.methods)} - {rule.rule}")
    logging.info("Registered routes: %s", routes)

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

def scan_gateway_ports(gateway_info):
    """Enhanced gateway port scanning with better error handling"""
    results = []
    
    try:
        # Parse gateway info safely
        client_ip = "Unknown"
        if isinstance(gateway_info, str) and "Client IP:" in gateway_info:
            client_ip = gateway_info.split("Client IP:")[1].split("|")[0].strip()
        
        # Add client IP information to the report
        results.append((f"Client detected at IP: {client_ip}", "Info"))
        
        # Add gateway detection information
        gateway_ips = []
        if isinstance(gateway_info, str) and "Likely gateways:" in gateway_info:
            gateways = gateway_info.split("Likely gateways:")[1].strip()
            if "|" in gateways:
                gateways = gateways.split("|")[0].strip()
            gateway_ips = [g.strip() for g in gateways.split(",")]
            results.append((f"Potential gateway IPs: {', '.join(gateway_ips)}", "Info"))
        
        # Scan common ports on gateway IPs
        if gateway_ips:
            for ip in gateway_ips:
                if not ip or not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                    continue  # Skip invalid IPs
                
                for port, (service, severity) in GATEWAY_PORT_WARNINGS.items():
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.settimeout(1.0)  # Quick timeout
                            result = s.connect_ex((ip, port))
                            if result == 0:
                                results.append((f"Port {port} ({service}) is open on {ip}", severity))
                    except socket.error:
                        pass  # Ignore socket errors for individual port checks
        else:
            results.append(("Could not identify gateway IPs to scan", "Medium"))
        
        # Add network type information if available
        if isinstance(gateway_info, str) and "Network Type:" in gateway_info:
            network_type = gateway_info.split("Network Type:")[1].split("|")[0].strip()
            results.append((f"Network type detected: {network_type}", "Info"))
            
            # Add specific warnings based on network type
            if "public" in network_type.lower():
                results.append(("Device is connected to a public network which poses higher security risks", "High"))
            elif "guest" in network_type.lower():
                results.append(("Device is connected to a guest network which may have limited security", "Medium"))
    except Exception as e:
        results.append((f"Error analyzing gateway: {str(e)}", "High"))
    
    # Make sure we return at least some results
    if not results:
        results.append(("Gateway information unavailable", "Medium"))
    
    return results

def determine_industry(company_name, email_domain):
    """
    Determine the industry type based on company name and email domain
    
    Args:
        company_name (str): Name of the company
        email_domain (str): Domain from email address
        
    Returns:
        str: Industry type (healthcare, financial, retail, etc.)
    """
    # Convert inputs to lowercase for case-insensitive matching
    company_name = company_name.lower() if company_name else ""
    email_domain = email_domain.lower() if email_domain else ""
    
    # Healthcare indicators
    healthcare_keywords = ['hospital', 'health', 'medical', 'clinic', 'care', 'pharma', 
                          'doctor', 'dental', 'medicine', 'healthcare']
    healthcare_domains = ['hospital.org', 'health.org', 'med.org']
    
    # Financial indicators
    financial_keywords = ['bank', 'finance', 'investment', 'capital', 'financial', 
                         'insurance', 'credit', 'wealth', 'asset', 'accounting']
    financial_domains = ['bank.com', 'invest.com', 'financial.com']
    
    # Retail indicators
    retail_keywords = ['retail', 'shop', 'store', 'market', 'commerce', 'mall', 
                      'sales', 'buy', 'shopping', 'consumer']
    retail_domains = ['shop.com', 'retail.com', 'store.com', 'market.com']
    
    # Education indicators
    education_keywords = ['school', 'university', 'college', 'academy', 'education', 
                         'institute', 'learning', 'teach', 'student', 'faculty']
    education_domains = ['edu', 'education.org', 'university.edu', 'school.org']
    
    # Manufacturing indicators
    manufacturing_keywords = ['manufacturing', 'factory', 'production', 'industrial', 
                             'build', 'maker', 'assembly', 'fabrication']
    manufacturing_domains = ['mfg.com', 'industrial.com', 'production.com']
    
    # Government indicators
    government_keywords = ['government', 'gov', 'federal', 'state', 'municipal', 
                          'county', 'agency', 'authority', 'administration']
    government_domains = ['gov', 'state.gov', 'county.gov', 'city.gov']
    
    # Check company name for industry keywords
    for keyword in healthcare_keywords:
        if keyword in company_name:
            return 'healthcare'
    
    for keyword in financial_keywords:
        if keyword in company_name:
            return 'financial'
    
    for keyword in retail_keywords:
        if keyword in company_name:
            return 'retail'
    
    for keyword in education_keywords:
        if keyword in company_name:
            return 'education'
    
    for keyword in manufacturing_keywords:
        if keyword in company_name:
            return 'manufacturing'
    
    for keyword in government_keywords:
        if keyword in company_name:
            return 'government'
    
    # Check email domain for industry indicators
    if email_domain:
        if '.edu' in email_domain:
            return 'education'
        
        if '.gov' in email_domain:
            return 'government'
        
        for domain in healthcare_domains:
            if domain in email_domain:
                return 'healthcare'
        
        for domain in financial_domains:
            if domain in email_domain:
                return 'financial'
        
        for domain in retail_domains:
            if domain in email_domain:
                return 'retail'
        
        for domain in education_domains:
            if domain in email_domain:
                return 'education'
        
        for domain in manufacturing_domains:
            if domain in email_domain:
                return 'manufacturing'
    
    # Default industry if no match found
    return 'default'

def get_industry_benchmarks():
    """
    Return benchmark data for different industries
    
    Returns:
        dict: Industry benchmark data
    """
    return {
        'healthcare': {
            'name': 'Healthcare',
            'compliance': ['HIPAA', 'HITECH', 'FDA'],
            'critical_controls': [
                'PHI Data Encryption',
                'Network Segmentation',
                'Access Control',
                'Regular Risk Assessments',
                'Incident Response Plan'
            ],
            'avg_score': 72,
            'percentile_distribution': {
                10: 45,
                25: 58,
                50: 72,
                75: 84,
                90: 92
            }
        },
        'financial': {
            'name': 'Financial Services',
            'compliance': ['PCI DSS', 'SOX', 'GLBA'],
            'critical_controls': [
                'Multi-factor Authentication',
                'Encryption of Financial Data',
                'Fraud Detection',
                'Continuous Monitoring',
                'Disaster Recovery'
            ],
            'avg_score': 78,
            'percentile_distribution': {
                10: 52,
                25: 65,
                50: 78,
                75: 88,
                90: 95
            }
        },
        'retail': {
            'name': 'Retail',
            'compliance': ['PCI DSS', 'CCPA', 'GDPR'],
            'critical_controls': [
                'Point-of-Sale Security',
                'Payment Data Protection',
                'Inventory System Security',
                'Ecommerce Platform Security',
                'Customer Data Protection'
            ],
            'avg_score': 65,
            'percentile_distribution': {
                10: 38,
                25: 52,
                50: 65,
                75: 79,
                90: 88
            }
        },
        'education': {
            'name': 'Education',
            'compliance': ['FERPA', 'COPPA', 'State Privacy Laws'],
            'critical_controls': [
                'Student Data Protection',
                'Campus Network Security',
                'Remote Learning Security',
                'Research Data Protection',
                'Identity Management'
            ],
            'avg_score': 60,
            'percentile_distribution': {
                10: 32,
                25: 45,
                50: 60,
                75: 76,
                90: 85
            }
        },
        'manufacturing': {
            'name': 'Manufacturing',
            'compliance': ['ISO 27001', 'NIST', 'Industry-Specific Regulations'],
            'critical_controls': [
                'OT/IT Security',
                'Supply Chain Risk Management',
                'Intellectual Property Protection',
                'Industrial Control System Security',
                'Physical Security'
            ],
            'avg_score': 68,
            'percentile_distribution': {
                10: 40,
                25: 54,
                50: 68,
                75: 80,
                90: 89
            }
        },
        'government': {
            'name': 'Government',
            'compliance': ['FISMA', 'NIST 800-53', 'FedRAMP'],
            'critical_controls': [
                'Data Classification',
                'Continuous Monitoring',
                'Authentication Controls',
                'Incident Response',
                'Security Clearance Management'
            ],
            'avg_score': 70,
            'percentile_distribution': {
                10: 42,
                25: 56,
                50: 70,
                75: 82,
                90: 90
            }
        },
        'default': {
            'name': 'General Business',
            'compliance': ['General Data Protection', 'Industry Best Practices'],
            'critical_controls': [
                'Data Protection',
                'Secure Authentication',
                'Network Security',
                'Endpoint Protection',
                'Security Awareness Training'
            ],
            'avg_score': 65,
            'percentile_distribution': {
                10: 35,
                25: 50,
                50: 65,
                75: 80,
                90: 90
            }
        }
    }

def calculate_industry_percentile(score, industry_type='default'):
    """
    Calculate percentile and comparison information for a security score within an industry
    
    Args:
        score (int): Security score (0-100)
        industry_type (str): Industry type to compare against
        
    Returns:
        dict: Percentile information
    """
    # Get benchmarks
    benchmarks = get_industry_benchmarks()
    industry = benchmarks.get(industry_type, benchmarks['default'])
    
    # Get average score for the industry
    avg_score = industry['avg_score']
    
    # Calculate difference from industry average
    difference = score - avg_score
    
    # Determine if score is above or below average
    comparison = "above" if difference > 0 else "below"
    
    # Calculate percentile
    percentile_dist = industry['percentile_distribution']
    percentile = 0
    
    # Find which percentile the score falls into
    if score >= percentile_dist[90]:
        percentile = 90
    elif score >= percentile_dist[75]:
        percentile = 75
    elif score >= percentile_dist[50]:
        percentile = 50
    elif score >= percentile_dist[25]:
        percentile = 25
    elif score >= percentile_dist[10]:
        percentile = 10
    
    # For scores between the defined percentiles, calculate an approximate percentile
    # This is a simplified linear interpolation
    if percentile < 90:
        next_percentile = None
        if percentile == 0 and score < percentile_dist[10]:
            next_percentile = 10
            prev_score = 0
            next_score = percentile_dist[10]
        elif percentile == 10:
            next_percentile = 25
            prev_score = percentile_dist[10]
            next_score = percentile_dist[25]
        elif percentile == 25:
            next_percentile = 50
            prev_score = percentile_dist[25]
            next_score = percentile_dist[50]
        elif percentile == 50:
            next_percentile = 75
            prev_score = percentile_dist[50]
            next_score = percentile_dist[75]
        elif percentile == 75:
            next_percentile = 90
            prev_score = percentile_dist[75]
            next_score = percentile_dist[90]
        
        if next_percentile:
            # Linear interpolation
            if next_score - prev_score > 0:  # Avoid division by zero
                percentile = percentile + (next_percentile - percentile) * (score - prev_score) / (next_score - prev_score)
    
    # Return the benchmark data
    return {
        'percentile': round(percentile),
        'comparison': comparison,
        'difference': abs(difference),
        'avg_score': avg_score
    }
    
def send_automatic_report_to_admin(scan_results):
    """Send scan report automatically to admin email"""
    try:
        admin_email = os.environ.get('ADMIN_EMAIL', 'admissions@southgeauga.com')
        logging.info(f"Automatically sending report to admin at {admin_email}")
        
        # Create lead data for admin
        lead_data = {
            'name': scan_results.get('name', 'Unknown User'),
            'email': scan_results.get('email', 'unknown@example.com'),
            'company': scan_results.get('company', 'Unknown Company'),
            'phone': scan_results.get('phone', ''),
            'timestamp': scan_results.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        }
        
        # Use the complete HTML report if available
        if 'complete_html_report' in scan_results and scan_results['complete_html_report']:
            html_report = scan_results['complete_html_report']
        else:
            # Fallback to standard html_report or rendered template
            html_report = scan_results.get('html_report', render_template('results.html', scan=scan_results))
        
        # Send the email to admin
        return send_email_report(lead_data, scan_results, html_report)
    except Exception as e:
        logging.error(f"Error sending automatic email report: {e}")
        return False

# ---------------------------- MAIN SCANNING FUNCTION ----------------------------

def run_consolidated_scan(lead_data):
    """Run a complete security scan and generate one comprehensive report"""
    scan_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    
    logging.info(f"Starting scan with ID: {scan_id} for target: {lead_data.get('target', 'Unknown')}")
    
    # Initialize scan results structure - UPDATED to include industry info
    email = lead_data.get('email', '')
    email_domain = extract_domain_from_email(email) if email else ''
    company_name = lead_data.get('company', '')
    
    # Determine industry
    industry = determine_industry(company_name, email_domain)
    industry_benchmarks = get_industry_benchmarks().get(industry, get_industry_benchmarks()['default'])
    
    scan_results = {
        'scan_id': scan_id,
        'timestamp': timestamp,
        'target': lead_data.get('target', ''),
        'email': email,
        'industry': {
            'type': industry,
            'name': industry_benchmarks['name'],
            'compliance': industry_benchmarks['compliance'],
            'critical_controls': industry_benchmarks['critical_controls'],
            'benchmarks': None  # Will be filled after risk assessment
        },
        'client_info': {
            'name': lead_data.get('name', 'Unknown User'),
            'email': email,
            'company': company_name,
            'phone': lead_data.get('phone', ''),
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
    
    # 4. Web Security Checks - MODIFIED to prioritize domain from email
    try:
        logging.info("Running web security checks...")
    
        # Extract domain from email for scanning
        email = lead_data.get('email', '')
        extracted_domain = None
        if "@" in email:
            extracted_domain = extract_domain_from_email(email)
            logging.debug(f"Extracted domain from email: {extracted_domain}")
    
        # Use extracted domain or fall back to target
        target = extracted_domain or lead_data.get('target', '')
    
        if target and target.strip():
            logging.info(f"Using domain for scanning: {target}")
                
            # Check if ports 80 or 443 are accessible
            http_accessible = False
            https_accessible = False
                
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(3)
                    result = sock.connect_ex((target, 80))
                    http_accessible = (result == 0)
                    logging.debug(f"HTTP (port 80) accessible: {http_accessible}")
            except Exception as http_error:
                logging.error(f"Error checking HTTP accessibility: {http_error}")
                    
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(3)
                    result = sock.connect_ex((target, 443))
                    https_accessible = (result == 0)
                    logging.debug(f"HTTPS (port 443) accessible: {https_accessible}")
            except Exception as https_error:
                logging.error(f"Error checking HTTPS accessibility: {https_error}")
                    
            scan_results['http_accessible'] = http_accessible
            scan_results['https_accessible'] = https_accessible
                
            # Only perform web checks if HTTP or HTTPS is accessible
            if http_accessible or https_accessible:
                target_url = f"https://{target}" if https_accessible else f"http://{target}"
                logging.info(f"Using target URL: {target_url}")
                    
                # SSL/TLS Certificate Analysis (only if HTTPS is accessible)
                if https_accessible:
                    try:
                        logging.debug(f"Checking SSL certificate for {target}")
                        scan_results['ssl_certificate'] = check_ssl_certificate(target)
                        logging.debug(f"SSL certificate check completed")
                    except Exception as e:
                        logging.error(f"SSL check error for {target}: {e}")
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
                logging.warning(f"Neither HTTP nor HTTPS is accessible for {target}, skipping web checks")
                scan_results['web_accessibility_error'] = "Neither HTTP nor HTTPS ports are accessible"
        else:
            logging.info("No target domain/IP provided, skipping web security checks")
    except Exception as e:
        logging.error(f"Error during web security checks: {e}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        scan_results['web_error'] = str(e)
    
    # 5. Calculate risk score and recommendations
    try:
        logging.info("Calculating risk assessment...")
        scan_results['risk_assessment'] = calculate_risk_score(scan_results)
        logging.debug(f"Risk assessment completed")
        
        # Add service categories
        scan_results['service_categories'] = categorize_risks_by_services(scan_results)
        
        scan_results['recommendations'] = get_recommendations(scan_results)
        logging.debug(f"Generated {len(scan_results['recommendations'])} recommendations")
        
        scan_results['threat_scenarios'] = generate_threat_scenario(scan_results)
        logging.debug(f"Generated {len(scan_results['threat_scenarios'])} threat scenarios")
        
        # Add the industry percentile calculation after risk score
        if 'overall_score' in scan_results['risk_assessment']:
            overall_score = scan_results['risk_assessment']['overall_score']
            scan_results['industry']['benchmarks'] = calculate_industry_percentile(
                overall_score, 
                scan_results['industry'].get('type', 'default')
            )
            logging.debug(f"Industry benchmarking completed")
    except Exception as e:
        logging.error(f"Error during risk assessment: {e}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        scan_results['risk_assessment'] = {'error': str(e), 'overall_score': 50, 'risk_level': 'Medium'}
        scan_results['recommendations'] = ["Keep all software and systems updated with the latest security patches.",
                                         "Use strong, unique passwords and implement multi-factor authentication.",
                                         "Regularly back up your data and test the restoration process."]

    # 6. Generate the full HTML report with all context variables
    try:
        logging.info("Generating complete HTML report...")
    
        # Get client IP and gateway info for context variables
        client_ip = "Unknown"
        gateway_guesses = []
        network_type = "Unknown"
    
        if 'network' in scan_results and 'gateway' in scan_results['network']:
            gateway_info = scan_results['network']['gateway'].get('info', '')
            if isinstance(gateway_info, str):
                if "Client IP:" in gateway_info:
                    try:
                        client_ip = gateway_info.split("Client IP:")[1].split("|")[0].strip()
                    except:
                        pass
            
                if "Network Type:" in gateway_info:
                    try:
                        network_type = gateway_info.split("Network Type:")[1].split("|")[0].strip()
                    except:
                        pass
            
                if "Likely gateways:" in gateway_info:
                    try:
                        gateways_part = gateway_info.split("Likely gateways:")[1].strip()
                        if "|" in gateways_part:
                            gateways_part = gateways_part.split("|")[0].strip()
                        gateway_guesses = [g.strip() for g in gateways_part.split(",")]
                    except:
                        pass
        else:
            gateway_info = "Gateway information not available"
    
        # Render the complete HTML with all context variables
        complete_html = render_template('results.html', 
                                       scan=scan_results,
                                       client_ip=client_ip,
                                       gateway_guesses=gateway_guesses,
                                       network_type=network_type,
                                       gateway_info=gateway_info)
    
        # Store the complete HTML in the scan results
        scan_results['complete_html_report'] = complete_html
        logging.debug("Complete HTML report generated and stored successfully")
    except Exception as complete_html_error:
        logging.error(f"Error generating complete HTML report: {complete_html_error}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        scan_results['complete_html_report_error'] = str(complete_html_error)
    
    # 7. Generate HTML report
    try:
        logging.info("Generating HTML report...")
        html_report = generate_html_report(scan_results)
        scan_results['html_report'] = html_report
        logging.debug("HTML report generated successfully")
    except Exception as report_e:
        logging.error(f"Error generating HTML report: {report_e}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        scan_results['html_report_error'] = str(report_e)
    
    # 8. Save to database
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

@app.route('/emergency_login', methods=['GET', 'POST'])
def emergency_login():
    """Emergency login in case of auth issues"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            import sqlite3
            import hashlib
            import secrets
            from datetime import datetime, timedelta
            
            # Connect directly to database
            conn = sqlite3.connect(CLIENT_DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Find user
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            
            if not user:
                conn.close()
                return """
                <h1>Invalid Credentials</h1>
                <p>The username or password is incorrect.</p>
                <a href="/emergency_login">Try Again</a>
                """
                
            # Try password verification
            try:
                # PBKDF2 method (newer)
                password_hash = hashlib.pbkdf2_hmac(
                    'sha256', 
                    password.encode(), 
                    user['salt'].encode(), 
                    100000
                ).hex()
                pw_matches = (password_hash == user['password_hash'])
            except:
                # Simple SHA-256 method (older fallback)
                try:
                    password_hash = hashlib.sha256((password + user['salt']).encode()).hexdigest()
                    pw_matches = (password_hash == user['password_hash'])
                except:
                    pw_matches = False
            
            if not pw_matches:
                conn.close()
                return """
                <h1>Invalid Credentials</h1>
                <p>The username or password is incorrect.</p>
                <a href="/emergency_login">Try Again</a>
                """
            
            # Create session manually
            session_token = secrets.token_hex(32)
            created_at = datetime.now().isoformat()
            expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
            
            # Insert new session
            cursor.execute('''
            INSERT INTO sessions (
                user_id, session_token, created_at, expires_at, ip_address
            ) VALUES (?, ?, ?, ?, ?)
            ''', (user['id'], session_token, created_at, expires_at, request.remote_addr))
            
            conn.commit()
            
            # Store in session
            session.clear()  # Clear any old session data
            session['session_token'] = session_token
            session['username'] = user['username']
            session['role'] = user['role']
            
            # Success message with debugging info
            result = f"""
            <html>
                <head>
                    <title>Emergency Login Successful</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; padding: 20px; max-width: 800px; margin: 0 auto; }}
                        h1 {{ color: green; }}
                        .section {{ margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                        pre {{ background: #f5f5f5; padding: 10px; overflow-x: auto; }}
                    </style>
                </head>
                <body>
                    <h1>Emergency Login Successful!</h1>
                    <div class="section">
                        <p>You are logged in as <strong>{user['username']}</strong> with role <strong>{user['role']}</strong>.</p>
                        <p>Session token created: <code>{session_token}</code></p>
                    </div>
                    
                    <div class="section">
                        <h2>Debugging Information</h2>
                        <p>Session contains:</p>
                        <pre>{str(dict(session))}</pre>
                    </div>
                    
                    <div class="section">
                        <h2>Try Navigation</h2>
                        <p><a href="/admin/dashboard">Go to Admin Dashboard</a></p>
                        <p><a href="/client/dashboard">Go to Client Dashboard</a></p>
                        <p><a href="/">Go to Home</a></p>
                    </div>
                </body>
            </html>
            """
            
            conn.close()
            return result
        except Exception as e:
            import traceback
            return f"""
            <h1>Emergency Login Error</h1>
            <p>An error occurred: {str(e)}</p>
            <pre>{traceback.format_exc()}</pre>
            <form method="post">
                <label>Username: <input type="text" name="username" value="{username}"></label><br>
                <label>Password: <input type="password" name="password"></label><br>
                <button type="submit">Login</button>
            </form>
            """
    
    # Show login form for GET requests
    return '''
    <html>
        <head>
            <title>Emergency Login</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    margin: 20px; 
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                }
                form { 
                    margin-top: 20px; 
                    width: 300px;
                    border: 1px solid #ddd;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                h1 { color: #333; }
                input { 
                    margin: 5px 0; 
                    padding: 8px; 
                    width: 100%; 
                    box-sizing: border-box;
                }
                button { 
                    padding: 10px 16px; 
                    background: #4CAF50; 
                    color: white; 
                    border: none; 
                    border-radius: 4px;
                    cursor: pointer;
                    width: 100%;
                    margin-top: 15px;
                }
                button:hover {
                    background: #45a049;
                }
                .notice {
                    margin-top: 20px;
                    padding: 10px;
                    background: #fff8e1;
                    border: 1px solid #ffe0b2;
                    border-radius: 4px;
                    width: 300px;
                }
            </style>
        </head>
        <body>
            <h1>Emergency Login</h1>
            <form method="post">
                <div>
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username">
                </div>
                <div>
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password">
                </div>
                <button type="submit">Login</button>
            </form>
            <div class="notice">
                <p>This is for emergency access in case of authentication issues.</p>
                <p>Try using <strong>admin</strong> and <strong>admin123</strong> if you're unsure.</p>
            </div>
        </body>
    </html>
    '''

@app.route('/admin_simplified')
def admin_simplified():
    """Simplified admin view for emergency access"""
    session_token = session.get('session_token')
    username = session.get('username', 'Unknown')
    role = session.get('role', 'Unknown')
    
    # Very simple session check
    if not session_token or role != 'admin':
        return """
        <h1>Access Denied</h1>
        <p>You need to be logged in as an admin.</p>
        <a href="/emergency_login">Login</a>
        """
    
    try:
        # Get summary info
        import sqlite3
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get client count
        cursor.execute("SELECT COUNT(*) FROM clients")
        client_count = cursor.fetchone()[0]
        
        # Get user count
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        
        # Get recent clients
        cursor.execute("SELECT id, business_name, contact_email FROM clients ORDER BY id DESC LIMIT 5")
        recent_clients = [dict(row) for row in cursor.fetchall()]
        
        # Get recent users
        cursor.execute("SELECT id, username, email, role FROM users ORDER BY id DESC LIMIT 5")
        recent_users = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        # Create a simple dashboard HTML
        return f"""
        <html>
            <head>
                <title>Simplified Admin Dashboard</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .card {{ border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 20px; }}
                    .section {{ margin-bottom: 30px; }}
                    table {{ width: 100%; border-collapse: collapse; }}
                    th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}
                    th {{ background-color: #f2f2f2; }}
                </style>
            </head>
            <body>
                <h1>Simplified Admin Dashboard</h1>
                <p>Logged in as: {username} (Role: {role})</p>
                
                <div class="section">
                    <h2>Summary</h2>
                    <div style="display: flex; gap: 20px;">
                        <div class="card">
                            <h3>Clients</h3>
                            <p style="font-size: 24px;">{client_count}</p>
                        </div>
                        <div class="card">
                            <h3>Users</h3>
                            <p style="font-size: 24px;">{user_count}</p>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>Recent Clients</h2>
                    <table>
                        <tr>
                            <th>ID</th>
                            <th>Business Name</th>
                            <th>Email</th>
                        </tr>
                        {''.join([f'<tr><td>{c["id"]}</td><td>{c["business_name"]}</td><td>{c["contact_email"]}</td></tr>' for c in recent_clients])}
                    </table>
                </div>
                
                <div class="section">
                    <h2>Recent Users</h2>
                    <table>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Role</th>
                        </tr>
                        {''.join([f'<tr><td>{u["id"]}</td><td>{u["username"]}</td><td>{u["email"]}</td><td>{u["role"]}</td></tr>' for u in recent_users])}
                    </table>
                </div>
                
                <div>
                    <a href="/emergency_login">Back to Emergency Login</a>
                </div>
            </body>
        </html>
        """
    except Exception as e:
        return f"""
        <h1>Error</h1>
        <p>An error occurred: {str(e)}</p>
        <a href="/emergency_login">Back to Emergency Login</a>
        """
        
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
                'target': ''  # Leave blank to ensure we use email domain
            }
            
            # Extract domain from email and use it as target
            if lead_data["email"]:
                domain = extract_domain_from_email(lead_data["email"])
                lead_data["target"] = domain
                logging.info(f"Using domain extracted from email: {domain}")
            
            # Basic validation
            if not lead_data["email"]:
                return render_template('scan.html', error="Please enter your email address to receive the scan report.")
            
            # Save lead data to database
            logging.info("Saving lead data...")
            lead_id = save_lead_data(lead_data)
            logging.info(f"Lead data saved with ID: {lead_id}")
            
            # Check for client_id in query parameters (used for client-specific scanner)
            client_id = request.args.get('client_id')
            
            # If client_id is provided, get client customizations
            client = None
            if client_id:
                from client_db import get_client_by_id
                client = get_client_by_id(client_id)
            
            # Run the full consolidated scan
            logging.info(f"Starting scan for {lead_data.get('email')} targeting {lead_data.get('target')}...")
            scan_results = run_consolidated_scan(lead_data)
            
            # If scan was performed through a client scanner, log it
            if client:
                from client_db import log_scan
                log_scan(client['id'], scan_results['scan_id'], lead_data.get('target', ''))
            
            # Check if scan_results contains valid data
            if not scan_results or 'scan_id' not in scan_results:
                logging.error("Scan did not return valid results")
                return render_template('scan.html', error="Scan failed to return valid results. Please try again.")
            
            # Store scan ID in session for future reference
            try:
                session['scan_id'] = scan_results['scan_id']
                logging.info(f"Stored scan_id in session: {scan_results['scan_id']}")
            except Exception as session_error:
                logging.warning(f"Failed to store scan_id in session: {str(session_error)}")
            
            # Automatically send report to the user
            try:
                logging.info(f"Automatically sending report to user at {lead_data['email']}")
                
                # Get complete HTML report
                html_report = scan_results.get('complete_html_report', '')
                if not html_report:
                    # Fallback to standard html_report or re-render template
                    html_report = scan_results.get('html_report', render_template('results.html', scan=scan_results))
                
                # Use client email template if available
                email_subject = "Your Security Scan Report"
                email_intro = "Thank you for using our security scanner."
                
                if client:
                    email_subject = client.get('email_subject', email_subject)
                    email_intro = client.get('email_intro', email_intro)
                
                # Customize email for client
                if client:
                    # Add client branding to email
                    from email_handler import send_branded_email_report
                    email_sent = send_branded_email_report(
                        lead_data, 
                        scan_results, 
                        html_report, 
                        client['business_name'],
                        client.get('logo_path', ''),
                        client.get('primary_color', '#FF6900'),
                        email_subject,
                        email_intro
                    )
                else:
                    # Use standard email
                    email_sent = send_email_report(lead_data, scan_results, html_report)
                
                if email_sent:
                    logging.info("Report automatically sent to user")
                else:
                    logging.warning("Failed to automatically send report to user")
            except Exception as email_error:
                logging.error(f"Error sending automatic email report to user: {email_error}")
            
            # Check if this is an AJAX request
            is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.headers.get('Accept') == 'application/json'
            
            if is_ajax:
                # Return JSON response for AJAX requests
                return jsonify({
                    'status': 'success',
                    'scan_id': scan_results['scan_id'],
                    'message': 'Scan completed successfully'
                })
            else:
                # For regular form submissions, render results directly
                logging.info("Rendering results page directly...")
                
                # Use client's template if available
                if client:
                    template_path = os.path.join(
                        os.path.dirname(os.path.abspath(__file__)), 
                        'scanners', 
                        f"client_{client['id']}", 
                        'results.html'
                    )
                    
                    if os.path.exists(template_path):
                        # Render client-specific template
                        with open(template_path, 'r') as f:
                            template_content = f.read()
                        
                        from jinja2 import Template
                        template = Template(template_content)
                        rendered_html = template.render(scan=scan_results)
                        
                        return rendered_html
                
                # Fall back to standard template
                return render_template('results.html', scan=scan_results)
                
        except Exception as scan_error:
            logging.error(f"Error during scan: {str(scan_error)}")
            logging.debug(f"Exception traceback: {traceback.format_exc()}")
            
            # Check if this is an AJAX request
            is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.headers.get('Accept') == 'application/json'
            
            if is_ajax:
                # Return JSON error for AJAX requests
                return jsonify({
                    'status': 'error',
                    'message': str(scan_error)
                }), 500
            else:
                # For regular form submissions, show error page
                return render_template('scan.html', error=f"An error occurred during the scan: {str(scan_error)}")
    
    # For GET requests, show the scan form
    error = request.args.get('error')
    
    # Check for client_id in query parameters (used for client-specific scanner)
    client_id = request.args.get('client_id')
    client = None
    
    if client_id:
        try:
            from client_db import get_client_by_id
            client = get_client_by_id(client_id)
        except Exception as e:
            logging.error(f"Error retrieving client {client_id}: {e}")
    
    # Use client's template if available
    if client:
        template_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 
            'scanners', 
            f"client_{client['id']}", 
            'scan.html'
        )
        
        if os.path.exists(template_path):
            # Render client-specific template
            with open(template_path, 'r') as f:
                template_content = f.read()
            
            from jinja2 import Template
            template = Template(template_content)
            rendered_html = template.render(error=error)
            
            return rendered_html
    
    # Fall back to standard template
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
        
        # Ensure service_categories exists
        if 'service_categories' not in scan_results:
            try:
                scan_results['service_categories'] = categorize_risks_by_services(scan_results)
                logging.info("Generated service categories successfully")
            except Exception as cat_error:
                logging.error(f"Error generating service categories: {str(cat_error)}")
                # Initialize with empty categories
                scan_results['service_categories'] = {
                    'endpoint_security': {'name': 'Endpoint Security', 'description': 'Protection for your computers and devices', 'findings': [], 'risk_level': 'Low', 'score': 0, 'max_score': 0},
                    'network_defense': {'name': 'Network Defense', 'description': 'Protection for your network infrastructure', 'findings': [], 'risk_level': 'Low', 'score': 0, 'max_score': 0},
                    'data_protection': {'name': 'Data Protection', 'description': 'Solutions to secure your business data', 'findings': [], 'risk_level': 'Low', 'score': 0, 'max_score': 0},
                    'access_management': {'name': 'Access Management', 'description': 'Controls for secure system access', 'findings': [], 'risk_level': 'Low', 'score': 0, 'max_score': 0}
                }
        
        # Get client IP and gateway info for the template
        client_ip = "Unknown"
        gateway_guesses = []
        network_type = "Unknown"
        gateway_info = "Gateway information not available"

        if 'network' in scan_results and 'gateway' in scan_results['network']:
            gateway_info = scan_results['network']['gateway'].get('info', '')
            if isinstance(gateway_info, str):  # Ensure it's a string before processing
                if "Client IP:" in gateway_info:
                    try:
                        client_ip = gateway_info.split("Client IP:")[1].split("|")[0].strip()
                        logging.debug(f"Extracted client IP: {client_ip}")
                    except:
                        logging.warning("Failed to extract client IP from gateway info")
                
                # Try to extract network type
                if "Network Type:" in gateway_info:
                    try:
                        network_type = gateway_info.split("Network Type:")[1].split("|")[0].strip()
                        logging.debug(f"Extracted network type: {network_type}")
                    except:
                        logging.warning("Failed to extract network type from gateway info")
                
                # Try to extract gateway guesses
                if "Likely gateways:" in gateway_info:
                    try:
                        gateways_part = gateway_info.split("Likely gateways:")[1].strip()
                        if "|" in gateways_part:
                            gateways_part = gateways_part.split("|")[0].strip()
                        gateway_guesses = [g.strip() for g in gateways_part.split(",")]
                        logging.debug(f"Extracted gateway guesses: {gateway_guesses}")
                    except:
                        logging.warning("Failed to extract gateway guesses from gateway info")

        # Add additional logging for troubleshooting
        logging.info(f"Rendering results template with scan_id: {scan_id}")
        logging.info(f"Template variables: client_ip={client_ip}, network_type={network_type}, gateway_guesses={len(gateway_guesses)}")
        
        # Now render template with all required data
        return render_template('results.html', 
                               scan=scan_results,
                               client_ip=client_ip,
                               gateway_guesses=gateway_guesses,
                               network_type=network_type,
                               gateway_info=gateway_info)

    except Exception as e:
        logging.error(f"Error loading scan results: {e}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        return render_template('error.html', error=f"Error loading scan results: {str(e)}")
        
@app.route('/api/email_report', methods=['POST'])
def api_email_report():
    try:
        # Get data from request
        scan_id = request.form.get('scan_id')
        email = request.form.get('email')
        
        logging.info(f"Email report requested for scan_id: {scan_id} to email: {email}")
        
        if not scan_id or not email:
            logging.error("Missing required parameters (scan_id or email)")
            return jsonify({"status": "error", "message": "Missing required parameters"})
        
        # Get scan data from database 
        scan_data = get_scan_results(scan_id)
        
        if not scan_data:
            logging.error(f"Scan data not found for ID: {scan_id}")
            return jsonify({"status": "error", "message": "Scan data not found"})
        
        # Create a lead_data dictionary for the email function
        lead_data = {
            "email": email,
            "name": scan_data.get('client_info', {}).get('name', ''),
            "company": scan_data.get('client_info', {}).get('company', ''),
            "phone": scan_data.get('client_info', {}).get('phone', ''),
            "timestamp": scan_data.get('timestamp', '')
        }
        
        # Use the complete HTML that was stored during scan
        if 'complete_html_report' in scan_data and scan_data['complete_html_report']:
            html_report = scan_data['complete_html_report']
            logging.info("Using stored complete HTML report")
        else:
            # Fallback to either stored 'html_report' or re-render
            html_report = scan_data.get('html_report', '')
            
            # If neither complete nor basic HTML report is available, try to re-render
            if not html_report:
                try:
                    logging.warning("Complete HTML report not found, attempting to re-render")
                    html_report = render_template('results.html', scan=scan_data)
                except Exception as render_error:
                    logging.error(f"Error rendering HTML report: {render_error}")
        
        # Send email using the updated function
        logging.info(f"Attempting to send email report to {email}")
        email_sent = send_email_report(lead_data, scan_data, html_report)
        
        if email_sent:
            logging.info(f"Email report successfully sent to {email}")
            return jsonify({"status": "success"})
        else:
            logging.error(f"Failed to send email report to {email}")
            return jsonify({"status": "error", "message": "Failed to send email"})
            
    except Exception as e:
        logging.error(f"Error in email report API: {e}")
        logging.debug(traceback.format_exc())
        return jsonify({"status": "error", "message": str(e)})

@app.route('/simple_scan')
def simple_scan():
    """A completely simplified scan that bypasses all complexity"""
    try:
        # Create a simple scan result
        scan_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        # Return results directly without database or sessions
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Simple Scan Results</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .section {{ padding: 15px; margin-bottom: 20px; border: 1px solid #ddd; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1>Simple Scan Results</h1>
            
            <div class="section">
                <h2>Scan Information</h2>
                <p><strong>Scan ID:</strong> {scan_id}</p>
                <p><strong>Timestamp:</strong> {timestamp}</p>
            </div>
            
            <div class="section">
                <h2>Sample Results</h2>
                <p>This is a simple test page that bypasses all complex functionality.</p>
                <ul>
                    <li>Keep all software updated with security patches</li>
                    <li>Use strong, unique passwords</li>
                    <li>Enable multi-factor authentication where possible</li>
                </ul>
            </div>
            
            <a href="/scan">Run a real scan</a>
        </body>
        </html>
        """
    except Exception as e:
        return f"Error: {str(e)}"

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
            "target": ''  # Start with empty target
        }
        
        # Basic validation
        if not lead_data["email"]:
            return jsonify({
                "status": "error",
                "message": "Please provide an email address to receive the scan report."
            }), 400
        
        # Extract domain from email and use as target
        domain = extract_domain_from_email(lead_data["email"])
        lead_data["target"] = domain
        logging.info(f"Using domain extracted from email: {domain}")
            
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
    if request.method == 'POST':
        try:
            email = request.form.get('email', '')
            
            if not email:
                return "Email is required", 400
            
            # Extract domain from email
            domain = extract_domain_from_email(email)
            
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
                'target': domain  # Use extracted domain
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

@app.route('/debug_scan/<scan_id>')
def debug_scan_results(scan_id):
    scan_results = get_scan_results(scan_id)
    return jsonify(scan_results)
    
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
        "Debug Mode": True,
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

@app.route('/debug_submit', methods=['POST'])
def debug_submit():
    """Debug endpoint to test form submission"""
    try:
        test_email = request.form.get('test_email', 'unknown@example.com')
        
        return f"""
        <html>
            <head>
                <title>Debug Form Submission</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                </style>
            </head>
            <body>
                <h1>Form Submission Successful</h1>
                <p>Received test email: {test_email}</p>
                <p>This confirms that basic form submission is working.</p>
                <a href="/scan">Return to scan page</a>
            </body>
        </html>
        """
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/admin')
def admin_dashboard_redirect():
    return redirect(url_for('admin.dashboard'))

@app.route('/admin', endpoint='main_admin_redirect')
def admin_main_redirect():
    """Redirect to admin dashboard"""
    return redirect(url_for('admin.dashboard'))

@app.errorhandler(500)
def handle_500(e):
    app.logger.error(f'500 error: {str(e)}')
    return render_template('error.html', error=str(e)), 500

@app.errorhandler(404)
def handle_404(e):
    app.logger.error(f'404 error: {str(e)}')
    return render_template('error.html', error="Page not found"), 404

@app.route('/api/create-scanner', methods=['POST'])
def create_scanner_api():
    """API endpoint to handle scanner creation form submission"""
    try:
        # Get form data
        client_data = {
            'business_name': request.form.get('business_name', ''),
            'business_domain': request.form.get('business_domain', ''),
            'contact_email': request.form.get('contact_email', ''),
            'contact_phone': request.form.get('contact_phone', ''),
            'scanner_name': request.form.get('scanner_name', ''),
            'subscription': request.form.get('subscription', 'basic'),
            'primary_color': request.form.get('primary_color', '#FF6900'),
            'secondary_color': request.form.get('secondary_color', '#808588'),
            'email_subject': request.form.get('email_subject', 'Your Security Scan Report'),
            'email_intro': request.form.get('email_intro', '')
        }
        
        # Get default scans
        default_scans = request.form.getlist('default_scans[]')
        if default_scans:
            client_data['default_scans'] = default_scans
        
        # Handle file uploads
        if 'logo' in request.files and request.files['logo'].filename:
            # Process logo upload
            pass
            
        if 'favicon' in request.files and request.files['favicon'].filename:
            # Process favicon upload
            pass
            
        # For now, just return success response
        flash('Scanner created successfully', 'success')
        return redirect(url_for('admin.dashboard'))
        
    except Exception as e:
        app.logger.error(f"Error creating scanner: {str(e)}")
        flash(f'Error creating scanner: {str(e)}', 'danger')
        return redirect(url_for('customize_scanner'))

@app.route('/api/service_inquiry', methods=['POST'])
def api_service_inquiry():
    try:
        # Get data from request
        service = request.form.get('service')
        findings = request.form.get('findings')
        scan_id = request.form.get('scan_id')
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone', '')
        message = request.form.get('message', '')
        
        logging.info(f"Service inquiry received: {service} from {name} ({email})")
        
        # Get scan data for reference
        scan_data = get_scan_results(scan_id)
        
        # Create a lead_data dictionary
        lead_data = {
            "name": name,
            "email": email,
            "phone": phone,
            "message": message,
            "service": service,
            "findings": findings,
            "scan_id": scan_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Save the inquiry to the database
        try:
            # Create a new table or use an existing one for service inquiries
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Make sure the table exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS service_inquiries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    name TEXT,
                    email TEXT,
                    phone TEXT,
                    service TEXT,
                    findings TEXT,
                    message TEXT,
                    timestamp TEXT
                )
            ''')
            
            # Insert the inquiry
            cursor.execute('''
                INSERT INTO service_inquiries 
                (scan_id, name, email, phone, service, findings, message, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id, name, email, phone, service, findings, message, lead_data['timestamp']
            ))
            
            conn.commit()
            conn.close()
            logging.info(f"Service inquiry saved to database for {name}")
        except Exception as db_error:
            logging.error(f"Error saving service inquiry to database: {db_error}")
        
        # Send an email notification about the service inquiry
        try:
            # Customize the email_handler.py function to send service inquiries
            # or use the existing one with modified parameters
            email_subject = f"Service Inquiry: {service}"
            
            email_body = f"""
            <h2>New Service Inquiry from Security Scan</h2>
            <p><strong>Service:</strong> {service}</p>
            <p><strong>Issues Found:</strong> {findings}</p>
            <p><strong>Name:</strong> {name}</p>
            <p><strong>Email:</strong> {email}</p>
            <p><strong>Phone:</strong> {phone}</p>
            <p><strong>Message:</strong> {message}</p>
            <p><strong>Scan ID:</strong> {scan_id}</p>
            <p><strong>Timestamp:</strong> {lead_data['timestamp']}</p>
            """
            
            # Use your existing email sending function
            # send_email_notification(admin_email, email_subject, email_body)
            logging.info(f"Service inquiry email notification sent for {service}")
        except Exception as email_error:
            logging.error(f"Error sending service inquiry email: {email_error}")
        
        return jsonify({"status": "success"})
    except Exception as e:
        logging.error(f"Error processing service inquiry: {e}")
        return jsonify({"status": "error", "message": str(e)})

def check_route_conflicts():
    """Check for conflicting routes in registered blueprints"""
    routes = {}
    for rule in app.url_map.iter_rules():
        endpoint = rule.endpoint
        path = str(rule)
        if path in routes:
            logging.warning(f"Route conflict found: {path} is registered by both {routes[path]} and {endpoint}")
        else:
            routes[path] = endpoint
            
    # Print all routes for debugging
    logging.info("All registered routes:")
    for path, endpoint in sorted(routes.items()):
        logging.info(f"  {path} -> {endpoint}")
        
# Call this function after all blueprints are registered
check_route_conflicts()
        
# ---------------------------- MAIN ENTRY POINT ----------------------------

if __name__ == '__main__':
    # Get port from environment variable or use default
    port = int(os.environ.get('PORT', 5000))
    direct_db_fix()
    
    # Use 0.0.0.0 to make the app accessible from any IP
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_ENV') == 'development')
