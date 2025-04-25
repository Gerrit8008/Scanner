from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
import logging
import os
import platform
import socket
import uuid
import json
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'your_temporary_secret_key')

# Set up logging configuration
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Define the base directory and scan history directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCAN_HISTORY_DIR = os.path.join(BASE_DIR, 'scan_history')
if not os.path.exists(SCAN_HISTORY_DIR):
    os.makedirs(SCAN_HISTORY_DIR, exist_ok=True)

# Define a fallback directory that should be writable in most environments
FALLBACK_DIR = '/tmp/scan_history'
if not os.path.exists(FALLBACK_DIR):
    os.makedirs(FALLBACK_DIR, exist_ok=True)

# ---------------------------- UTILITY FUNCTIONS ----------------------------

def save_lead_data(lead_info):
    """Save lead information to a CSV file"""
    try:
        # In a web environment, we'll save to a temporary file that Render allows
        filename = "/tmp/leads.csv"
        file_exists = os.path.isfile(filename)
        
        # Add the new fields to the fieldnames list
        with open(filename, "a", newline="") as csvfile:
            import csv
            fieldnames = ["name", "email", "company", "phone", "timestamp", "client_os", "client_browser", "windows_version"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow(lead_info)
        return True
    except Exception as e:
        logging.error(f"Error saving lead data: {e}")
        return False

def simple_scan(lead_data):
    """
    A simplified version of the scan function.
    
    Args:
        lead_data (dict): User information and scan parameters
    
    Returns:
        dict: Scan results with file location
    """
    scan_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    
    logging.debug(f"Starting simplified scan with ID: {scan_id}")
    
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
    
    try:
        # Add some simulated scan results
        scan_results['system'] = {
            'os_updates': {'message': 'System is up to date', 'severity': 'Low'},
            'firewall': {'status': 'Firewall enabled', 'severity': 'Low'}
        }
        
        scan_results['network'] = {
            'open_ports': {'count': 3, 'list': [80, 443, 22], 'severity': 'Low'}
        }
        
        # Calculate a simple risk score
        scan_results['risk_assessment'] = {
            'overall_score': 85,
            'risk_level': 'Low',
            'risk_factors': []
        }
        
        logging.debug("Basic scan completed, attempting to save results...")
        
        # Try to save scan results in the primary directory
        primary_file = os.path.join(SCAN_HISTORY_DIR, f"scan_{scan_id}.json")
        fallback_file = os.path.join(FALLBACK_DIR, f"scan_{scan_id}.json")
        
        # Try primary location first
        saved_file = None
        try:
            with open(primary_file, 'w') as f:
                json.dump(scan_results, f, indent=2)
            if os.path.exists(primary_file):
                saved_file = primary_file
                logging.debug(f"Scan results saved to primary location: {primary_file}")
        except Exception as e:
            logging.error(f"Failed to save to primary location: {str(e)}")
        
        # If primary failed, try fallback
        if not saved_file:
            try:
                with open(fallback_file, 'w') as f:
                    json.dump(scan_results, f, indent=2)
                if os.path.exists(fallback_file):
                    saved_file = fallback_file
                    logging.debug(f"Scan results saved to fallback location: {fallback_file}")
            except Exception as e:
                logging.error(f"Failed to save to fallback location: {str(e)}")
        
        # Store the file location
        if saved_file:
            scan_results['results_file'] = saved_file
        else:
            logging.critical("CRITICAL: Could not save scan results to any location!")
            scan_results['error'] = "Failed to save scan results to disk"
        
        return scan_results
        
    except Exception as e:
        logging.error(f"Error during scan execution: {str(e)}")
        scan_results['error'] = str(e)
        return scan_results

def send_email_report(lead_data, scan_results):
    """Simplified email function for testing"""
    try:
        # Use environment variables for credentials
        smtp_user = os.environ.get('SMTP_USER')
        smtp_password = os.environ.get('SMTP_PASSWORD')
        
        # Check if credentials are available
        if not smtp_user or not smtp_password:
            logging.error("SMTP credentials not found in environment variables")
            return False
        
        logging.debug(f"Email would be sent to {lead_data.get('email', '')} with scan results")
        
        # For now, just log it - don't actually send
        return True
    except Exception as e:
        logging.error(f"Error in email function: {e}")
        return False

# ---------------------------- ROUTES ----------------------------

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
        logging.debug("POST request received on /scan endpoint")
        
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
            logging.warning("Form submission missing email address")
            return render_template('scan.html', error="Please enter your email address to receive the scan report.")
        
        try:
            # Clear any old session data
            session.pop('scan_id', None)
            session.pop('scan_results_file', None)
            logging.debug("Cleared old session data")
            
            # Save lead data
            save_lead_data(lead_data)
            logging.debug("Lead data saved")
            
            # Run the simplified scan
            logging.debug("Starting simplified scan...")
            scan_results = simple_scan(lead_data)
            logging.debug(f"Scan completed with ID: {scan_results.get('scan_id', 'No ID generated')}")
            
            # Try to send email
            send_email_report(lead_data, scan_results)
            
            # Store scan info in session
            session['scan_id'] = scan_results['scan_id']
            if 'results_file' in scan_results:
                session['scan_results_file'] = scan_results['results_file']
            logging.debug(f"Stored in session: scan_id={session.get('scan_id')}, results_file={session.get('scan_results_file')}")
            
            # Redirect to results page
            return redirect(url_for('results'))
        except Exception as e:
            logging.error(f"Error processing scan: {str(e)}")
            return render_template('scan.html', error=f"An error occurred: {str(e)}")
    
    # For GET requests, just show the scan form
    return render_template('scan.html')

@app.route('/results')
def results():
    """Display scan results"""
    scan_id = session.get('scan_id')
    results_file = session.get('scan_results_file')
    
    logging.debug(f"Results page accessed with scan_id={scan_id}, results_file={results_file}")
    
    if not scan_id:
        logging.warning("No scan_id in session, redirecting to scan page")
        return render_template('error.html', error="No scan information found. Please run a scan first.")
    
    try:
        # Check if we have a specific file path and it exists
        if results_file and os.path.exists(results_file):
            logging.debug(f"Loading results from specific file: {results_file}")
            with open(results_file, 'r') as f:
                scan_results = json.load(f)
                logging.debug(f"Successfully loaded results with keys: {list(scan_results.keys())}")
            return render_template('results.html', scan=scan_results)
        
        # Try various potential locations
        primary_file = os.path.join(SCAN_HISTORY_DIR, f"scan_{scan_id}.json")
        fallback_file = os.path.join(FALLBACK_DIR, f"scan_{scan_id}.json")
        
        if os.path.exists(primary_file):
            logging.debug(f"Found results at primary location: {primary_file}")
            with open(primary_file, 'r') as f:
                scan_results = json.load(f)
            return render_template('results.html', scan=scan_results)
        
        if os.path.exists(fallback_file):
            logging.debug(f"Found results at fallback location: {fallback_file}")
            with open(fallback_file, 'r') as f:
                scan_results = json.load(f)
            return render_template('results.html', scan=scan_results)
        
        # If we get here, we couldn't find the results
        logging.error(f"Could not find results for scan_id: {scan_id}")
        return render_template('error.html', error="Scan results not found. Please try scanning again.")
        
    except Exception as e:
        logging.error(f"Error loading scan results: {str(e)}")
        return render_template('error.html', error=f"Error loading scan results: {str(e)}")

@app.route('/debug/config')
def debug_config():
    """Show current application configuration for debugging"""
    config_info = {
        'BASE_DIR': BASE_DIR,
        'SCAN_HISTORY_DIR': SCAN_HISTORY_DIR,
        'SCAN_HISTORY_DIR_EXISTS': os.path.exists(SCAN_HISTORY_DIR),
        'SCAN_HISTORY_DIR_WRITABLE': os.access(SCAN_HISTORY_DIR, os.W_OK) if os.path.exists(SCAN_HISTORY_DIR) else False,
        'FALLBACK_DIR': FALLBACK_DIR,
        'FALLBACK_DIR_EXISTS': os.path.exists(FALLBACK_DIR),
        'FALLBACK_DIR_WRITABLE': os.access(FALLBACK_DIR, os.W_OK) if os.path.exists(FALLBACK_DIR) else False,
        'TMP_DIR_WRITABLE': os.access('/tmp', os.W_OK),
        'SMTP_CONFIG': {
            'SMTP_USER_SET': bool(os.environ.get('SMTP_USER')),
            'SMTP_PASSWORD_SET': bool(os.environ.get('SMTP_PASSWORD'))
        },
        'SESSION_SECRET_KEY_SET': bool(app.secret_key),
        'PYTHON_VERSION': platform.python_version(),
        'FLASK_ENV': app.config.get('ENV', 'production'),
        'DEBUG_MODE': app.config.get('DEBUG', False)
    }
    
    # Format as preformatted text
    output = "<h1>Application Configuration</h1><pre>"
    for key, value in config_info.items():
        output += f"{key}: {value}\n"
    output += "</pre>"
    
    return output

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

# ---------------------------- MAIN ENTRY POINT ----------------------------

if __name__ == '__main__':
    # Get port from environment variable or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Use 0.0.0.0 to make the app accessible from any IP
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_ENV') == 'development')
