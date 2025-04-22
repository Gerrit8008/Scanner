from flask import Flask, request, jsonify
import subprocess
import json
import re
import time
import uuid
import os
from flask_cors import CORS
import logging
import ssl
import socket
import requests
from urllib.parse import urlparse
import re
import json
import time
import uuid
import os
import datetime
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import dns.resolver
import dns.zone
import dns.query
from flask_cors import CORS
import logging
import warnings

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
CORS(app)  # Enable CORS for cross-domain requests

# Configuration
SCAN_TIMEOUT = 60  # Maximum time for a scan in seconds
ALLOWED_IPS = ['127.0.0.1', 'localhost', '192.168.1.1']  # List of IPs allowed to be scanned
SCAN_HISTORY_DIR = 'scan_history'

# Create scan history directory if it doesn't exist
if not os.path.exists(SCAN_HISTORY_DIR):
    os.makedirs(SCAN_HISTORY_DIR)


# Suppress InsecureRequestWarning warnings
warnings.filterwarnings('ignore', category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

# ===== Add the new API endpoints after your existing endpoints =====

@app.route('/api/comprehensive_scan', methods=['POST'])
def comprehensive_scan():
    """API endpoint to perform a comprehensive security scan on a target"""
    data = request.json
    
    # Validate input
    if not data or 'target' not in data:
        return jsonify({'error': 'Target is required (domain or IP address)'}), 400
    
    target = data['target']
    
    # Generate a unique scan ID
    scan_id = str(uuid.uuid4())
    
    # Parse the target to determine if it's a domain or IP
    is_domain = False
    try:
        socket.inet_aton(target)  # This will fail if target is not an IP address
    except socket.error:
        is_domain = True
    
    # Initialize scan results dictionary
    scan_results = {
        'scan_id': scan_id,
        'target': target,
        'timestamp': time.time(),
        'is_domain': is_domain
    }
    
    # Perform port scan (reuse your existing functionality)
    if data.get('skip_port_scan', False) is False:
        port_scan_data = request.json.copy()
        port_scan_data['scan_type'] = port_scan_data.get('scan_type', 'basic')
        port_scan_response = scan_ports()
        if port_scan_response.status_code == 200:
            port_scan_results = json.loads(port_scan_response.get_data(as_text=True))
            scan_results['open_ports'] = port_scan_results.get('results', {})
    
    # If it's a domain, perform web security checks
    if is_domain:
        # Attempt to normalize the domain
        if target.startswith('http://') or target.startswith('https://'):
            parsed_url = urlparse(target)
            domain = parsed_url.netloc
        else:
            domain = target
            
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
            if https_accessible and data.get('skip_ssl_scan', False) is False:
                scan_results['ssl_certificate'] = check_ssl_certificate(domain)
            
            # HTTP Security Headers Assessment
            if data.get('skip_header_scan', False) is False:
                scan_results['security_headers'] = check_security_headers(target_url)
            
            # CMS Detection
            if data.get('skip_cms_scan', False) is False:
                scan_results['cms'] = detect_cms(target_url)
            
            # Cookie Security Analysis
            if data.get('skip_cookie_scan', False) is False:
                scan_results['cookies'] = analyze_cookies(target_url)
            
            # Web Application Framework Detection
            if data.get('skip_framework_scan', False) is False:
                scan_results['frameworks'] = detect_web_framework(target_url)
            
            # Basic Content Crawling (look for sensitive paths)
            if data.get('skip_content_scan', False) is False:
                max_urls = data.get('max_crawl_urls', 15)
                scan_results['sensitive_content'] = crawl_for_sensitive_content(target_url, max_urls)
        
        # DNS Configuration Analysis (for domains)
        if data.get('skip_dns_scan', False) is False:
            scan_results['dns_configuration'] = analyze_dns_configuration(domain)
    
    # Calculate overall risk score
    scan_results['risk_assessment'] = calculate_risk_score(scan_results)
    
    # Save scan results
    save_comprehensive_results(scan_id, scan_results)
    
    return jsonify(scan_results)

def save_comprehensive_results(scan_id, results):
    """Save comprehensive scan results to a file"""
    filename = os.path.join(SCAN_HISTORY_DIR, f"comprehensive_{scan_id}.json")
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)

@app.route('/api/comprehensive_scan/<scan_id>', methods=['GET'])
def get_comprehensive_scan(scan_id):
    """Retrieve results of a previous comprehensive scan"""
    try:
        filename = os.path.join(SCAN_HISTORY_DIR, f"comprehensive_{scan_id}.json")
        if not os.path.exists(filename):
            return jsonify({'error': 'Comprehensive scan not found'}), 404
        
        with open(filename, 'r') as f:
            scan_data = json.load(f)
        
        return jsonify(scan_data)
    except Exception as e:
        return jsonify({'error': f'Failed to retrieve comprehensive scan: {str(e)}'}), 500

@app.route('/api/ssl_check', methods=['POST'])
def ssl_check():
    """API endpoint to check SSL/TLS certificate"""
    data = request.json
    
    if not data or 'target' not in data:
        return jsonify({'error': 'Target domain is required'}), 400
    
    target = data['target']
    port = data.get('port', 443)
    
    try:
        result = check_ssl_certificate(target, port)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'SSL check failed: {str(e)}'}), 500

@app.route('/api/header_check', methods=['POST'])
def header_check():
    """API endpoint to check HTTP security headers"""
    data = request.json
    
    if not data or 'target' not in data:
        return jsonify({'error': 'Target URL is required'}), 400
    
    target = data['target']
    
    try:
        result = check_security_headers(target)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'Header check failed: {str(e)}'}), 500

@app.route('/api/cms_detect', methods=['POST'])
def cms_detect():
    """API endpoint to detect CMS and check for vulnerabilities"""
    data = request.json
    
    if not data or 'target' not in data:
        return jsonify({'error': 'Target URL is required'}), 400
    
    target = data['target']
    
    try:
        result = detect_cms(target)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'CMS detection failed: {str(e)}'}), 500

@app.route('/api/dns_analysis', methods=['POST'])
def dns_analysis():
    """API endpoint to analyze DNS configuration"""
    data = request.json
    
    if not data or 'target' not in data:
        return jsonify({'error': 'Target domain is required'}), 400
    
    target = data['target']
    
    try:
        result = analyze_dns_configuration(target)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'DNS analysis failed: {str(e)}'}), 500

@app.route('/api/cookie_analysis', methods=['POST'])
def cookie_analysis():
    """API endpoint to analyze cookie security"""
    data = request.json
    
    if not data or 'target' not in data:
        return jsonify({'error': 'Target URL is required'}), 400
    
    target = data['target']
    
    try:
        result = analyze_cookies(target)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'Cookie analysis failed: {str(e)}'}), 500

@app.route('/api/framework_detect', methods=['POST'])
def framework_detect():
    """API endpoint to detect web application frameworks"""
    data = request.json
    
    if not data or 'target' not in data:
        return jsonify({'error': 'Target URL is required'}), 400
    
    target = data['target']
    
    try:
        result = detect_web_framework(target)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'Framework detection failed: {str(e)}'}), 500

@app.route('/api/content_scan', methods=['POST'])
def content_scan():
    """API endpoint to scan for sensitive content"""
    data = request.json
    
    if not data or 'target' not in data:
        return jsonify({'error': 'Target URL is required'}), 400
    
    target = data['target']
    max_urls = data.get('max_urls', 10)
    
    try:
        result = crawl_for_sensitive_content(target, max_urls)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'Content scanning failed: {str(e)}'}), 500

# Add this optional endpoint to generate a consolidated security report in HTML format
@app.route('/api/generate_report/<scan_id>', methods=['GET'])
def generate_report(scan_id):
    """Generate a comprehensive HTML security report from scan results"""
    try:
        # Try to load comprehensive scan first
        comprehensive_filename = os.path.join(SCAN_HISTORY_DIR, f"comprehensive_{scan_id}.json")
        if not os.path.exists(comprehensive_filename):
            # Try regular scan if comprehensive not found
            regular_filename = os.path.join(SCAN_HISTORY_DIR, f"{scan_id}.json")
            if not os.path.exists(regular_filename):
                return jsonify({'error': 'Scan not found'}), 404
            
            with open(regular_filename, 'r') as f:
                scan_data = json.load(f)
                is_comprehensive = False
        else:
            with open(comprehensive_filename, 'r') as f:
                scan_data = json.load(f)
                is_comprehensive = True
        
        # Generate HTML report
        html_report = generate_html_report(scan_data, is_comprehensive)
        
        # Return the HTML report
        return html_report
    except Exception as e:
        return jsonify({'error': f'Failed to generate report: {str(e)}'}), 500

def generate_html_report(scan_data, is_comprehensive=True):
    """Generate an HTML report from scan data"""
    target = scan_data.get('target', 'Unknown')
    scan_date = datetime.datetime.fromtimestamp(scan_data.get('timestamp', time.time())).strftime('%Y-%m-%d %H:%M:%S')
    
    # Start building HTML
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Scan Report for {target}</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }}
            .header {{ background-color: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
            .section {{ margin-bottom: 30px; border: 1px solid #ddd; border-radius: 5px; padding: 20px; }}
            .subsection {{ margin-top: 20px; }}
            h1 {{ color: #2c3e50; }}
            h2 {{ color: #3498db; border-bottom: 1px solid #eee; padding-bottom: 10px; }}
            h3 {{ color: #2980b9; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #f8f9fa; }}
            .score {{ font-size: 24px; font-weight: bold; }}
            .high {{ color: #27ae60; }}
            .medium {{ color: #f39c12; }}
            .low {{ color: #e74c3c; }}
            .critical {{ color: #c0392b; }}
            .issue {{ padding: 10px; margin: 5px 0; border-radius: 3px; }}
            .high-severity {{ background-color: #ffdddd; }}
            .medium-severity {{ background-color: #ffffcc; }}
            .low-severity {{ background-color: #e8f4f8; }}
            .recommendation {{ background-color: #d5f5e3; padding: 10px; margin-top: 10px; border-radius: 3px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Security Scan Report</h1>
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Scan Date:</strong> {scan_date}</p>
            <p><strong>Scan ID:</strong> {scan_data.get('scan_id', 'Unknown')}</p>
    """
    
    # Add risk assessment if available
    if 'risk_assessment' in scan_data:
        risk = scan_data['risk_assessment']
        score = risk.get('overall_score', 0)
        risk_level = risk.get('risk_level', 'Unknown')
        
        score_class = 'high' if score >= 80 else 'medium' if score >= 60 else 'low' if score >= 40 else 'critical'
        
        html += f"""
            <div>
                <h2>Overall Security Score</h2>
                <p class="score {score_class}">{score}/100 - {risk_level} Risk</p>
            </div>
        """
    
    html += """
        </div>
    """
    
    # Add recommendations section if available
    if 'risk_assessment' in scan_data and 'recommendations' in scan_data['risk_assessment']:
        recommendations = scan_data['risk_assessment']['recommendations']
        
        if recommendations:
            html += """
            <div class="section">
                <h2>Key Recommendations</h2>
                <ul>
            """
            
            for recommendation in recommendations:
                html += f"""
                    <li>{recommendation}</li>
                """
            
            html += """
                </ul>
            </div>
            """
    
    # Add SSL/TLS Certificate section if available
    if 'ssl_certificate' in scan_data:
        ssl_data = scan_data['ssl_certificate']
        
        if 'error' not in ssl_data:
            status = ssl_data.get('status', 'Unknown')
            status_class = 'high' if status == 'valid' else 'low'
            
            html += f"""
            <div class="section">
                <h2>SSL/TLS Certificate</h2>
                <p>Status: <span class="{status_class}">{status.upper()}</span></p>
                
                <table>
                    <tr>
                        <th>Attribute</th>
                        <th>Value</th>
                    </tr>
                    <tr>
                        <td>Issuer</td>
                        <td>{ssl_data.get('issuer', 'Unknown')}</td>
                    </tr>
                    <tr>
                        <td>Valid Until</td>
                        <td>{ssl_data.get('valid_until', 'Unknown')}</td>
                    </tr>
                    <tr>
                        <td>Days to Expiry</td>
                        <td>{ssl_data.get('days_to_expiry', 'Unknown')}</td>
                    </tr>
                    <tr>
                        <td>Protocol</td>
                        <td>{ssl_data.get('protocol', 'Unknown')}</td>
                    </tr>
                    <tr>
                        <td>Cipher Suite</td>
                        <td>{ssl_data.get('cipher_suite', 'Unknown')}</td>
                    </tr>
                </table>
                
                <div class="subsection">
                    <h3>Issues</h3>
            """
            
            has_issues = False
            
            if ssl_data.get('is_expired', False):
                has_issues = True
                html += """
                    <div class="issue high-severity">
                        <strong>Critical: Certificate is expired</strong>
                        <p>Your SSL certificate has expired and needs to be renewed immediately.</p>
                    </div>
                """
            elif ssl_data.get('expiring_soon', False):
                has_issues = True
                html += """
                    <div class="issue medium-severity">
                        <strong>Warning: Certificate expiring soon</strong>
                        <p>Your SSL certificate will expire soon. Plan to renew it before expiration.</p>
                    </div>
                """
            
            if ssl_data.get('weak_protocol', False):
                has_issues = True
                html += """
                    <div class="issue high-severity">
                        <strong>Critical: Weak SSL/TLS protocol</strong>
                        <p>Your server is using an outdated SSL/TLS protocol that has known vulnerabilities.</p>
                    </div>
                """
            
            if not has_issues:
                html += """
                    <p>No issues found with SSL certificate.</p>
                """
            
            html += """
                </div>
            </div>
            """
    
    # Add Security Headers section if available
    if 'security_headers' in scan_data:
        headers_data = scan_data['security_headers']
        
        if 'error' not in headers_data:
            score = headers_data.get('score', 0)
            score_class = 'high' if score >= 80 else 'medium' if score >= 60 else 'low'
            
            html += f"""
            <div class="section">
                <h2>HTTP Security Headers</h2>
                <p>Score: <span class="{score_class}">{score}/100</span></p>
                
                <div class="subsection">
                    <h3>Missing Headers</h3>
            """
            
            missing_headers = headers_data.get('missing_headers', [])
            
            if missing_headers:
                html += """
                    <ul>
                """
                
                for header in missing_headers:
                    description = headers_data.get('headers', {}).get(header, {}).get('description', '')
                    html += f"""
                        <li><strong>{header}</strong>: {description}</li>
                    """
                
                html += """
                    </ul>
                """
            else:
                html += """
                    <p>All recommended security headers are present. Great job!</p>
                """
            
            html += """
                </div>
                
                <div class="subsection">
                    <h3>Present Headers</h3>
                    <table>
                        <tr>
                            <th>Header</th>
                            <th>Value</th>
                        </tr>
            """
            
            for header, details in headers_data.get('headers', {}).items():
                if details.get('present', False):
                    html += f"""
                        <tr>
                            <td>{header}</td>
                            <td>{details.get('value', 'Unknown')}</td>
                        </tr>
                    """
            
            html += """
                    </table>
                </div>
            </div>
            """
    
    # Add CMS Detection section if available
    if 'cms' in scan_data:
        cms_data = scan_data['cms']
        
        if 'error' not in cms_data:
            cms_name = cms_data.get('cms_name', 'No CMS detected')
            cms_version = cms_data.get('version', 'Unknown')
            cms_detected = cms_data.get('cms_detected', False)
            
            html += f"""
            <div class="section">
                <h2>Content Management System (CMS)</h2>
                <p><strong>Detected:</strong> {'Yes' if cms_detected else 'No'}</p>
            """
            
            if cms_detected:
                html += f"""
                <p><strong>CMS:</strong> {cms_name}</p>
                <p><strong>Version:</strong> {cms_version}</p>
                <p><strong>Confidence:</strong> {cms_data.get('confidence', 'Unknown')}</p>
                """
                
                vulnerabilities = cms_data.get('potential_vulnerabilities', [])
                if vulnerabilities:
                    html += """
                    <div class="subsection">
                        <h3>Potential Vulnerabilities</h3>
                        <ul>
                    """
                    
                    for vuln in vulnerabilities:
                        html += f"""
                        <li>
                            <strong>{vuln.get('name', 'Unknown Issue')}</strong>
                            <p>{vuln.get('description', '')}</p>
                            <div class="recommendation">{vuln.get('recommendation', '')}</div>
                        </li>
                        """
                    
                    html += """
                        </ul>
                    </div>
                    """
                else:
                    html += """
                    <p>No known vulnerabilities detected for this CMS configuration.</p>
                    """
            
            html += """
            </div>
            """
    
    # Add DNS Configuration section if available
    if 'dns_configuration' in scan_data:
        dns_data = scan_data['dns_configuration']
        
        if 'error' not in dns_data:
            html += f"""
            <div class="section">
                <h2>DNS Configuration</h2>
                <p><strong>Domain:</strong> {dns_data.get('domain', 'Unknown')}</p>
                
                <div class="subsection">
                    <h3>DNS Records</h3>
                    <table>
                        <tr>
                            <th>Record Type</th>
                            <th>Values</th>
                        </tr>
            """
            
            for record_type, records in dns_data.get('records', {}).items():
                record_values = "<br>".join(records) if records else "None found"
                html += f"""
                        <tr>
                            <td>{record_type}</td>
                            <td>{record_values}</td>
                        </tr>
                """
            
            html += """
                    </table>
                </div>
                
                <div class="subsection">
                    <h3>DNS Security Issues</h3>
            """
            
            issues = dns_data.get('issues', [])
            
            if issues:
                html += """
                    <ul>
                """
                
                for issue in issues:
                    severity_class = "high-severity" if issue.get('severity') == "High" else "medium-severity" if issue.get('severity') == "Medium" else "low-severity"
                    
                    html += f"""
                        <li class="issue {severity_class}">
                            <strong>{issue.get('type', 'Unknown Issue')} ({issue.get('severity', 'Unknown')})</strong>
                            <p>{issue.get('description', '')}</p>
                            <div class="recommendation">{issue.get('recommendation', '')}</div>
                        </li>
                    """
                
                html += """
                    </ul>
                """
            else:
                html += """
                    <p>No DNS configuration issues detected.</p>
                """
            
            html += """
                </div>
            </div>
            """
    
    # Add Cookie Security section if available
    if 'cookies' in scan_data:
        cookie_data = scan_data['cookies']
        
        if 'error' not in cookie_data:
            score = cookie_data.get('score', 0)
            score_class = 'high' if score >= 80 else 'medium' if score >= 60 else 'low'
            
            html += f"""
            <div class="section">
                <h2>Cookie Security</h2>
                <p>Score: <span class="{score_class}">{score}/100</span></p>
                <p><strong>Total Cookies:</strong> {cookie_data.get('total_cookies', 0)}</p>
                <p><strong>Cookies with Issues:</strong> {cookie_data.get('total_issues', 0)}</p>
                
                <div class="subsection">
                    <h3>Cookie Details</h3>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Secure</th>
                            <th>HttpOnly</th>
                            <th>SameSite</th>
                            <th>Issues</th>
                        </tr>
            """
            
            for cookie in cookie_data.get('cookies', []):
                secure_class = 'high' if cookie.get('secure', False) else 'low'
                http_only_class = 'high' if cookie.get('http_only', False) else 'low'
                same_site_class = 'high' if cookie.get('same_site', '') else 'low'
                
                issues = len(cookie.get('security_issues', []))
                issues_class = 'high' if issues == 0 else 'medium' if issues == 1 else 'low'
                
                html += f"""
                        <tr>
                            <td>{cookie.get('name', 'Unknown')}</td>
                            <td class="{secure_class}">{"Yes" if cookie.get('secure', False) else "No"}</td>
                            <td class="{http_only_class}">{"Yes" if cookie.get('http_only', False) else "No"}</td>
                            <td class="{same_site_class}">{cookie.get('same_site', 'Not set')}</td>
                            <td class="{issues_class}">{issues}</td>
                        </tr>
                """
            
            html += """
                    </table>
                </div>
            </div>
            """
    
    # Add Web Framework Detection section if available
    if 'frameworks' in scan_data:
        framework_data = scan_data['frameworks']
        
        if 'error' not in framework_data:
            frameworks = framework_data.get('frameworks', [])
            
            html += """
            <div class="section">
                <h2>Web Technologies</h2>
                <div class="subsection">
                    <h3>Detected Technologies</h3>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Version</th>
                            <th>Type</th>
                        </tr>
            """
            
            for tech in frameworks:
                html += f"""
                        <tr>
                            <td>{tech.get('name', 'Unknown')}</td>
                            <td>{tech.get('value', 'Unknown')}</td>
                            <td>{tech.get('type', 'Unknown')}</td>
                        </tr>
                """
            
            html += """
                    </table>
                </div>
            """
            
            vulnerabilities = framework_data.get('known_vulnerabilities', [])
            if vulnerabilities:
                html += """
                <div class="subsection">
                    <h3>Known Vulnerabilities</h3>
                    <ul>
                """
                
                for vuln in vulnerabilities:
                    html += f"""
                        <li class="issue high-severity">
                            <strong>{vuln.get('framework', 'Unknown Framework')} {vuln.get('version', '')}</strong>
                            <p>{vuln.get('description', '')}</p>
                            <div class="recommendation">{vuln.get('recommendation', '')}</div>
                        </li>
                    """
                
                html += """
                    </ul>
                </div>
                """
            
            html += """
            </div>
            """
    
    # Add Sensitive Content section if available
    if 'sensitive_content' in scan_data:
        content_data = scan_data['sensitive_content']
        
        if 'error' not in content_data:
            risk_level = content_data.get('risk_level', 'low').lower()
            risk_class = 'high' if risk_level == 'low' else 'medium' if risk_level == 'medium' else 'low'
            
            html += f"""
            <div class="section">
                <h2>Sensitive Content Exposure</h2>
                <p><strong>Risk Level:</strong> <span class="{risk_class}">{risk_level.upper()}</span></p>
                <p><strong>Sensitive Paths Found:</strong> {content_data.get('sensitive_paths_found', 0)}</p>
                
                <div class="subsection">
                    <h3>Findings</h3>
            """
            
            findings = content_data.get('findings', [])
            
            if findings:
                html += """
                    <table>
                        <tr>
                            <th>URL</th>
                            <th>Status</th>
                            <th>Source</th>
                            <th>Severity</th>
                        </tr>
                """
                
                for finding in findings:
                    severity = finding.get('severity', 'medium')
                    severity_class = 'high-severity' if severity == 'high' else 'medium-severity'
                    
                    html += f"""
                        <tr class="{severity_class}">
                            <td>{finding.get('url', 'Unknown')}</td>
                            <td>{finding.get('status_code', 'Unknown')}</td>
                            <td>{finding.get('source', 'Unknown')}</td>
                            <td>{severity.upper()}</td>
                        </tr>
                    """
                
                html += """
                    </table>
                """
                
                html += f"""
                <div class="recommendation">{content_data.get('recommendation', '')}</div>
                """
            else:
                html += """
                <p>No sensitive content exposure detected.</p>
                """
            
            html += """
                </div>
            </div>
            """
    
    # Add Open Ports section if available
    if 'open_ports' in scan_data:
        ports_data = scan_data['open_ports']
        
        html += """
        <div class="section">
            <h2>Open Ports and Services</h2>
        """
        
        open_ports = ports_data.get('open_ports', [])
        if open_ports:
            html += f"""
            <p><strong>Open Ports:</strong> {len(open_ports)}</p>
            
            <table>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Protocol</th>
                    <th>Risk</th>
                </tr>
            """
            
            # Define high-risk ports
            high_risk_ports = [21, 22, 23, 25, 53, 137, 138, 139, 445, 1433, 1434, 3306, 3389, 5432, 5900]
            
            for port in sorted(open_ports):
                service_info = ports_data.get('services', {}).get(str(port), {})
                service = service_info.get('service', 'Unknown')
                protocol = service_info.get('protocol', 'tcp')
                
                risk = "High" if port in high_risk_ports else "Medium"
                risk_class = "high-severity" if risk == "High" else "medium-severity"
                
                html += f"""
                <tr class="{risk_class}">
                    <td>{port}</td>
                    <td>{service}</td>
                    <td>{protocol}</td>
                    <td>{risk}</td>
                </tr>
                """
            
            html += """
            </table>
            """
        else:
            html += """
            <p>No open ports detected.</p>
            """
        
        filtered_ports = ports_data.get('filtered_ports', [])
        if filtered_ports:
            html += f"""
            <div class="subsection">
                <h3>Filtered Ports</h3>
                <p>{len(filtered_ports)} ports are filtered (possibly behind a firewall).</p>
            </div>
            """
        
        html += """
        </div>
        """
    
    # Complete the HTML document
    html += """
    </body>
    </html>
    """
    
    return html

@app.route('/api/scan', methods=['POST'])
def scan_ports():
    """API endpoint to scan ports using Nmap"""
    data = request.json
    
    # Validate input
    if not data or 'target' not in data:
        return jsonify({'error': 'Target IP address is required'}), 400
    
    target = data['target']
    scan_type = data.get('scan_type', 'basic')  # Default to basic scan
    
    # Security check: Only allow scanning of approved IPs
    if target not in ALLOWED_IPS and not target.startswith('192.168.'):
        return jsonify({'error': 'Scanning of this IP is not allowed for security reasons'}), 403
    
    # Generate a unique scan ID
    scan_id = str(uuid.uuid4())
    
    try:
        # Check if nmap is installed
        try:
            subprocess.run(['nmap', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            # Nmap not available, use alternative port checker
            return perform_socket_scan(target, scan_id)
        
        # Prepare nmap command based on scan type
        if scan_type == 'basic':
            cmd = ['nmap', '-F', target]  # Fast scan of common ports
        elif scan_type == 'full':
            cmd = ['nmap', '-p', '1-65535', target]  # Full port scan
        elif scan_type == 'service':
            cmd = ['nmap', '-sV', target]  # Service detection
        else:
            return jsonify({'error': 'Invalid scan type'}), 400
        
        logging.debug(f"Running command: {' '.join(cmd)}")
        
        # Run nmap command
        result = subprocess.run(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            timeout=SCAN_TIMEOUT,
            text=True
        )
        
        # Process the output
        scan_results = parse_nmap_output(result.stdout)
        
        # Save scan results
        save_scan_results(scan_id, target, scan_type, scan_results)
        
        return jsonify({
            'scan_id': scan_id,
            'target': target,
            'scan_type': scan_type,
            'results': scan_results
        })
        
    except subprocess.TimeoutExpired:
        return jsonify({'error': f'Scan timed out after {SCAN_TIMEOUT} seconds'}), 500
    except Exception as e:
        logging.error(f"Error during scan: {str(e)}")
        # If nmap fails, fallback to socket scan
        return perform_socket_scan(target, scan_id)

def perform_socket_scan(target, scan_id):
    """Perform a port scan using Python sockets (fallback if nmap is not available)"""
    try:
        logging.debug(f"Performing socket-based scan on {target}")
        
        # Common ports to scan
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443
        ]
        
        scan_results = {
            'open_ports': [],
            'filtered_ports': [],
            'closed_ports': [],
            'services': {}
        }
        
        # Scan each port
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        scan_results['open_ports'].append(port)
                        service_name = get_service_name(port)
                        scan_results['services'][port] = {
                            'protocol': 'tcp',
                            'service': service_name
                        }
            except:
                scan_results['filtered_ports'].append(port)
        
        # Save scan results
        save_scan_results(scan_id, target, 'basic', scan_results)
        
        return jsonify({
            'scan_id': scan_id,
            'target': target,
            'scan_type': 'basic',
            'results': scan_results,
            'note': 'Performed using socket-based scan (nmap not available)'
        })
    except Exception as e:
        logging.error(f"Error during socket scan: {str(e)}")
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500

def get_service_name(port):
    """Get service name from common port numbers"""
    common_services = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        111: 'RPC',
        135: 'RPC',
        139: 'NetBIOS',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        1723: 'PPTP',
        3306: 'MySQL',
        3389: 'RDP',
        5900: 'VNC',
        8080: 'HTTP-ALT',
        8443: 'HTTPS-ALT'
    }
    
    return common_services.get(port, 'Unknown')

def parse_nmap_output(output):
    """Parse Nmap output into a structured format"""
    results = {
        'open_ports': [],
        'filtered_ports': [],
        'closed_ports': [],
        'services': {}
    }
    
    # Extract port information using regex
    port_pattern = r'(\d+)/(\w+)\s+(\w+)\s+([^\n]*)'
    matches = re.findall(port_pattern, output)
    
    for match in matches:
        port, protocol, state, service = match
        port = int(port)
        
        if state == 'open':
            results['open_ports'].append(port)
            results['services'][port] = {
                'protocol': protocol,
                'service': service.strip()
            }
        elif state == 'filtered':
            results['filtered_ports'].append(port)
        elif state == 'closed':
            results['closed_ports'].append(port)
    
    return results

def save_scan_results(scan_id, target, scan_type, results):
    """Save scan results to a file for future reference"""
    scan_data = {
        'scan_id': scan_id,
        'target': target,
        'scan_type': scan_type,
        'timestamp': time.time(),
        'results': results
    }
    
    filename = os.path.join(SCAN_HISTORY_DIR, f"{scan_id}.json")
    with open(filename, 'w') as f:
        json.dump(scan_data, f, indent=2)

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_results(scan_id):
    """Retrieve results of a previous scan"""
    try:
        filename = os.path.join(SCAN_HISTORY_DIR, f"{scan_id}.json")
        if not os.path.exists(filename):
            return jsonify({'error': 'Scan not found'}), 404
        
        with open(filename, 'r') as f:
            scan_data = json.load(f)
        
        return jsonify(scan_data)
    except Exception as e:
        return jsonify({'error': f'Failed to retrieve scan: {str(e)}'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': time.time(),
        'scan_api': 'running'
    })

if __name__ == '__main__':
    import socket  # Import socket here for fallback scan
    port = int(os.environ.get('PORT', 5001))
    logging.info(f"Starting Port Scanning API on port {port}")
    app.run(host='0.0.0.0', port=port, debug=True)
