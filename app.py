from flask import Flask, render_template, request, jsonify, session, redirect, url_for
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

# ===== ENHANCED SECURITY SCANNER FUNCTIONS =====

def check_ssl_certificate(hostname, port=443):
    """Check SSL/TLS certificate for security issues"""
    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get certificate
                cert_binary = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_binary, default_backend())
                
                # Extract certificate information
                issuer = cert.issuer.rfc4514_string()
                subject = cert.subject.rfc4514_string()
                not_before = cert.not_valid_before
                not_after = cert.not_valid_after
                
                # Check if certificate is expired or about to expire
                now = datetime.now()
                days_to_expiry = (not_after - now).days
                is_expired = now > not_after
                expiring_soon = days_to_expiry < 30
                
                # Get cipher and protocol information
                cipher = ssock.cipher()
                protocol = ssock.version()
                
                # Check for weak protocols (SSL2, SSL3, TLS1.0, TLS1.1)
                weak_protocol = protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
                
                # Results
                result = {
                    'issuer': issuer,
                    'subject': subject,
                    'valid_from': not_before.isoformat(),
                    'valid_until': not_after.isoformat(),
                    'days_to_expiry': days_to_expiry,
                    'is_expired': is_expired,
                    'expiring_soon': expiring_soon,
                    'cipher_suite': cipher[0],
                    'protocol': protocol,
                    'weak_protocol': weak_protocol,
                    'status': 'valid' if not is_expired else 'expired'
                }
                
                return result
    except Exception as e:
        logging.error(f"SSL certificate check failed: {str(e)}")
        return {
            'error': f'SSL certificate check failed: {str(e)}',
            'status': 'error'
        }

def check_security_headers(url):
    """Check for security headers in HTTP responses"""
    try:
        if not url.startswith('http'):
            url = f'https://{url}'
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        # Headers to check and their recommended values
        security_headers = {
            'Content-Security-Policy': {'present': False, 'value': None, 'description': 'Helps prevent XSS and data injection attacks'},
            'X-Content-Type-Options': {'present': False, 'value': None, 'description': 'Prevents MIME type sniffing'},
            'X-Frame-Options': {'present': False, 'value': None, 'description': 'Protects against clickjacking'},
            'X-XSS-Protection': {'present': False, 'value': None, 'description': 'Mitigates Cross-Site Scripting (XSS) attacks'},
            'Strict-Transport-Security': {'present': False, 'value': None, 'description': 'Enforces secure (HTTPS) connections'},
            'Referrer-Policy': {'present': False, 'value': None, 'description': 'Controls how much referrer information is included with requests'},
            'Feature-Policy': {'present': False, 'value': None, 'description': 'Controls which browser features can be used'},
            'Permissions-Policy': {'present': False, 'value': None, 'description': 'Controls which browser features can be used (newer version of Feature-Policy)'},
            'Access-Control-Allow-Origin': {'present': False, 'value': None, 'description': 'Indicates which origins can access the resource'},
            'Cache-Control': {'present': False, 'value': None, 'description': 'Directives for caching mechanisms'},
            'Clear-Site-Data': {'present': False, 'value': None, 'description': 'Clears browsing data associated with the site'}
        }
        
        # Check which headers are present
        for header, details in security_headers.items():
            if header.lower() in [h.lower() for h in response.headers]:
                security_headers[header]['present'] = True
                security_headers[header]['value'] = response.headers[header]
        
        # Calculate missing headers and overall score
        missing_headers = [h for h, d in security_headers.items() if not d['present']]
        total_headers = len(security_headers)
        present_headers = total_headers - len(missing_headers)
        score = int((present_headers / total_headers) * 100)
        
        return {
            'headers': security_headers,
            'missing_headers': missing_headers,
            'score': score,
            'total_headers': total_headers,
            'present_headers': present_headers
        }
    except Exception as e:
        logging.error(f"Security headers check failed: {str(e)}")
        return {
            'error': f'Security headers check failed: {str(e)}',
            'score': 0
        }

def detect_cms(url):
    """Detect Content Management System and check for known vulnerabilities"""
    try:
        if not url.startswith('http'):
            url = f'https://{url}'
            
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        html_content = response.text
        
        # Common CMS signatures to check
        cms_signatures = {
            'WordPress': {
                'patterns': [
                    r'wp-content',
                    r'wp-includes',
                    r'wordpress',
                    r'<meta name="generator" content="WordPress ([0-9.]+)"'
                ],
                'version_pattern': r'<meta name="generator" content="WordPress ([0-9.]+)"',
                'common_paths': ['/wp-login.php', '/wp-admin/', '/wp-content/']
            },
            'Joomla': {
                'patterns': [
                    r'joomla',
                    r'<meta name="generator" content="Joomla!'
                ],
                'version_pattern': r'<meta name="generator" content="Joomla! ([0-9.]+)"',
                'common_paths': ['/administrator/', '/components/', '/templates/']
            },
            'Drupal': {
                'patterns': [
                    r'drupal',
                    r'Drupal.settings',
                    r'/sites/default/'
                ],
                'version_pattern': r'Drupal ([0-9.]+)',
                'common_paths': ['/node/', '/sites/default/', '/user/login/']
            },
            'Magento': {
                'patterns': [
                    r'Mage.Cookies',
                    r'magento',
                    r'/skin/frontend/'
                ],
                'version_pattern': r'Magento/([0-9.]+)',
                'common_paths': ['/index.php/admin/', '/skin/frontend/', '/app/etc/']
            },
            'Shopify': {
                'patterns': [
                    r'Shopify.theme',
                    r'shopify',
                    r'/cdn.shopify.com/'
                ],
                'version_pattern': None,  # Shopify doesn't typically expose version
                'common_paths': []
            }
        }
        
        detected_cms = None
        detected_version = None
        
        # Try to detect CMS based on HTML content
        for cms, details in cms_signatures.items():
            for pattern in details['patterns']:
                if re.search(pattern, html_content, re.IGNORECASE):
                    detected_cms = cms
                    
                    # Try to extract version if pattern exists
                    if details['version_pattern']:
                        version_match = re.search(details['version_pattern'], html_content)
                        if version_match:
                            detected_version = version_match.group(1)
                    
                    break
            if detected_cms:
                break
        
        # If no CMS detected yet, check for common paths
        if not detected_cms:
            base_url = urllib.parse.urlparse(url).netloc
            for cms, details in cms_signatures.items():
                for path in details['common_paths']:
                    try:
                        check_url = f"https://{base_url}{path}"
                        path_response = requests.head(check_url, headers=headers, timeout=5, verify=False)
                        if path_response.status_code < 400:  # Path exists
                            detected_cms = cms
                            break
                    except:
                        pass
                if detected_cms:
                    break
        
        # Build result
        result = {
            'cms_detected': detected_cms is not None,
            'cms_name': detected_cms,
            'version': detected_version,
            'confidence': 'high' if detected_version else 'medium',
            'potential_vulnerabilities': []
        }
        
        # If CMS detected, try to identify potential vulnerabilities
        if detected_cms and detected_version:
            # This is a simplified example - in a real implementation, you would
            # check against a database of known vulnerabilities
            if detected_cms == 'WordPress' and detected_version:
                version_parts = [int(x) for x in detected_version.split('.')]
                if version_parts[0] < 5 or (version_parts[0] == 5 and version_parts[1] < 8):
                    result['potential_vulnerabilities'].append({
                        'name': 'Outdated WordPress',
                        'description': 'This WordPress version may contain known security vulnerabilities',
                        'recommendation': 'Update to the latest version of WordPress'
                    })
        
        return result
    except Exception as e:
        logging.error(f"CMS detection failed: {str(e)}")
        return {
            'error': f'CMS detection failed: {str(e)}',
            'cms_detected': False
        }

def analyze_cookies(url):
    """Analyze cookie security configurations"""
    try:
        if not url.startswith('http'):
            url = f'https://{url}'
            
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        session = requests.Session()
        response = session.get(url, headers=headers, timeout=10, verify=False)
        
        cookies = session.cookies
        cookie_analysis = []
        
        for cookie in cookies:
            security_issues = []
            
            # Check for Secure flag
            if not cookie.secure:
                security_issues.append({
                    'issue': 'Missing Secure Flag',
                    'description': 'Cookie can be transmitted over unencrypted HTTP connections',
                    'recommendation': 'Set the Secure flag to ensure cookies are only sent over HTTPS'
                })
            
            # Check for HttpOnly flag
            if not cookie.has_nonstandard_attr('HttpOnly'):
                security_issues.append({
                    'issue': 'Missing HttpOnly Flag',
                    'description': 'Cookie can be accessed by JavaScript, increasing XSS risk',
                    'recommendation': 'Set the HttpOnly flag to prevent JavaScript access to cookies'
                })
            
            # Check for SameSite attribute
            same_site = None
            for attr in cookie._rest.keys():
                if attr.lower() == 'samesite':
                    same_site = cookie._rest[attr]
            
            if not same_site:
                security_issues.append({
                    'issue': 'Missing SameSite Attribute',
                    'description': 'Cookie has no SameSite attribute, increasing CSRF risk',
                    'recommendation': 'Set SameSite=Lax or SameSite=Strict to limit cookie sending'
                })
            elif same_site.lower() == 'none':
                # SameSite=None is valid, but requires Secure flag
                if not cookie.secure:
                    security_issues.append({
                        'issue': 'Insecure SameSite=None Configuration',
                        'description': 'SameSite=None requires the Secure flag',
                        'recommendation': 'Add the Secure flag when using SameSite=None'
                    })
                    
            cookie_analysis.append({
                'name': cookie.name,
                'domain': cookie.domain,
                'path': cookie.path,
                'secure': cookie.secure,
                'expires': datetime.fromtimestamp(cookie.expires).isoformat() if cookie.expires else None,
                'http_only': cookie.has_nonstandard_attr('HttpOnly'),
                'same_site': same_site,
                'security_issues': security_issues
            })
        
        # Calculate overall score
        total_cookies = len(cookie_analysis)
        total_issues = sum(len(cookie['security_issues']) for cookie in cookie_analysis)
        score = 100
        if total_cookies > 0:
            avg_issues_per_cookie = total_issues / total_cookies
            # Deduct points based on average issues per cookie
            score = max(0, int(100 - (avg_issues_per_cookie * 30)))
        
        return {
            'cookies': cookie_analysis,
            'total_cookies': total_cookies,
            'total_issues': total_issues,
            'score': score
        }
    except Exception as e:
        logging.error(f"Cookie analysis failed: {str(e)}")
        return {
            'error': f'Cookie analysis failed: {str(e)}',
            'total_cookies': 0,
            'score': 0
        }

def detect_web_framework(url):
    """Detect web application frameworks and server technologies"""
    try:
        if not url.startswith('http'):
            url = f'https://{url}'
            
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        frameworks = []
        
        # Check HTTP headers for framework clues
        response_headers = response.headers
        server = response_headers.get('Server', '')
        x_powered_by = response_headers.get('X-Powered-By', '')
        
        # Server header detection
        if server:
            frameworks.append({
                'name': 'Server',
                'value': server,
                'confidence': 'high',
                'type': 'web_server'
            })
        
        # X-Powered-By header detection
        if x_powered_by:
            frameworks.append({
                'name': 'X-Powered-By',
                'value': x_powered_by,
                'confidence': 'high',
                'type': 'framework'
            })
        
        # Check for other framework-specific headers
        framework_headers = {
            'X-AspNet-Version': 'ASP.NET',
            'X-AspNetMvc-Version': 'ASP.NET MVC',
            'X-Drupal-Cache': 'Drupal',
            'X-Generator': 'Generic CMS',
            'X-Powered-CMS': 'Generic CMS',
            'X-Rails-Version': 'Ruby on Rails',
            'X-Django-Version': 'Django'
        }
        
        for header, framework in framework_headers.items():
            if header in response_headers:
                frameworks.append({
                    'name': framework,
                    'value': response_headers[header],
                    'confidence': 'high',
                    'type': 'framework'
                })
        
        # HTML content analysis
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Meta generator tag
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator and meta_generator.get('content'):
            frameworks.append({
                'name': 'Generator',
                'value': meta_generator['content'],
                'confidence': 'medium',
                'type': 'generator'
            })
        
        # Common framework patterns in HTML/JS
        framework_patterns = {
            r'jquery[/-]([0-9.]+)': 'jQuery',
            r'react[/-]dom[.-]([0-9.]+)': 'React',
            r'angular(?:js)?[/-]([0-9.]+)': 'Angular',
            r'vue(?:js)?[/-]([0-9.]+)': 'Vue.js',
            r'bootstrap[/-]([0-9.]+)': 'Bootstrap',
            r'laravel': 'Laravel',
            r'django': 'Django',
            r'express': 'Express.js',
            r'next[/-]([0-9.]+)': 'Next.js',
            r'nuxt[/-]([0-9.]+)': 'Nuxt.js',
            r'svelte': 'Svelte',
            r'ember[/-]([0-9.]+)': 'Ember.js'
        }
        
        for pattern, framework_name in framework_patterns.items():
            matches = re.search(pattern, html_content, re.IGNORECASE)
            if matches:
                version = matches.group(1) if len(matches.groups()) > 0 else None
                frameworks.append({
                    'name': framework_name,
                    'value': version if version else 'detected',
                    'confidence': 'medium',
                    'type': 'frontend_framework'
                })
        
        # Look for potential security issues
        known_vulnerabilities = []
        
        # Example: Check for outdated jQuery
        jquery_match = re.search(r'jquery[/-]([0-9.]+)', html_content, re.IGNORECASE)
        if jquery_match:
            jquery_version = jquery_match.group(1)
            version_parts = [int(x) for x in jquery_version.split('.')]
            if version_parts[0] < 3 or (version_parts[0] == 3 and version_parts[1] < 5):
                known_vulnerabilities.append({
                    'framework': 'jQuery',
                    'version': jquery_version,
                    'description': 'Using an outdated version of jQuery that may contain security vulnerabilities',
                    'recommendation': 'Update to jQuery 3.5 or later'
                })
        
        return {
            'frameworks': frameworks,
            'known_vulnerabilities': known_vulnerabilities,
            'recommended_updates': len(known_vulnerabilities) > 0
        }
    except Exception as e:
        logging.error(f"Framework detection failed: {str(e)}")
        return {
            'error': f'Framework detection failed: {str(e)}',
            'frameworks': []
        }

def crawl_for_sensitive_content(url, max_urls=10):
    """Crawl website for potentially sensitive information exposure"""
    try:
        if not url.startswith('http'):
            url = f'https://{url}'
        
        base_url = urllib.parse.urlparse(url).netloc
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Check robots.txt
        robots_url = f"https://{base_url}/robots.txt"
        disallowed_paths = []
        try:
            robots_response = requests.get(robots_url, headers=headers, timeout=5, verify=False)
            if robots_response.status_code == 200:
                for line in robots_response.text.splitlines():
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            disallowed_paths.append(path)
        except:
            pass
        
        # Common sensitive paths to check
        sensitive_paths = [
            '/admin/',
            '/login/',
            '/backup/',
            '/wp-admin/',
            '/phpinfo.php',
            '/config.php',
            '/database/',
            '/.git/',
            '/.env',
            '/credentials.txt',
            '/sitemap.xml',
            '/api/',
            '/backup.sql',
            '/server-status',
            '/test.php',
            '/tmp/',
            '/logs/',
            '/installer/',
            '/install.php',
            '/setup/',
            '/.htaccess',
            '/readme.html',
            '/license.txt',
            '/error_log',
            '/error.log',
            '/deploy.php',
            '/info.php',
            '/database.sql',
            '/password.txt',
            '/private/'
        ]
        
        # Add disallowed paths from robots.txt to sensitive paths
        sensitive_paths.extend(disallowed_paths)
        
        findings = []
        
        # Check each sensitive path
        for path in sensitive_paths[:max_urls]:  # Limit to max_urls
            try:
                check_url = f"https://{base_url}{path}"
                path_response = requests.head(check_url, headers=headers, timeout=5, verify=False, allow_redirects=False)
                
                if path_response.status_code < 400:  # Path exists or redirects
                    findings.append({
                        'url': check_url,
                        'status_code': path_response.status_code,
                        'accessible': True,
                        'source': 'robots.txt' if path in disallowed_paths else 'common_paths',
                        'severity': 'high' if path_response.status_code == 200 else 'medium'
                    })
            except:
                continue
        
        # Additional checks for exposed files
        exposed_file_types = ['.sql', '.bak', '.backup', '.zip', '.tar.gz', '.log', '.conf', '.xml', '.json']
        
        # Check for leaked data files in known locations
        for file_ext in exposed_file_types:
            check_paths = [
                f"/backup{file_ext}",
                f"/db{file_ext}",
                f"/database{file_ext}",
                f"/site{file_ext}",
                f"/backup/latest{file_ext}"
            ]
            
            for path in check_paths:
                try:
                    check_url = f"https://{base_url}{path}"
                    file_response = requests.head(check_url, headers=headers, timeout=3, verify=False)
                    
                    if file_response.status_code == 200:
                        findings.append({
                            'url': check_url,
                            'status_code': file_response.status_code,
                            'accessible': True,
                            'source': 'exposed_files',
                            'severity': 'high'
                        })
                except:
                    continue
        
        return {
            'sensitive_paths_found': len(findings),
            'findings': findings,
            'risk_level': 'high' if len(findings) > 0 else 'low',
            'recommendation': 'Restrict access to sensitive paths and files'
        }
    except Exception as e:
        logging.error(f"Content crawling failed: {str(e)}")
        return {
            'error': f'Content crawling failed: {str(e)}',
            'sensitive_paths_found': 0
        }

def calculate_risk_score(scan_results):
    """Calculate overall security risk score based on all scan results"""
    try:
        scores = {
            'ssl_certificate': 0,
            'security_headers': 0,
            'cms': 0,
            'dns_configuration': 0,
            'cookies': 0,
            'frameworks': 0,
            'sensitive_content': 0,
            'open_ports': 0,
            'email_security': 0,
            'system_security': 0
        }
        
        weights = {
            'ssl_certificate': 15,
            'security_headers': 10,
            'cms': 10,
            'dns_configuration': 10,
            'cookies': 5,
            'frameworks': 10,
            'sensitive_content': 10,
            'open_ports': 15,
            'email_security': 10,
            'system_security': 5
        }
        
        # SSL Certificate scoring
        if 'ssl_certificate' in scan_results and 'error' not in scan_results['ssl_certificate']:
            ssl_data = scan_results['ssl_certificate']
            
            # Start with full score
            ssl_score = 100
            
            # Deduct for issues
            if ssl_data.get('is_expired', False):
                ssl_score -= 50
            elif ssl_data.get('expiring_soon', False):
                ssl_score -= 20
                
            if ssl_data.get('weak_protocol', False):
                ssl_score -= 30
                
            scores['ssl_certificate'] = max(0, ssl_score)
        
        # Security Headers scoring
        if 'security_headers' in scan_results:
            scores['security_headers'] = scan_results['security_headers'].get('score', 0)
        
        # CMS scoring
        if 'cms' in scan_results:
            cms_data = scan_results['cms']
            
            if cms_data.get('cms_detected', False):
                # Start with full score
                cms_score = 100
                vulnerabilities = cms_data.get('potential_vulnerabilities', [])
                
                if vulnerabilities:
                    cms_score -= len(vulnerabilities) * 25  # Deduct 25 points per vulnerability
                
                scores['cms'] = max(0, cms_score)
            else:
                scores['cms'] = 100  # No known CMS, assume good
        
        # DNS Configuration scoring
        if 'dns_configuration' in scan_results:
            dns_data = scan_results['dns_configuration']
            
            # Start with full score
            dns_score = 100
            
            # Deduct points for issues
            issues = dns_data.get('issues', [])
            for issue in issues:
                severity = issue.get('severity', 'Medium')
                if severity == 'High':
                    dns_score -= 30
                elif severity == 'Medium':
                    dns_score -= 15
                else:  # Low
                    dns_score -= 5
            
            # Major penalty for allowing zone transfers
            if dns_data.get('zone_transfer', False):
                dns_score -= 50
                
            scores['dns_configuration'] = max(0, dns_score)
        
        # Cookie security scoring
        if 'cookies' in scan_results:
            scores['cookies'] = scan_results['cookies'].get('score', 0)
        
        # Framework detection scoring
        if 'frameworks' in scan_results:
            framework_data = scan_results['frameworks']
            
            # Start with full score
            framework_score = 100
            
            # Deduct for vulnerabilities
            vulnerabilities = framework_data.get('known_vulnerabilities', [])
            if vulnerabilities:
                framework_score -= len(vulnerabilities) * 20
                
            scores['frameworks'] = max(0, framework_score)
        
        # Sensitive content scoring
        if 'sensitive_content' in scan_results:
            content_data = scan_results['sensitive_content']
            
            # Start with full score
            content_score = 100
            
            # Deduct based on findings
            findings = content_data.get('findings', [])
            for finding in findings:
                severity = finding.get('severity', 'medium')
                if severity == 'high':
                    content_score -= 15
                else:  # medium
                    content_score -= 7
            
            scores['sensitive_content'] = max(0, content_score)
        
        # Open ports scoring
        if 'open_ports' in scan_results:
            ports_data = scan_results['open_ports']
            
            # Start with full score
            ports_score = 100
            
            # Count high-risk open ports
            high_risk_ports = [21, 22, 23, 25, 53, 137, 138, 139, 445, 1433, 1434, 3306, 3389, 5432, 5900]
            open_ports = ports_data.get('open_ports', [])
            
            high_risk_open = sum(1 for port in open_ports if port in high_risk_ports)
            
            # Deduct points for high-risk ports
            if high_risk_open > 0:
                ports_score -= high_risk_open * 15
            
            # Deduct less for other open ports
            other_open = len(open_ports) - high_risk_open
            if other_open > 0:
                ports_score -= other_open * 5
                
            scores['open_ports'] = max(0, ports_score)
        
        # Email security scoring
        if 'email_security' in scan_results:
            email_data = scan_results['email_security']
            
            # Start with full score
            email_score = 100
            
            # Check SPF
            spf_severity = email_data.get('spf', {}).get('severity', 'Low')
            if spf_severity == 'High':
                email_score -= 30
            elif spf_severity == 'Medium':
                email_score -= 15
            
            # Check DMARC
            dmarc_severity = email_data.get('dmarc', {}).get('severity', 'Low')
            if dmarc_severity == 'High':
                email_score -= 30
            elif dmarc_severity == 'Medium':
                email_score -= 15
            
            # Check DKIM
            dkim_severity = email_data.get('dkim', {}).get('severity', 'Low')
            if dkim_severity == 'High':
                email_score -= 30
            elif dkim_severity == 'Medium':
                email_score -= 15
            
            scores['email_security'] = max(0, email_score)
        
        # System security scoring
        if 'system_security' in scan_results:
            system_data = scan_results['system_security']
            
            # Start with full score
            system_score = 100
            
            # Check Windows version
            windows_version = system_data.get('windows_version', '')
            if 'Windows 7' in windows_version or 'Older' in windows_version:
                system_score -= 30
            elif 'Windows 8' in windows_version:
                system_score -= 15
            
            # Check firewall status
            firewall_severity = system_data.get('firewall_severity', 'Low')
            if firewall_severity == 'High':
                system_score -= 25
            elif firewall_severity == 'Medium':
                system_score -= 10
            
            # Check OS update status
            os_update_severity = system_data.get('os_update_severity', 'Low')
            if os_update_severity == 'High':
                system_score -= 30
            elif os_update_severity == 'Medium':
                system_score -= 15
            
            scores['system_security'] = max(0, system_score)
        
        # Calculate weighted average score
        total_weight = sum(weights.values())
        weighted_score = 0
        
        for category, score in scores.items():
            weighted_score += score * weights[category]
        
        overall_score = int(weighted_score / total_weight)
        
        # Generate risk level based on score
        if overall_score >= 90:
            risk_level = 'Low'
        elif overall_score >= 70:
            risk_level = 'Medium'
        elif overall_score >= 50:
            risk_level = 'High'
        else:
            risk_level = 'Critical'
        
        # Generate recommendations based on lowest scores
        recommendations = []
        for category, score in scores.items():
            if score < 70:  # Only recommend fixing categories with low scores
                if category == 'ssl_certificate' and score < 70:
                    recommendations.append('Update SSL/TLS configuration to use modern protocols and ensure certificate is valid')
                elif category == 'security_headers' and score < 70:
                    recommendations.append('Implement missing security headers to improve web application security')
                elif category == 'cms' and score < 70:
                    recommendations.append('Update CMS to latest version and check for vulnerable plugins')
                elif category == 'dns_configuration' and score < 70:
                    recommendations.append('Fix DNS configuration issues such as missing records or zone transfer vulnerabilities')
                elif category == 'cookies' and score < 70:
                    recommendations.append('Add security flags to cookies (Secure, HttpOnly, SameSite)')
                elif category == 'frameworks' and score < 70:
                    recommendations.append('Update web frameworks and libraries to fix known vulnerabilities')
                elif category == 'sensitive_content' and score < 70:
                    recommendations.append('Restrict access to sensitive files and directories')
                elif category == 'open_ports' and score < 70:
                    recommendations.append('Close unnecessary open ports, especially high-risk services')
                elif category == 'email_security' and score < 70:
                    recommendations.append('Configure SPF, DMARC, and DKIM records to improve email security')
                elif category == 'system_security' and score < 70:
                    recommendations.append('Update operating system, enable firewall, and improve system security configuration')
        
        return {
            'overall_score': overall_score,
            'risk_level': risk_level,
            'category_scores': scores,
            'recommendations': recommendations
        }
    except Exception as e:
        logging.error(f"Risk scoring failed: {str(e)}")
        return {
            'error': f'Risk scoring failed: {str(e)}',
            'overall_score': 0,
            'risk_level': 'Unknown'
        }

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
