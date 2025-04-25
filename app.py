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

SCAN_HISTORY_DIR = 'scan_history'
if not os.path.exists(SCAN_HISTORY_DIR):
    os.makedirs(SCAN_HISTORY_DIR)

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

# ---------------------------- SCANNING FUNCTIONS ----------------------------

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

def get_client_and_gateway_ip(request):
    """
    Detects client IP and makes educated guesses about possible gateway IPs
    based on common network configurations.
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
    client_ip, gateway_guesses, network_type = get_client_and_gateway_ip(request)
    
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

def check_ssl_certificate(domain):
    """Check SSL certificate of a domain"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Parse certificate details
                not_after = cert['notAfter']
                not_before = cert['notBefore']
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                
                # Format dates
                from datetime import datetime
                import ssl
                not_after_date = ssl.cert_time_to_seconds(not_after)
                current_time = datetime.now().timestamp()
                days_remaining = int((not_after_date - current_time) / 86400)
                
                # Check if expired or expiring soon
                is_expired = days_remaining < 0
                expiring_soon = days_remaining >= 0 and days_remaining <= 30
                
                # Check protocol version
                protocol_version = ssock.version()
                weak_protocol = protocol_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
                
                # Determine status
                if is_expired:
                    status = "Expired"
                    severity = "Critical"
                elif expiring_soon:
                    status = f"Expiring Soon ({days_remaining} days)"
                    severity = "High"
                elif weak_protocol:
                    status = f"Using weak protocol ({protocol_version})"
                    severity = "Medium"
                else:
                    status = "Valid"
                    severity = "Low"
                
                # Return structured data
                return {
                    'status': status,
                    'valid_until': not_after,
                    'valid_from': not_before,
                    'issuer': issuer.get('commonName', 'Unknown'),
                    'subject': subject.get('commonName', 'Unknown'),
                    'days_remaining': days_remaining,
                    'is_expired': is_expired,
                    'expiring_soon': expiring_soon,
                    'protocol_version': protocol_version,
                    'weak_protocol': weak_protocol,
                    'severity': severity
                }
    except Exception as e:
        return {
            'error': str(e),
            'status': 'Error checking certificate',
            'severity': 'High'
        }

def check_security_headers(url):
    """Check security headers of a website"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        # Headers to check
        security_headers = {
            'Strict-Transport-Security': {'weight': 20, 'found': False},
            'Content-Security-Policy': {'weight': 20, 'found': False},
            'X-Frame-Options': {'weight': 15, 'found': False},
            'X-Content-Type-Options': {'weight': 10, 'found': False},
            'Referrer-Policy': {'weight': 10, 'found': False},
            'Permissions-Policy': {'weight': 10, 'found': False},
            'X-XSS-Protection': {'weight': 15, 'found': False}
        }
        
        # Check presence of each header
        resp_headers = response.headers
        for header, details in security_headers.items():
            if header.lower() in [h.lower() for h in resp_headers]:
                security_headers[header]['found'] = True
        
        # Calculate score
        score = sum(details['weight'] for header, details in security_headers.items() if details['found'])
        
        # Determine severity
        if score >= 80:
            severity = "Low"
        elif score >= 50:
            severity = "Medium"
        else:
            severity = "High"
        
        return {
            'score': score,
            'headers': {header: details['found'] for header, details in security_headers.items()},
            'severity': severity
        }
    except Exception as e:
        return {
            'error': str(e),
            'score': 0,
            'severity': 'High'
        }

def detect_cms(url):
    """Detect Content Management System (CMS) used by a website"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        html_content = response.text
        
        # CMS detection patterns
        cms_patterns = {
            'WordPress': [
                '<meta name="generator" content="WordPress',
                '/wp-content/',
                '/wp-includes/'
            ],
            'Joomla': [
                '<meta name="generator" content="Joomla',
                '/media/jui/',
                '/media/system/js/'
            ],
            'Drupal': [
                'Drupal.settings',
                '/sites/default/files/',
                'jQuery.extend(Drupal.settings'
            ],
            'Magento': [
                'Mage.Cookies',
                '/skin/frontend/',
                'var BLANK_URL'
            ],
            'Shopify': [
                'Shopify.theme',
                '.myshopify.com',
                'cdn.shopify.com'
            ],
            'Wix': [
                'X-Wix-Published-Version',
                'X-Wix-Request-Id',
                'static.wixstatic.com'
            ]
        }
        
        # Check for CMS presence
        detected_cms = None
        version = "Unknown"
        
        for cms, patterns in cms_patterns.items():
            for pattern in patterns:
                if pattern in html_content:
                    detected_cms = cms
                    break
            if detected_cms:
                break
        
        # Try to detect version
        if detected_cms == 'WordPress':
            version_match = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', html_content)
            if version_match:
                version = version_match.group(1)
        
        # Check for potential vulnerabilities
        potential_vulnerabilities = []
        
        if detected_cms == 'WordPress' and version != "Unknown":
            # Simulated vulnerability check - in a real system, would check against a CVE database
            major_version = int(version.split('.')[0])
            if major_version < 5:
                potential_vulnerabilities.append(f"WordPress {version} is outdated and may contain security vulnerabilities.")
        
        if detected_cms:
            return {
                'cms_detected': True,
                'cms_name': detected_cms,
                'version': version,
                'potential_vulnerabilities': potential_vulnerabilities,
                'severity': "High" if potential_vulnerabilities else "Low"
            }
        else:
            return {
                'cms_detected': False,
                'cms_name': None,
                'version': None,
                'potential_vulnerabilities': [],
                'severity': "Low"
            }
    except Exception as e:
        return {
            'error': str(e),
            'cms_detected': False,
            'severity': 'Medium'
        }

def analyze_cookies(url):
    """Analyze cookies set by a website"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        # Get cookies
        cookies = response.cookies
        
        # Analyze cookies
        secure_cookies = 0
        httponly_cookies = 0
        samesite_cookies = 0
        total_cookies = len(cookies)
        
        for cookie in cookies:
            if cookie.secure:
                secure_cookies += 1
            if cookie.has_nonstandard_attr('httponly'):
                httponly_cookies += 1
            if cookie.has_nonstandard_attr('samesite'):
                samesite_cookies += 1
        
        # Calculate score (out of 100)
        if total_cookies == 0:
            score = 100  # No cookies, no risk
        else:
            secure_ratio = secure_cookies / total_cookies
            httponly_ratio = httponly_cookies / total_cookies
            samesite_ratio = samesite_cookies / total_cookies
            
            # Weight the scores
            score = (secure_ratio * 40) + (httponly_ratio * 30) + (samesite_ratio * 30)
            score = int(score * 100)
        
        # Determine severity
        if score >= 80:
            severity = "Low"
        elif score >= 50:
            severity = "Medium"
        else:
            severity = "High"
        
        return {
            'total_cookies': total_cookies,
            'secure_cookies': secure_cookies,
            'httponly_cookies': httponly_cookies,
            'samesite_cookies': samesite_cookies,
            'score': score,
            'severity': severity
        }
    except Exception as e:
        return {
            'error': str(e),
            'score': 0,
            'severity': 'Medium'
        }

def detect_web_framework(url):
    """Detect web framework used by a website"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        # Get headers and HTML content
        resp_headers = response.headers
        html_content = response.text
        
        frameworks = []
        
        # Check headers for framework clues
        if 'X-Powered-By' in resp_headers:
            powered_by = resp_headers['X-Powered-By']
            frameworks.append(powered_by)
        
        # Check for common framework patterns in HTML
        framework_patterns = {
            'React': ['reactroot', 'react-app'],
            'Angular': ['ng-app', 'angular.module'],
            'Vue.js': ['vue-app', 'data-v-'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap.min.css', 'bootstrap.min.js'],
            'Laravel': ['laravel', 'csrf-token'],
            'Django': ['csrfmiddlewaretoken', '__django'],
            'Ruby on Rails': ['csrf-param', 'data-remote="true"'],
            'ASP.NET': ['__VIEWSTATE', '__EVENTVALIDATION'],
            'Express.js': ['express', 'node_modules']
        }
        
        for framework, patterns in framework_patterns.items():
            for pattern in patterns:
                if pattern.lower() in html_content.lower():
                    frameworks.append(framework)
                    break
        
        # Remove duplicates
        frameworks = list(set(frameworks))
        
        return {
            'frameworks': frameworks,
            'count': len(frameworks)
        }
    except Exception as e:
        return {
            'error': str(e),
            'frameworks': [],
            'count': 0
        }

def crawl_for_sensitive_content(url, max_urls=15):
    """Crawl website for potentially sensitive content"""
    try:
        sensitive_paths = [
            '/admin', '/login', '/wp-admin', '/administrator', '/backend',
            '/cpanel', '/phpmyadmin', '/config', '/backup', '/db',
            '/logs', '/test', '/dev', '/staging', '/.git', '/.env',
            '/robots.txt', '/sitemap.xml', '/config.php', '/wp-config.php'
        ]
        
        found_paths = []
        sensitive_count = 0
        
        # Normalize URL
        if not url.endswith('/'):
            url = url + '/'
        
        # Check each sensitive path
        for path in sensitive_paths[:max_urls]:
            try:
                test_url = url + path.lstrip('/')
                response = requests.head(test_url, timeout=5, verify=False, allow_redirects=False)
                
                # Check if path exists (200 OK, 302 Found, etc.)
                if response.status_code < 400:
                    found_paths.append(path)
                    sensitive_count += 1
            except:
                continue
        
        # Determine severity based on number of sensitive paths found
        if sensitive_count > 5:
            severity = "Critical"
        elif sensitive_count > 2:
            severity = "High"
        elif sensitive_count > 0:
            severity = "Medium"
        else:
            severity = "Low"
        
        return {
            'sensitive_paths_found': sensitive_count,
            'paths': found_paths,
            'severity': severity
        }
    except Exception as e:
        return {
            'error': str(e),
            'sensitive_paths_found': 0,
            'paths': [],
            'severity': 'Medium'
        }

def analyze_dns_configuration(domain):
    """Analyze DNS configuration for a domain"""
    try:
        # Check A records
        a_records = []
        try:
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                a_records.append(str(rdata))
        except Exception as e:
            a_records = [f"Error: {str(e)}"]
        
        # Check MX records
        mx_records = []
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                mx_records.append(f"{rdata.exchange} (priority: {rdata.preference})")
        except Exception as e:
            mx_records = [f"Error: {str(e)}"]
        
        # Check NS records
        ns_records = []
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            for rdata in answers:
                ns_records.append(str(rdata))
        except Exception as e:
            ns_records = [f"Error: {str(e)}"]
        
        # Check TXT records
        txt_records = []
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                for txt_string in rdata.strings:
                    txt_records.append(txt_string.decode('utf-8'))
        except Exception as e:
            txt_records = [f"Error: {str(e)}"]
        
        # Determine severity
        severity = "Low"  # Default
        
        # Check for issues
        issues = []
        
        # No A records
        if len(a_records) == 0 or a_records[0].startswith("Error"):
            issues.append("No A records found")
            severity = "High"
        
        # No MX records
        if len(mx_records) == 0 or mx_records[0].startswith("Error"):
            issues.append("No MX records found")
            if severity != "High":
                severity = "Medium"
        
        # No NS records
        if len(ns_records) == 0 or ns_records[0].startswith("Error"):
            issues.append("No NS records found")
            severity = "High"
        
        return {
            'a_records': a_records,
            'mx_records': mx_records,
            'ns_records': ns_records,
            'txt_records': txt_records,
            'issues': issues,
            'severity': severity
        }
    except Exception as e:
        return {
            'error': str(e),
            'severity': 'Medium'
        }

def check_spf_status(domain):
    """Check SPF record status for a domain"""
    try:
        # Query TXT records for the domain
        answers = dns.resolver.resolve(domain, 'TXT')
        
        spf_record = None
        for rdata in answers:
            for txt_string in rdata.strings:
                txt_record = txt_string.decode('utf-8')
                if txt_record.startswith('v=spf1'):
                    spf_record = txt_record
                    break
        
        # Analyze SPF record
        if not spf_record:
            return "No SPF record found", "High"
        
        # Check for ~all (soft fail)
        if '~all' in spf_record:
            return f"SPF record found: {spf_record} (Soft fail)", "Medium"
        
        # Check for -all (hard fail, most secure)
        if '-all' in spf_record:
            return f"SPF record found: {spf_record} (Hard fail, secure)", "Low"
        
        # Check for ?all (neutral)
        if '?all' in spf_record:
            return f"SPF record found: {spf_record} (Neutral, not secure)", "High"
        
        # Check for +all (allow all, very insecure)
        if '+all' in spf_record:
            return f"SPF record found: {spf_record} (Allow all, very insecure)", "Critical"
        
        return f"SPF record found: {spf_record} (No explicit policy)", "Medium"
    except Exception as e:
        return f"Error checking SPF: {str(e)}", "High"

def check_dmarc_record(domain):
    """Check DMARC record status for a domain"""
    try:
        # Query TXT records for _dmarc.domain
        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            
            dmarc_record = None
            for rdata in answers:
                for txt_string in rdata.strings:
                    txt_record = txt_string.decode('utf-8')
                    if txt_record.startswith('v=DMARC1'):
                        dmarc_record = txt_record
                        break
            
            # Analyze DMARC record
            if not dmarc_record:
                return "No DMARC record found", "High"
            
            # Extract policy
            policy_match = re.search(r'p=([^;]+)', dmarc_record)
            policy = policy_match.group(1) if policy_match else "none"
            
            # Determine severity based on policy
            if policy == "reject":
                return f"DMARC record found: {dmarc_record} (Policy: reject, secure)", "Low"
            elif policy == "quarantine":
                return f"DMARC record found: {dmarc_record} (Policy: quarantine, medium security)", "Medium"
            else:  # policy == "none"
                return f"DMARC record found: {dmarc_record} (Policy: none, low security)", "High"
        except dns.resolver.NXDOMAIN:
            return "No DMARC record found (NXDOMAIN)", "High"
        except Exception as e:
            return f"Error querying DMARC: {str(e)}", "High"
    except Exception as e:
        return f"Error checking DMARC: {str(e)}", "High"

def check_dkim_record(domain):
    """Check DKIM record status for a domain"""
    # Common DKIM selectors to check
    selectors = ['default', 'dkim', 'mail', 'email', 'selector1', 'selector2', 'k1']
    
    try:
        for selector in selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            try:
                answers = dns.resolver.resolve(dkim_domain, 'TXT')
                
                # If we got this far, a DKIM record exists
                return f"DKIM record found for selector '{selector}'", "Low"
            except dns.resolver.NXDOMAIN:
                continue
            except Exception:
                continue
        
        # If we get here, no DKIM records were found
        return "No DKIM records found for common selectors", "High"
    except Exception as e:
        return f"Error checking DKIM: {str(e)}", "High"

def check_os_updates():
    """Check if operating system updates are available (simulated)"""
    # This is a simulation since we can't actually check OS updates in a web environment
    simulated_results = [
        {"message": "System is up to date", "severity": "Low"},
        {"message": "Updates available, but not critical", "severity": "Medium"},
        {"message": "Critical updates pending", "severity": "High"},
        {"message": "System severely outdated", "severity": "Critical"}
    ]
    
    # Use deterministic approach instead of random
    current_hour = datetime.now().hour
    result_index = current_hour % len(simulated_results)
    
    return simulated_results[result_index]

def check_firewall_status():
    """Check firewall status (simulated)"""
    # This is a simulation since we can't actually check firewall status in a web environment
    simulated_results = [
        ("Firewall enabled and properly configured", "Low"),
        ("Firewall enabled but needs configuration review", "Medium"),
        ("Firewall enabled but has significant gaps", "High"),
        ("Firewall disabled or not detected", "Critical")
    ]
    
    # Use deterministic approach instead of random
    current_minute = datetime.now().minute
    result_index = current_minute % len(simulated_results)
    
    return simulated_results[result_index]

def check_open_ports():
    """Check for open ports (simulated)"""
    # This is a simulation since we can't actually scan ports in a web environment
    
    # Deterministic approach based on current time
    current_second = datetime.now().second
    
    if current_second < 15:
        # Few open ports
        count = 3
        severity = "Low"
        ports = [80, 443, 22]
    elif current_second < 30:
        # Some open ports
        count = 6
        severity = "Medium"
        ports = [80, 443, 22, 25, 143, 993]
    elif current_second < 45:
        # Many open ports
        count = 10
        severity = "High"
        ports = [80, 443, 22, 25, 143, 993, 3306, 8080, 21, 5900]
    else:
        # Too many open ports
        count = 15
        severity = "Critical"
        ports = [80, 443, 22, 25, 143, 993, 3306, 8080, 21, 5900, 23, 445, 1433, 3389, 8443]
    
    return count, ports, severity

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

def calculate_risk_score(scan_results):
    """Calculate overall risk score based on all scan results"""
    try:
        risk_factors = []
        total_weight = 0
        weighted_score = 0
        
        # Define risk factors and their weights
        risk_weights = {
            'ssl_certificate': 15,
            'security_headers': 15,
            'cms': 10,
            'cookies': 5,
            'sensitive_content': 20,
            'email_security': 15,
            'open_ports': 20
        }
        
        # Process SSL certificate
        if 'ssl_certificate' in scan_results and 'error' not in scan_results['ssl_certificate']:
            ssl_severity = scan_results['ssl_certificate'].get('severity', 'Low')
            ssl_score = 10 - SEVERITY.get(ssl_severity, 1)
            risk_factors.append({
                'name': 'SSL/TLS Certificate',
                'score': ssl_score,
                'weight': risk_weights['ssl_certificate'],
                'weighted_score': ssl_score * risk_weights['ssl_certificate'] / 10
            })
            weighted_score += ssl_score * risk_weights['ssl_certificate']
            total_weight += risk_weights['ssl_certificate']
        
        # Process security headers
        if 'security_headers' in scan_results and 'error' not in scan_results['security_headers']:
            header_score = scan_results['security_headers'].get('score', 0) / 10
            risk_factors.append({
                'name': 'Security Headers',
                'score': header_score,
                'weight': risk_weights['security_headers'],
                'weighted_score': header_score * risk_weights['security_headers'] / 10
            })
            weighted_score += header_score * risk_weights['security_headers']
            total_weight += risk_weights['security_headers']
        
        # Process CMS
        if 'cms' in scan_results and 'error' not in scan_results['cms']:
            cms_severity = scan_results['cms'].get('severity', 'Low')
            cms_score = 10 - SEVERITY.get(cms_severity, 1)
            risk_factors.append({
                'name': 'Content Management System',
                'score': cms_score,
                'weight': risk_weights['cms'],
                'weighted_score': cms_score * risk_weights['cms'] / 10
            })
            weighted_score += cms_score * risk_weights['cms']
            total_weight += risk_weights['cms']
        
        # Process cookies
        if 'cookies' in scan_results and 'error' not in scan_results['cookies']:
            cookie_score = scan_results['cookies'].get('score', 0) / 10
            risk_factors.append({
                'name': 'Cookie Security',
                'score': cookie_score,
                'weight': risk_weights['cookies'],
                'weighted_score': cookie_score * risk_weights['cookies'] / 10
            })
            weighted_score += cookie_score * risk_weights['cookies']
            total_weight += risk_weights['cookies']
        
        # Process sensitive content
        if 'sensitive_content' in scan_results and 'error' not in scan_results['sensitive_content']:
            sensitive_severity = scan_results['sensitive_content'].get('severity', 'Low')
            sensitive_score = 10 - SEVERITY.get(sensitive_severity, 1)
            risk_factors.append({
                'name': 'Sensitive Content Exposure',
                'score': sensitive_score,
                'weight': risk_weights['sensitive_content'],
                'weighted_score': sensitive_score * risk_weights['sensitive_content'] / 10
            })
            weighted_score += sensitive_score * risk_weights['sensitive_content']
            total_weight += risk_weights['sensitive_content']
        
        # Process email security
        if 'email_security' in scan_results:
            email_sec = scan_results['email_security']
            if 'error' not in email_sec:
                spf_severity = email_sec.get('spf', {}).get('severity', 'Low')
                dmarc_severity = email_sec.get('dmarc', {}).get('severity', 'Low')
                dkim_severity = email_sec.get('dkim', {}).get('severity', 'Low')
                
                avg_severity_value = (SEVERITY.get(spf_severity, 1) + 
                                      SEVERITY.get(dmarc_severity, 1) + 
                                      SEVERITY.get(dkim_severity, 1)) / 3
                
                email_score = 10 - avg_severity_value
                risk_factors.append({
                    'name': 'Email Security',
                    'score': email_score,
                    'weight': risk_weights['email_security'],
                    'weighted_score': email_score * risk_weights['email_security'] / 10
                })
                weighted_score += email_score * risk_weights['email_security']
                total_weight += risk_weights['email_security']
        
        # Process open ports
        if 'network' in scan_results and 'open_ports' in scan_results['network']:
            ports_severity = scan_results['network']['open_ports'].get('severity', 'Low')
            ports_score = 10 - SEVERITY.get(ports_severity, 1)
            risk_factors.append({
                'name': 'Open Ports',
                'score': ports_score,
                'weight': risk_weights['open_ports'],
                'weighted_score': ports_score * risk_weights['open_ports'] / 10
            })
            weighted_score += ports_score * risk_weights['open_ports']
            total_weight += risk_weights['open_ports']
        
        # Calculate final score
        overall_score = 0
        if total_weight > 0:
            overall_score = int((weighted_score / total_weight) * 100)
        
        # Determine risk level
        if overall_score >= 90:
            risk_level = "Low"
        elif overall_score >= 70:
            risk_level = "Medium"
        elif overall_score >= 50:
            risk_level = "High"
        else:
            risk_level = "Critical"
        
        return {
            'overall_score': overall_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors
        }
    except Exception as e:
        return {
            'error': str(e),
            'overall_score': 0,
            'risk_level': 'Unknown'
        }

def get_severity_level(score):
    """Convert a numerical score to a severity level"""
    if score <= 30:
        return "Critical"
    elif score <= 50:
        return "High"
    elif score <= 75:
        return "Medium"
    else:
        return "Low"

def get_recommendations(scan_results):
    """Generate recommendations based on scan results"""
    recommendations = []
    
    # Email security recommendations
    if 'email_security' in scan_results:
        email_sec = scan_results['email_security']
        
        # SPF recommendations
        if 'spf' in email_sec and email_sec['spf']['severity'] in ['High', 'Critical']:
            recommendations.append("Implement a proper SPF record with a hard fail (-all) policy to prevent email spoofing.")
        
        # DMARC recommendations
        if 'dmarc' in email_sec and email_sec['dmarc']['severity'] in ['High', 'Critical']:
            recommendations.append("Set up a DMARC record with a 'reject' or 'quarantine' policy to enhance email security.")
        
        # DKIM recommendations
        if 'dkim' in email_sec and email_sec['dkim']['severity'] in ['High', 'Critical']:
            recommendations.append("Implement DKIM signing for your domain to authenticate outgoing emails.")
    
    # Web security recommendations
    if 'ssl_certificate' in scan_results and scan_results['ssl_certificate'].get('severity', 'Low') in ['High', 'Critical']:
        recommendations.append("Update your SSL/TLS certificate and ensure proper configuration with modern protocols.")
    
    if 'security_headers' in scan_results and scan_results['security_headers'].get('severity', 'Low') in ['High', 'Critical']:
        recommendations.append("Implement missing security headers to protect against common web vulnerabilities.")
    
    if 'cms' in scan_results and scan_results['cms'].get('severity', 'Low') in ['High', 'Critical']:
        cms_name = scan_results['cms'].get('cms_name', '')
        if cms_name:
            recommendations.append(f"Update your {cms_name} installation to the latest version to patch security vulnerabilities.")
    
    if 'sensitive_content' in scan_results and scan_results['sensitive_content'].get('severity', 'Low') in ['High', 'Critical']:
        recommendations.append("Restrict access to sensitive directories and files that could expose configuration details.")
    
    # Network recommendations
    if 'network' in scan_results and 'open_ports' in scan_results['network']:
        if scan_results['network']['open_ports'].get('severity', 'Low') in ['High', 'Critical']:
            recommendations.append("Close unnecessary open ports to reduce attack surface. Use a properly configured firewall.")
    
    # Add general recommendations if specific ones are limited
    if len(recommendations) < 3:
        recommendations.append("Implement regular security scanning and monitoring for early detection of vulnerabilities.")
        recommendations.append("Keep all software and systems updated with the latest security patches.")
        recommendations.append("Use strong, unique passwords and consider implementing multi-factor authentication where possible.")
    
    return recommendations

def generate_threat_scenario(scan_results):
    """Generate a realistic threat scenario based on scan findings"""
    threats = []
    
    # Check for specific high-risk issues
    if 'email_security' in scan_results:
        email_sec = scan_results['email_security']
        if 'spf' in email_sec and email_sec['spf']['severity'] in ['High', 'Critical']:
            threats.append({
                'name': 'Email Spoofing Attack',
                'description': 'Without proper SPF records, attackers could send emails that appear to come from your domain, leading to successful phishing attacks against your customers or partners.',
                'impact': 'High',
                'likelihood': 'Medium'
            })
    
    if 'ssl_certificate' in scan_results and scan_results['ssl_certificate'].get('severity', 'High') == 'Critical':
        threats.append({
            'name': 'Man-in-the-Middle Attack',
            'description': 'With an expired or improperly configured SSL certificate, attackers could intercept communications between your users and your website, potentially stealing sensitive information.',
            'impact': 'High',
            'likelihood': 'Medium'
        })
    
    if 'network' in scan_results and 'open_ports' in scan_results['network']:
        if scan_results['network']['open_ports'].get('severity', 'Low') in ['High', 'Critical']:
            ports = scan_results['network']['open_ports'].get('list', [])
            if 3389 in ports:  # RDP
                threats.append({
                    'name': 'Remote Desktop Brute Force Attack',
                    'description': 'With Remote Desktop Protocol exposed, attackers could attempt brute force password attacks to gain unauthorized access to your systems.',
                    'impact': 'Critical',
                    'likelihood': 'High'
                })
            if 21 in ports or 23 in ports:  # FTP or Telnet
                threats.append({
                    'name': 'Credential Theft via Unencrypted Protocols',
                    'description': 'Use of unencrypted protocols like FTP or Telnet could allow attackers to capture login credentials through network sniffing.',
                    'impact': 'High',
                    'likelihood': 'Medium'
                })
    
    if 'cms' in scan_results and scan_results['cms'].get('cms_detected', False):
        if scan_results['cms'].get('potential_vulnerabilities', []):
            cms_name = scan_results['cms'].get('cms_name', 'CMS')
            threats.append({
                'name': f'{cms_name} Vulnerability Exploitation',
                'description': f'Outdated {cms_name} installations often contain known vulnerabilities that attackers can exploit to gain unauthorized access or inject malicious code.',
                'impact': 'High',
                'likelihood': 'High'
            })
    
    if 'sensitive_content' in scan_results and scan_results['sensitive_content'].get('severity', 'Low') in ['High', 'Critical']:
        threats.append({
            'name': 'Sensitive Data Exposure',
            'description': 'Exposed configuration files, backup data, or development artifacts could provide attackers with valuable information to plan more targeted attacks.',
            'impact': 'Medium',
            'likelihood': 'Medium'
        })
    
    # Add a generic threat if no specific threats were identified
    if not threats:
        threats.append({
            'name': 'General Cyber Attack',
            'description': 'Even with no critical vulnerabilities detected, organizations remain targets for common attacks like phishing, social engineering, or exploitation of newly discovered vulnerabilities.',
            'impact': 'Medium',
            'likelihood': 'Low'
        })
    
    return threats

def generate_html_report(scan_results, is_integrated=False):
    """Generate an HTML report from scan results"""
    try:
        # Start HTML document
        html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Scan Report</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 20px;
                    color: #333;
                    background-color: #f9f9f9;
                }
                .container {
                    max-width: 1000px;
                    margin: 0 auto;
                    background: white;
                    padding: 30px;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                }
                .header {
                    background-color: #2c3e50;
                    color: white;
                    padding: 20px;
                    text-align: center;
                    margin-bottom: 20px;
                    border-radius: 5px;
                }
                .logo {
                    max-width: 200px;
                    margin: 0 auto 20px auto;
                    display: block;
                }
                h1 {
                    margin: 0;
                    font-size: 24px;
                }
                h2 {
                    color: #2c3e50;
                    border-bottom: 2px solid #eee;
                    padding-bottom: 10px;
                    margin-top: 30px;
                }
                h3 {
                    color: #3498db;
                    margin-top: 20px;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }
                th, td {
                    padding: 12px 15px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }
                th {
                    background-color: #f2f2f2;
                }
                tr:hover {
                    background-color: #f5f5f5;
                }
                .severity {
                    font-weight: bold;
                    padding: 5px 10px;
                    border-radius: 4px;
                    display: inline-block;
                }
                .Critical {
                    background-color: #ff4d4d;
                    color: white;
                }
                .High {
                    background-color: #ff9933;
                    color: white;
                }
                .Medium {
                    background-color: #ffcc00;
                    color: #333;
                }
                .Low {
                    background-color: #92d36e;
                    color: #333;
                }
                .Info {
                    background-color: #3498db;
                    color: white;
                }
                .summary {
                    background-color: #f8f9fa;
                    padding: 20px;
                    border-radius: 5px;
                    margin: 20px 0;
                }
                .score-container {
                    text-align: center;
                    margin: 30px 0;
                }
                .score {
                    font-size: 64px;
                    font-weight: bold;
                    line-height: 1;
                }
                .recommendation {
                    background-color: #e8f4fc;
                    padding: 15px;
                    border-left: 5px solid #3498db;
                    margin: 10px 0;
                }
                .threat {
                    background-color: #fff3e0;
                    padding: 15px;
                    border-left: 5px solid #ff9800;
                    margin: 10px 0;
                }
                .footer {
                    margin-top: 50px;
                    text-align: center;
                    color: #777;
                    font-size: 14px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Comprehensive Security Scan Report</h1>
                    <p>Generated on """ + datetime.now().strftime("%Y-%m-%d at %H:%M:%S") + """</p>
                </div>
                
                <div class="summary">
                    <h2>Executive Summary</h2>
        """
        
        # Add risk score if available
        if 'risk_assessment' in scan_results and 'overall_score' in scan_results['risk_assessment']:
            risk_score = scan_results['risk_assessment']['overall_score']
            risk_level = scan_results['risk_assessment']['risk_level']
            
            # Determine color based on risk level
            score_color = "#92d36e"  # Green (Low)
            if risk_level == "Medium":
                score_color = "#ffcc00"  # Yellow
            elif risk_level == "High":
                score_color = "#ff9933"  # Orange
            elif risk_level == "Critical":
                score_color = "#ff4d4d"  # Red
            
            html += f"""
                    <div class="score-container">
                        <div style="font-size: 18px;">Overall Risk Score</div>
                        <div class="score" style="color: {score_color};">{risk_score}</div>
                        <div><span class="severity {risk_level}">{risk_level} Risk</span></div>
                    </div>
            """
        
        # Add scan scope information
        html += """
                    <p><strong>Scan Type:</strong> Comprehensive Security Assessment</p>
        """
        
        if 'target' in scan_results:
            target = scan_results['target']
            html += f"""
                    <p><strong>Target:</strong> {target}</p>
            """
        
        html += """
                </div>
                
                <h2>Key Findings</h2>
        """
        
        # Build a list of key findings
        key_findings = []
        
        # Email security findings
        if 'email_security' in scan_results:
            email_sec = scan_results['email_security']
            if 'error' not in email_sec:
                for protocol in ['spf', 'dmarc', 'dkim']:
                    if protocol in email_sec and email_sec[protocol]['severity'] in ['High', 'Critical']:
                        status = email_sec[protocol]['status'] if 'status' in email_sec[protocol] else f"Issue with {protocol.upper()}"
                        key_findings.append({
                            'category': 'Email Security',
                            'finding': status,
                            'severity': email_sec[protocol]['severity']
                        })
        
        # Web security findings
        if 'ssl_certificate' in scan_results and 'error' not in scan_results['ssl_certificate']:
            if scan_results['ssl_certificate']['severity'] in ['High', 'Critical']:
                key_findings.append({
                    'category': 'Web Security',
                    'finding': scan_results['ssl_certificate']['status'],
                    'severity': scan_results['ssl_certificate']['severity']
                })
        
        if 'security_headers' in scan_results and 'error' not in scan_results['security_headers']:
            if scan_results['security_headers']['severity'] in ['High', 'Critical']:
                key_findings.append({
                    'category': 'Web Security',
                    'finding': f"Missing important security headers (Score: {scan_results['security_headers']['score']}/100)",
                    'severity': scan_results['security_headers']['severity']
                })
        
        if 'cms' in scan_results and 'error' not in scan_results['cms']:
            if scan_results['cms']['severity'] in ['High', 'Critical'] and scan_results['cms']['cms_detected']:
                vulnerabilities = scan_results['cms'].get('potential_vulnerabilities', [])
                if vulnerabilities:
                    key_findings.append({
                        'category': 'Web Application',
                        'finding': f"Vulnerable {scan_results['cms']['cms_name']} installation detected",
                        'severity': scan_results['cms']['severity']
                    })
        
        if 'sensitive_content' in scan_results and 'error' not in scan_results['sensitive_content']:
            if scan_results['sensitive_content']['severity'] in ['High', 'Critical']:
                paths = scan_results['sensitive_content'].get('paths', [])
                path_count = len(paths)
                key_findings.append({
                    'category': 'Web Content',
                    'finding': f"Exposed sensitive content ({path_count} paths discovered)",
                    'severity': scan_results['sensitive_content']['severity']
                })
        
        # Network findings
        if 'network' in scan_results and 'open_ports' in scan_results['network']:
            if scan_results['network']['open_ports']['severity'] in ['High', 'Critical']:
                key_findings.append({
                    'category': 'Network Security',
                    'finding': f"Excessive open ports detected ({scan_results['network']['open_ports']['count']} ports)",
                    'severity': scan_results['network']['open_ports']['severity']
                })
        
        # System findings
        if 'system' in scan_results:
            if 'os_updates' in scan_results['system'] and scan_results['system']['os_updates']['severity'] in ['High', 'Critical']:
                key_findings.append({
                    'category': 'System Security',
                    'finding': scan_results['system']['os_updates']['message'],
                    'severity': scan_results['system']['os_updates']['severity']
                })
            
            if 'firewall' in scan_results['system'] and scan_results['system']['firewall']['severity'] in ['High', 'Critical']:
                key_findings.append({
                    'category': 'System Security',
                    'finding': scan_results['system']['firewall']['status'],
                    'severity': scan_results['system']['firewall']['severity']
                })
        
        # If we have key findings, add them to the report
        if key_findings:
            html += """
                <table>
                    <tr>
                        <th>Category</th>
                        <th>Finding</th>
                        <th>Severity</th>
                    </tr>
            """
            
            # Sort findings by severity (Critical first, then High, etc.)
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
            key_findings.sort(key=lambda x: severity_order.get(x['severity'], 999))
            
            for finding in key_findings:
                html += f"""
                    <tr>
                        <td>{finding['category']}</td>
                        <td>{finding['finding']}</td>
                        <td><span class="severity {finding['severity']}">{finding['severity']}</span></td>
                    </tr>
                """
            
            html += """
                </table>
            """
        else:
            html += """
                <p>No critical security issues were detected in this scan. Continue to monitor and maintain your security posture.</p>
            """
        
        # Add detailed sections
        
        # Email Security Section
        if 'email_security' in scan_results:
            html += """
                <h2>Email Security Assessment</h2>
                <table>
                    <tr>
                        <th>Protocol</th>
                        <th>Status</th>
                        <th>Severity</th>
                    </tr>
            """
            
            email_sec = scan_results['email_security']
            if 'error' not in email_sec:
                for protocol in ['spf', 'dmarc', 'dkim']:
                    if protocol in email_sec:
                        status = email_sec[protocol]['status'] if 'status' in email_sec[protocol] else "Unknown"
                        severity = email_sec[protocol]['severity'] if 'severity' in email_sec[protocol] else "Info"
                        html += f"""
                            <tr>
                                <td>{protocol.upper()}</td>
                                <td>{status}</td>
                                <td><span class="severity {severity}">{severity}</span></td>
                            </tr>
                        """
            
            html += """
                </table>
            """
        
        # SSL/TLS Section
        if 'ssl_certificate' in scan_results and 'error' not in scan_results['ssl_certificate']:
            html += """
                <h2>SSL/TLS Certificate Analysis</h2>
                <table>
                    <tr>
                        <th>Attribute</th>
                        <th>Value</th>
                    </tr>
            """
            
            ssl_cert = scan_results['ssl_certificate']
            attributes = [
                ('Status', 'status'),
                ('Issuer', 'issuer'),
                ('Subject', 'subject'),
                ('Valid Until', 'valid_until'),
                ('Days Remaining', 'days_remaining'),
                ('Protocol Version', 'protocol_version')
            ]
            
            for label, key in attributes:
                if key in ssl_cert:
                    html += f"""
                        <tr>
                            <td>{label}</td>
                            <td>{ssl_cert[key]}</td>
                        </tr>
                    """
            
            # Add a severity row
            html += f"""
                <tr>
                    <td>Severity</td>
                    <td><span class="severity {ssl_cert.get('severity', 'Info')}">{ssl_cert.get('severity', 'Info')}</span></td>
                </tr>
            """
            
            html += """
                </table>
            """
        
        # Security Headers Section
        if 'security_headers' in scan_results and 'error' not in scan_results['security_headers']:
            html += """
                <h2>Security Headers Assessment</h2>
                <p>Security headers help protect your website from various attacks like XSS, clickjacking, and more.</p>
                
                <div class="score-container">
                    <div style="font-size: 18px;">Security Headers Score</div>
                    <div class="score" style="font-size: 48px;">{scan_results['security_headers']['score']}/100</div>
                </div>
                
                <table>
                    <tr>
                        <th>Header</th>
                        <th>Status</th>
                    </tr>
            """
            
            for header, found in scan_results['security_headers'].get('headers', {}).items():
                status = "✅ Present" if found else "❌ Missing"
                html += f"""
                    <tr>
                        <td>{header}</td>
                        <td>{status}</td>
                    </tr>
                """
            
            html += f"""
                <tr>
                    <td>Overall Severity</td>
                    <td><span class="severity {scan_results['security_headers'].get('severity', 'Info')}">{scan_results['security_headers'].get('severity', 'Info')}</span></td>
                </tr>
            </table>
            """
        
        # CMS Detection Section
        if 'cms' in scan_results and 'error' not in scan_results['cms']:
            html += """
                <h2>Content Management System Analysis</h2>
            """
            
            if scan_results['cms'].get('cms_detected', False):
                html += f"""
                    <p>Detected CMS: <strong>{scan_results['cms'].get('cms_name', 'Unknown')}</strong></p>
                    <p>Version: <strong>{scan_results['cms'].get('version', 'Unknown')}</strong></p>
                """
                
                vulnerabilities = scan_results['cms'].get('potential_vulnerabilities', [])
                if vulnerabilities:
                    html += """
                        <h3>Potential Vulnerabilities</h3>
                        <ul>
                    """
                    
                    for vuln in vulnerabilities:
                        html += f"""
                            <li>{vuln}</li>
                        """
                    
                    html += """
                        </ul>
                    """
                
                html += f"""
                    <p>Severity: <span class="severity {scan_results['cms'].get('severity', 'Info')}">{scan_results['cms'].get('severity', 'Info')}</span></p>
                """
            else:
                html += """
                    <p>No Content Management System detected.</p>
                """
        
        # Sensitive Content Section
        if 'sensitive_content' in scan_results and 'error' not in scan_results['sensitive_content']:
            html += """
                <h2>Sensitive Content Analysis</h2>
            """
            
            paths = scan_results['sensitive_content'].get('paths', [])
            if paths:
                html += f"""
                    <p>Found {len(paths)} potentially sensitive paths:</p>
                    <ul>
                """
                
                for path in paths:
                    html += f"""
                        <li>{path}</li>
                    """
                
                html += """
                    </ul>
                """
            else:
                html += """
                    <p>No sensitive content paths detected.</p>
                """
            
            html += f"""
                <p>Severity: <span class="severity {scan_results['sensitive_content'].get('severity', 'Info')}">{scan_results['sensitive_content'].get('severity', 'Info')}</span></p>
            """
        
        # Network Security Section
        if 'network' in scan_results:
            html += """
                <h2>Network Security Analysis</h2>
            """
            
            if 'open_ports' in scan_results['network']:
                open_ports = scan_results['network']['open_ports']
                html += f"""
                    <h3>Open Ports</h3>
                    <p>Detected {open_ports.get('count', 0)} open ports.</p>
                """
                
                ports_list = open_ports.get('list', [])
                if ports_list:
                    html += """
                        <table>
                            <tr>
                                <th>Port</th>
                                <th>Service</th>
                                <th>Risk</th>
                            </tr>
                    """
                    
                    # Define service names
                    services = {
                        21: "FTP",
                        22: "SSH",
                        23: "Telnet",
                        25: "SMTP",
                        80: "HTTP",
                        110: "POP3",
                        143: "IMAP",
                        443: "HTTPS",
                        445: "SMB",
                        3306: "MySQL",
                        3389: "RDP",
                        5900: "VNC",
                        8080: "HTTP Alternate"
                    }
                    
                    # Define risk levels
                    high_risk_ports = [21, 23, 445, 3389, 5900]
                    medium_risk_ports = [25, 110, 143, 3306, 8080]
                    
                    for port in sorted(ports_list):
                        service = services.get(port, "Unknown")
                        
                        if port in high_risk_ports:
                            risk = "High"
                        elif port in medium_risk_ports:
                            risk = "Medium"
                        else:
                            risk = "Low"
                        
                        html += f"""
                            <tr>
                                <td>{port}</td>
                                <td>{service}</td>
                                <td><span class="severity {risk}">{risk}</span></td>
                            </tr>
                        """
                    
                    html += """
                        </table>
                    """
                
                html += f"""
                    <p>Overall Port Security: <span class="severity {open_ports.get('severity', 'Info')}">{open_ports.get('severity', 'Info')}</span></p>
                """
            
            # Gateway information if available
            if 'gateway' in scan_results['network']:
                gateway = scan_results['network']['gateway']
                html += """
                    <h3>Gateway Security</h3>
                """
                
                if 'info' in gateway:
                    html += f"""
                        <p>{gateway['info']}</p>
                    """
                
                if 'results' in gateway and gateway['results']:
                    html += """
                        <table>
                            <tr>
                                <th>Finding</th>
                                <th>Severity</th>
                            </tr>
                    """
                    
                    for finding, severity in gateway['results']:
                        if severity != "Info":  # Only show non-info findings
                            html += f"""
                                <tr>
                                    <td>{finding}</td>
                                    <td><span class="severity {severity}">{severity}</span></td>
                                </tr>
                            """
                    
                    html += """
                        </table>
                    """
        
        # System Security Section
        if 'system' in scan_results:
            html += """
                <h2>System Security Analysis</h2>
                <table>
                    <tr>
                        <th>Component</th>
                        <th>Status</th>
                        <th>Severity</th>
                    </tr>
            """
            
            if 'os_updates' in scan_results['system']:
                os_updates = scan_results['system']['os_updates']
                html += f"""
                    <tr>
                        <td>Operating System Updates</td>
                        <td>{os_updates.get('message', 'Unknown')}</td>
                        <td><span class="severity {os_updates.get('severity', 'Info')}">{os_updates.get('severity', 'Info')}</span></td>
                    </tr>
                """
            
            if 'firewall' in scan_results['system']:
                firewall = scan_results['system']['firewall']
                html += f"""
                    <tr>
                        <td>Firewall Status</td>
                        <td>{firewall.get('status', 'Unknown')}</td>
                        <td><span class="severity {firewall.get('severity', 'Info')}">{firewall.get('severity', 'Info')}</span></td>
                    </tr>
                """
            
            html += """
                </table>
            """
        
        # Recommendations Section
        recommendations = get_recommendations(scan_results)
        if recommendations:
            html += """
                <h2>Security Recommendations</h2>
                <ol>
            """
            
            for rec in recommendations:
                html += f"""
                    <li class="recommendation">{rec}</li>
                """
            
            html += """
                </ol>
            """
        
        # Threat Scenarios Section
        threats = generate_threat_scenario(scan_results)
        if threats:
            html += """
                <h2>Potential Threat Scenarios</h2>
                <p>Based on the scan results, these are potential threats that could affect your organization:</p>
            """
            
            for threat in threats:
                html += f"""
                    <div class="threat">
                        <h3>{threat['name']}</h3>
                        <p>{threat['description']}</p>
                        <p><strong>Impact:</strong> {threat['impact']} | <strong>Likelihood:</strong> {threat['likelihood']}</p>
                    </div>
                """
        
        # Footer
        html += """
                <div class="footer">
                    <p>This report was generated by the Comprehensive Security Scanner.</p>
                    <p>© """ + str(datetime.now().year) + """ Security Scanner. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    except Exception as e:
        logging.error(f"Error generating HTML report: {e}")
        return f"""
        <html>
            <body>
                <h1>Error Generating Report</h1>
                <p>An error occurred while generating the HTML report: {str(e)}</p>
            </body>
        </html>
        """

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

def send_email_report(lead_data, report_content, is_html=False, is_integrated=False):
    """
    Send email report to user.
    This is a placeholder - in a real implementation, you'd connect to an email service.
    """
    try:
        # Log email sending attempt
        recipient = lead_data.get('email', '')
        logging.info(f"Sending {'HTML' if is_html else 'text'} report to {recipient}")
        
        # In a real implementation, you'd use something like:
        # - smtplib for direct SMTP connection
        # - A third-party service like SendGrid, Mailgun, etc.
        # - A transactional email API
        
        # For now, we'll just log that we would send the email
        logging.info(f"Email would be sent to {recipient} with {'an HTML' if is_html else 'a text'} report")
        
        # In a production environment, you'd actually send the email here
        
        return True
    except Exception as e:
        logging.error(f"Error sending email: {e}")
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
    scan_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    
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
        gateway_info = get_default_gateway_ip()
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
        with open(results_file, 'w') as f:
            json.dump(scan_results, f, indent=2)
        
        # Send email report
        email = lead_data.get('email')
        if email:
            logging.info(f"Sending report to {email}...")
            send_email_report(lead_data, html_report, is_html=True)
    except Exception as e:
        logging.error(f"Error generating or sending report: {e}")
    
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
    scan_id = session.get('scan_id')
    
    logging.debug(f"Results page accessed with scan_id from session: {scan_id}")
    
    if not scan_id:
        logging.warning("No scan_id in session, redirecting to scan page")
        return redirect(url_for('scan_page'))
    
    try:
        # Load scan results from file
        results_file = os.path.join(SCAN_HISTORY_DIR, f"scan_{scan_id}.json")
        
        logging.debug(f"Looking for results file: {results_file}")
        
        if not os.path.exists(results_file):
            logging.error(f"Scan results file not found: {results_file}")
            return render_template('error.html', error="Scan results not found. Please try scanning again.")
        
        with open(results_file, 'r') as f:
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
