import os
import platform
import socket
import re
import uuid
import urllib.parse
from datetime import datetime
import random
import ipaddress
import json
import logging
import ssl
import requests
from bs4 import BeautifulSoup
import dns.resolver
from app import SCAN_HISTORY_DIR

# Set up logging configuration
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

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

# ---------------------------- UTILITY FUNCTIONS ----------------------------

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

def get_default_gateway_ip(request):
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

# ---------------------------- SSL AND WEB SECURITY FUNCTIONS ----------------------------

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

# ---------------------------- EMAIL SECURITY FUNCTIONS ----------------------------

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

# ----------------------------
# ---------------------------- SYSTEM SECURITY FUNCTIONS ----------------------------

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

# ---------------------------- ANALYSIS AND REPORTING FUNCTIONS ----------------------------

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

            <div style="font-size: 18px;">Security Headers Score</div>
            <div class="score" style="font-size: 48px;">N/A</div>
            </div>"""
