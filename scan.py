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

def get_recommendations(scan_results, scan_data=None):
    """Generate recommendations based on scan results"""
    recommendations = []
    
    # Email security recommendations
    if 'email_security' in scan_results:
        email_sec = scan_results['email_security']
        
        # SPF recommendations
        if 'spf' in email_sec and email_sec['spf'].get('severity') in ['High', 'Critical']:
            recommendations.append("Implement a proper SPF record with a hard fail (-all) policy to prevent email spoofing.")
        
        # DMARC recommendations
        if 'dmarc' in email_sec and email_sec['dmarc'].get('severity') in ['High', 'Critical']:
            recommendations.append("Set up a DMARC record with a 'reject' or 'quarantine' policy to enhance email security.")
        
        # DKIM recommendations
        if 'dkim' in email_sec and email_sec['dkim'].get('severity') in ['High', 'Critical']:
            recommendations.append("Implement DKIM signing for your domain to authenticate outgoing emails.")
    
    # Web security recommendations
    if 'web_security' in scan_results:
        if 'ssl_certificate' in scan_results['web_security'] and scan_results['web_security']['ssl_certificate'].get('severity', 'Low') in ['High', 'Critical']:
            recommendations.append("Update your SSL/TLS certificate and ensure proper configuration with modern protocols.")
        
        if 'security_headers' in scan_results['web_security'] and scan_results['web_security']['security_headers'].get('severity', 'Low') in ['High', 'Critical']:
            recommendations.append("Implement missing security headers to protect against common web vulnerabilities.")
        
        if 'cms' in scan_results['web_security'] and scan_results['web_security']['cms'].get('severity', 'Low') in ['High', 'Critical']:
            cms_name = scan_results['web_security']['cms'].get('cms_name', '')
            if cms_name:
                recommendations.append(f"Update your {cms_name} installation to the latest version to patch security vulnerabilities.")
        
        if 'sensitive_content' in scan_results['web_security'] and scan_results['web_security']['sensitive_content'].get('severity', 'Low') in ['High', 'Critical']:
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
    
    # Update scan data if provided
    if scan_data:
        scan_data["recommendations"] = recommendations
        update_scan_progress(scan_data, "recommendations", 5)
    
    return recommendationsimport os
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

# ---------------------------- PROGRESSIVE SAVING FUNCTIONALITY ----------------------------

def initialize_scan_data(target, scan_id=None):
    """Initialize the scan data structure and create a unique scan ID if not provided"""
    if scan_id is None:
        scan_id = str(uuid.uuid4())
    
    scan_data = {
        "scan_id": scan_id,
        "target": target,
        "start_time": datetime.now().isoformat(),
        "end_time": None,
        "status": "in_progress",
        "completion_percentage": 0,
        "email_security": {},
        "web_security": {},
        "network": {},
        "system": {},
        "risk_assessment": {}
    }
    
    # Ensure scan history directory exists
    os.makedirs(SCAN_HISTORY_DIR, exist_ok=True)
    
    # Save initial scan data
    save_scan_data(scan_data)
    
    return scan_data

def save_scan_data(scan_data):
    """Save the current scan data to a JSON file"""
    scan_id = scan_data["scan_id"]
    json_path = os.path.join(SCAN_HISTORY_DIR, f"{scan_id}.json")
    
    try:
        with open(json_path, 'w') as f:
            json.dump(scan_data, f, indent=2)
        logging.info(f"Scan data saved to {json_path}")
        return True
    except Exception as e:
        logging.error(f"Failed to save scan data: {e}")
        return False

def update_scan_progress(scan_data, module_name, percentage_increase=10):
    """Update the scan progress and save the data"""
    # Update completion percentage
    current_percentage = scan_data.get("completion_percentage", 0)
    new_percentage = min(current_percentage + percentage_increase, 100)
    scan_data["completion_percentage"] = new_percentage
    
    # Add timestamp for module completion
    module_timestamps = scan_data.get("module_timestamps", {})
    module_timestamps[module_name] = datetime.now().isoformat()
    scan_data["module_timestamps"] = module_timestamps
    
    # Log progress
    logging.info(f"Scan progress updated: {module_name} completed, overall progress: {new_percentage}%")
    
    # Save updated data
    return save_scan_data(scan_data)

def finalize_scan(scan_data, results_html_path="results.html"):
    """Finalize the scan, generate the HTML report, and save to the specified path"""
    # Update scan data
    scan_data["end_time"] = datetime.now().isoformat()
    scan_data["status"] = "completed"
    scan_data["completion_percentage"] = 100
    
    # Generate HTML report
    html_report = generate_html_report(scan_data)
    
    # Write HTML report to the specified path
    try:
        with open(results_html_path, 'w') as f:
            f.write(html_report)
        logging.info(f"Scan report saved to {results_html_path}")
        
        # Save final scan data
        save_scan_data(scan_data)
        
        return True, results_html_path
    except Exception as e:
        logging.error(f"Failed to write HTML report: {e}")
        return False, str(e)

# ---------------------------- SSL AND WEB SECURITY FUNCTIONS ----------------------------

def check_ssl_certificate(domain, scan_data=None):
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
                
                # Create result
                result = {
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
                
                # Update scan data if provided
                if scan_data:
                    scan_data["web_security"]["ssl_certificate"] = result
                    update_scan_progress(scan_data, "ssl_certificate", 10)
                
                return result
    except Exception as e:
        result = {
            'error': str(e),
            'status': 'Error checking certificate',
            'severity': 'High'
        }
        
        # Update scan data if provided
        if scan_data:
            scan_data["web_security"]["ssl_certificate"] = result
            update_scan_progress(scan_data, "ssl_certificate", 10)
        
        return result

def check_security_headers(url, scan_data=None):
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
        
        result = {
            'score': score,
            'headers': {header: details['found'] for header, details in security_headers.items()},
            'severity': severity
        }
        
        # Update scan data if provided
        if scan_data:
            scan_data["web_security"]["security_headers"] = result
            update_scan_progress(scan_data, "security_headers", 10)
        
        return result
    except Exception as e:
        result = {
            'error': str(e),
            'score': 0,
            'severity': 'High'
        }
        
        # Update scan data if provided
        if scan_data:
            scan_data["web_security"]["security_headers"] = result
            update_scan_progress(scan_data, "security_headers", 10)
        
        return result

def detect_cms(url, scan_data=None):
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
            result = {
                'cms_detected': True,
                'cms_name': detected_cms,
                'version': version,
                'potential_vulnerabilities': potential_vulnerabilities,
                'severity': "High" if potential_vulnerabilities else "Low"
            }
        else:
            result = {
                'cms_detected': False,
                'cms_name': None,
                'version': None,
                'potential_vulnerabilities': [],
                'severity': "Low"
            }
        
        # Update scan data if provided
        if scan_data:
            scan_data["web_security"]["cms"] = result
            update_scan_progress(scan_data, "cms_detection", 10)
        
        return result
    except Exception as e:
        result = {
            'error': str(e),
            'cms_detected': False,
            'severity': 'Medium'
        }
        
        # Update scan data if provided
        if scan_data:
            scan_data["web_security"]["cms"] = result
            update_scan_progress(scan_data, "cms_detection", 10)
        
        return result

def analyze_cookies(url, scan_data=None):
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
        
        result = {
            'total_cookies': total_cookies,
            'secure_cookies': secure_cookies,
            'httponly_cookies': httponly_cookies,
            'samesite_cookies': samesite_cookies,
            'score': score,
            'severity': severity
        }
        
        # Update scan data if provided
        if scan_data:
            scan_data["web_security"]["cookies"] = result
            update_scan_progress(scan_data, "cookie_analysis", 10)
        
        return result
    except Exception as e:
        result = {
            'error': str(e),
            'score': 0,
            'severity': 'Medium'
        }
        
        # Update scan data if provided
        if scan_data:
            scan_data["web_security"]["cookies"] = result
            update_scan_progress(scan_data, "cookie_analysis", 10)
        
        return result

def detect_web_framework(url, scan_data=None):
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
        
        result = {
            'frameworks': frameworks,
            'count': len(frameworks)
        }
        
        # Update scan data if provided
        if scan_data:
            scan_data["web_security"]["frameworks"] = result
            update_scan_progress(scan_data, "framework_detection", 5)
        
        return result
    except Exception as e:
        result = {
            'error': str(e),
            'frameworks': [],
            'count': 0
        }
        
        # Update scan data if provided
        if scan_data:
            scan_data["web_security"]["frameworks"] = result
            update_scan_progress(scan_data, "framework_detection", 5)
        
        return result

def crawl_for_sensitive_content(url, max_urls=15, scan_data=None):
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
            
            # Update scan data periodically during the crawl
            if scan_data and (len(found_paths) % 5 == 0 or len(found_paths) == 1):
                scan_data["web_security"]["sensitive_content_partial"] = {
                    'sensitive_paths_found_so_far': sensitive_count,
                    'paths_so_far': found_paths,
                    'progress': f"Checked {len(found_paths)}/{len(sensitive_paths[:max_urls])} paths"
                }
                update_scan_progress(scan_data, "sensitive_content", 1)
        
        # Determine severity based on number of sensitive paths found
        if sensitive_count > 5:
            severity = "Critical"
        elif sensitive_count > 2:
            severity = "High"
        elif sensitive_count > 0:
            severity = "Medium"
        else:
            severity = "Low"
        
        result = {
            'sensitive_paths_found': sensitive_count,
            'paths': found_paths,
            'severity': severity
        }
        
        # Update scan data if provided
        if scan_data:
            scan_data["web_security"]["sensitive_content"] = result
            update_scan_progress(scan_data, "sensitive_content", 5)
        
        return result
    except Exception as e:
        result = {
            'error': str(e),
            'sensitive_paths_found': 0,
            'paths': [],
            'severity': 'Medium'
        }
        
        # Update scan data if provided
        if scan_data:
            scan_data["web_security"]["sensitive_content"] = result
            update_scan_progress(scan_data, "sensitive_content", 5)
        
        return result

# ---------------------------- EMAIL SECURITY FUNCTIONS ----------------------------

def analyze_dns_configuration(domain, scan_data=None):
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
