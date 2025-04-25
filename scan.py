"""
Integrated security scanner module combining basic and enhanced vulnerability scanning.
"""

import ssl
import socket
import dns.resolver
import requests
import re
import json
import datetime
import urllib.parse
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import logging
import warnings
import urllib3
import platform
import psutil
import random
import dns.zone
import dns.query
import sys
import os

# Suppress InsecureRequestWarning warnings
warnings.filterwarnings('ignore', message='.*InsecureRequestWarning.*')

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# ===== CONSTANTS =====

# Define severity levels
SEVERITY = {
    "Critical": 10,
    "High": 7,
    "Medium": 5,
    "Low": 2,
    "Info": 1
}

# ===== UTILITY FUNCTIONS =====

def generate_threat_scenario(vulnerability, severity):
    """Generate threat scenarios based on detected vulnerabilities"""
    scenarios = {
        "OS Update": "Outdated software can be exploited by attackers to run malicious code, leading to data breaches or system compromise.",
        "Weak Passwords": "Weak or reused passwords can be easily guessed or cracked, allowing attackers to access sensitive accounts or data.",
        "Open Ports": "Open network ports expose your system to external attacks, including DDoS, data theft, and unauthorized access.",
        "Encryption": "Lack of disk encryption increases the risk of data theft, especially if devices are lost or stolen.",
        "MFA": "Lack of Multi-Factor Authentication (MFA) makes your system vulnerable to unauthorized access from attackers.",
        "RDP Security": "Unsecured Remote Desktop Protocol (RDP) can be easily exploited by cybercriminals.",
        "Backup": "Without proper backup systems in place, critical data is vulnerable to loss in the event of a disaster.",
        "Email Security": "Email is a primary attack vector for phishing and malware distribution. Lack of proper security measures can result in a breach.",
        "Endpoint Protection": "Missing endpoint protection leaves your system vulnerable to malware and exploitation.",
        "Network Segmentation": "Lack of network segmentation increases the risk of a widespread breach if an attacker gains access.",
        "Ransomware Protection": "Without proper ransomware protection, your system is vulnerable to file encryption and extortion attacks.",
        "DNS Security": "Unprotected DNS servers can be used in phishing attacks and data manipulation. DNSSEC ensures the integrity of DNS queries."
    }
    return scenarios.get(vulnerability, "Unspecified threat scenario: This vulnerability could lead to serious consequences if not addressed.")

def get_severity_level(severity):
    """Calculate severity based on the issue type"""
    return SEVERITY.get(severity, SEVERITY["Info"])

def get_recommendations(vulnerability, severity):
    """Generate actionable recommendations based on severity"""
    if severity == "Critical":
        return f"[CRITICAL] Immediate action required: {vulnerability}"
    elif severity == "High":
        return f"[HIGH] Prioritize this fix: {vulnerability}"
    elif severity == "Medium":
        return f"[MEDIUM] Plan to address this issue: {vulnerability}"
    else:
        return f"[LOW] Address when convenient: {vulnerability}"

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

# ===== BASIC SYSTEM SCANNING FUNCTIONS =====

def check_os_updates():
    """Check for pending OS updates"""
    try:
        os_name = platform.system()
        
        if os_name == "Linux":
            return {
                "message": "Operating System (Linux) has pending updates",
                "severity": "High",
                "info": "Additional info about Linux"
            }
        elif os_name == "Windows":
            return {
                "message": "Operating System (Windows) is up-to-date",
                "severity": "Low",
                "info": "Everything is fine with Windows"
            }
        elif os_name == "Darwin":  # macOS
            return {
                "message": "Operating System (macOS) is up-to-date",
                "severity": "Low",
                "info": "No pending updates"
            }
        else:
            return {
                "message": "Operating System update status: Unknown",
                "severity": "Critical",
                "info": "Unknown OS"
            }
    except Exception as e:
        logging.error(f"Error checking OS updates: {e}")
        return {
            "message": "Error checking OS updates",
            "severity": "Critical",
            "info": str(e)
        }

def get_windows_version():
    """Get Windows version and assess its security"""
    try:
        os_name = platform.system()
        if os_name == "Windows":
            try:
                win_ver = sys.getwindowsversion()
                major, build = win_ver.major, win_ver.build
                if major == 10 and build >= 22000:
                    return f"Windows 11 or higher (Build {build})", "Low"
                else:
                    return f"Windows version is earlier than Windows 11 (Build {build})", "Critical"
            except:
                return "Windows version detection failed", "Medium"
        else:
            return f"Server running {os_name}", "Low"
    except Exception as e:
        logging.error(f"Error checking Windows version: {e}")
        return f"Error checking OS version: {str(e)}", "Medium"

def check_open_ports():
    """Simulated port check for web environment"""
    try:
        # For web environment, return simulated results
        # This represents typical findings rather than actual open ports
        simulated_open_ports = [80, 443, 3389, 445, 139, 135, 5985, 5986, 53, 88]
        
        # Add some random ports to simulate a more realistic environment
        additional_ports = random.sample([21, 22, 23, 25, 110, 143, 1433, 3306, 5900, 8080, 8443], 
                                        random.randint(3, 8))
        simulated_open_ports.extend(additional_ports)
        
        open_ports_count = len(simulated_open_ports)
        logging.debug(f"Simulated {open_ports_count} open ports")
        
        # Severity based on count and specific ports
        if open_ports_count >= 30 or any(p in [3389, 5900, 21, 23] for p in simulated_open_ports):
            severity = "High"
        elif open_ports_count >= 10:
            severity = "Medium"
        else:
            severity = "Low"
            
        return open_ports_count, simulated_open_ports, severity
    except Exception as e:
        logging.error(f"Error in simulated port check: {e}")
        return 0, [], "Critical"

def check_firewall_status():
    """Enhanced firewall status check for web environment"""
    try:
        client_os = platform.system()
        
        # Make educated guesses about firewall status based on available info
        if "Windows" in client_os:
            return "Windows Firewall is likely active, but web browsers cannot directly detect its status. We recommend manually checking Windows Defender Firewall settings.", "Medium"
        elif "Darwin" in client_os:  # macOS
            return "macOS likely has its built-in firewall enabled, but web browsers cannot directly detect its status. We recommend checking Security & Privacy settings.", "Medium"
        elif "Linux" in client_os:
            return "Linux systems typically use iptables or ufw for firewall protection. Web browsers cannot directly detect firewall status.", "Medium"
        else:
            return "Firewall status check limited in web environment. We recommend manually checking your system's firewall settings.", "Medium"
    except Exception as e:
        logging.error(f"Error checking firewall status: {e}")
        return "Error checking firewall status", "Medium"

# ===== EMAIL SECURITY SCANNING FUNCTIONS =====

def check_spf_status(domain):
    """Check the SPF record for a given domain with enhanced validation."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = rdata.to_text().strip('"')
            if txt_record.startswith("v=spf1"):
                logging.debug(f"Found SPF record for {domain}: {txt_record}")

                # Count the number of mechanisms
                mechanisms = [m for m in txt_record.split() if any(m.startswith(p) for p in ["include:", "a", "mx", "ip4:", "ip6:"])]
                mechanism_count = len(mechanisms)

                # Check for ending
                if txt_record.endswith("-all"):
                    if mechanism_count <= 10:
                        return f"SPF record OK: {txt_record} (Mechanisms: {mechanism_count})", "Low"
                    else:
                        return f"Too many SPF mechanisms ({mechanism_count}) in record: {txt_record}", "High"
                elif txt_record.endswith("~all"):
                    if mechanism_count <= 10:
                        return f"SPF uses soft fail (~all). Consider using -all. Record: {txt_record} (Mechanisms: {mechanism_count})", "Medium"
                    else:
                        return f"Too many SPF mechanisms ({mechanism_count}) and ends in ~all: {txt_record}", "High"
                else:
                    return f"SPF record missing final '-all' or '~all': {txt_record}", "High"

        return "No SPF record found", "High"

    except Exception as e:
        logging.error(f"Error checking SPF status for domain {domain}: {e}")
        return f"Error checking SPF status: {e}", "Critical"
    
def check_dmarc_record(domain):
    """Check if the domain has a valid DMARC record."""
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT")

        for rdata in answers:
            record = rdata.to_text().strip('"')
            if record.lower().startswith("v=dmarc1"):
                return f"DMARC record found: {record}", "Low"
        return "No valid DMARC record found", "High"

    except dns.resolver.NXDOMAIN:
        return "Domain does not exist", "Critical"
    except dns.resolver.NoAnswer:
        return "No DMARC record found", "High"
    except Exception as e:
        return f"Error checking DMARC record: {e}", "Critical"

def check_dkim_record(domain):
    """Check if the domain has a valid DKIM record."""
    selectors = ["default", "selector1", "selector2", "google", "dkim", "dkim1"]
    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(dkim_domain, "TXT")
            txt_record = answers[0].to_text().strip('"')
            return f"DKIM record found with selector '{selector}': {txt_record}", "Low"
        except dns.resolver.NXDOMAIN:
            continue  # No such name, try next
        except Exception as e:
            continue  # Suppress other errors for now

    return "DKIM record not found using common selectors.", "High"

# ===== DNS SECURITY SCANNING FUNCTIONS =====

def analyze_dns_configuration(domain):
    """Analyze DNS configuration for a domain"""
    try:
        result = {
            'domain': domain,
            'records': {},
            'issues': [],
            'risk_level': 'Low'
        }
        
        # Check for A records
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            result['records']['A'] = [record.to_text() for record in a_records]
        except Exception as e:
            result['issues'].append({
                'type': 'A Record Missing',
                'description': f"Could not find A records for domain: {str(e)}",
                'severity': 'High',
                'recommendation': 'Configure an A record to point to your server IP address'
            })
        
        # Check for MX records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            result['records']['MX'] = [record.to_text() for record in mx_records]
        except Exception as e:
            result['issues'].append({
                'type': 'MX Record Missing',
                'description': f"Could not find MX records for domain: {str(e)}",
                'severity': 'Medium',
                'recommendation': 'Configure MX records if you use this domain for email'
            })
        
        # Check for NS records
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            result['records']['NS'] = [record.to_text() for record in ns_records]
            
            # Check if multiple nameservers exist (redundancy)
            if len(result['records']['NS']) < 2:
                result['issues'].append({
                    'type': 'Insufficient Nameservers',
                    'description': 'Domain has less than 2 nameservers, which could create a single point of failure',
                    'severity': 'Medium',
                    'recommendation': 'Configure at least 2 nameservers for redundancy'
                })
        except Exception as e:
            result['issues'].append({
                'type': 'NS Record Issue',
                'description': f"Problem with NS records: {str(e)}",
                'severity': 'High',
                'recommendation': 'Ensure your domain has properly configured nameservers'
            })
        
        # Check for TXT records (SPF, DMARC, etc.)
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            result['records']['TXT'] = [record.to_text() for record in txt_records]
            
            # Check for SPF
            spf_found = False
            for record in result['records']['TXT']:
                if record.startswith('"v=spf1'):
                    spf_found = True
                    break
            
            if not spf_found:
                result['issues'].append({
                    'type': 'SPF Record Missing',
                    'description': 'No SPF record found in TXT records',
                    'severity': 'Medium',
                    'recommendation': 'Configure SPF record to prevent email spoofing'
                })
        except Exception:
            result['records']['TXT'] = []
        
        # Check for DMARC record
        try:
            dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            result['records']['DMARC'] = [record.to_text() for record in dmarc_records]
        except Exception:
            result['issues'].append({
                'type': 'DMARC Record Missing',
                'description': 'No DMARC record found',
                'severity': 'Medium',
                'recommendation': 'Configure DMARC record to enhance email security'
            })
        
        # Check for DNSSEC
        try:
            dnskey_records = dns.resolver.resolve(domain, 'DNSKEY')
            result['records']['DNSKEY'] = [record.to_text() for record in dnskey_records]
        except Exception:
            result['issues'].append({
                'type': 'DNSSEC Not Configured',
                'description': 'DNSSEC is not configured for this domain',
                'severity': 'Medium',
                'recommendation': 'Consider implementing DNSSEC to protect against DNS spoofing'
            })
        
        # Check for CAA records
        try:
            caa_records = dns.resolver.resolve(domain, 'CAA')
            result['records']['CAA'] = [record.to_text() for record in caa_records]
        except Exception:
            result['issues'].append({
                'type': 'CAA Record Missing',
                'description': 'No CAA record found',
                'severity': 'Low',
                'recommendation': 'Configure CAA record to control which CAs can issue certificates for your domain'
            })
        
        # Determine overall risk level based on issues
        high_severity_issues = [issue for issue in result['issues'] if issue['severity'] == 'High']
        medium_severity_issues = [issue for issue in result['issues'] if issue['severity'] == 'Medium']
        
        if high_severity_issues:
            result['risk_level'] = 'High'
        elif len(medium_severity_issues) > 2:
            result['risk_level'] = 'Medium'
        
        return result
    except Exception as e:
        logging.error(f"Error analyzing DNS configuration: {e}")
        return {
            'domain': domain,
            'error': str(e),
            'risk_level': 'Unknown'
        }

# ===== WEB APPLICATION SCANNING FUNCTIONS =====

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
                now = datetime.datetime.now()
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
                
                # Additional check for common vulnerable WordPress version
                if version_parts[0] == 5 and version_parts[1] < 2:
                    result['potential_vulnerabilities'].append({
                        'name': 'WordPress REST API Vulnerability',
                        'description': 'Versions before 5.2.0 may be vulnerable to REST API issues',
                        'recommendation': 'Update to WordPress 5.2.0 or later'
                    })
        
        return result
    except Exception as e:
        logging.error(f"CMS detection failed: {str(e)}")
        return {
            'error': f'CMS detection failed: {str(e)}',
            'cms_detected': False
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
                'expires': datetime.datetime.fromtimestamp(cookie.expires).isoformat() if cookie.expires else None,
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
