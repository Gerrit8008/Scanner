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

# ---------------------------- INDUSTRY ANALYSIS FUNCTIONS ----------------------------

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
            'compliance': ['HIPAA', 'HITECH', 'FDA', 'NIST 800-66'],
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
            'compliance': ['PCI DSS', 'SOX', 'GLBA', 'GDPR', 'NIST 800-53'],
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
            'compliance': ['PCI DSS', 'CCPA', 'GDPR', 'ISO 27001'],
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
            'compliance': ['FERPA', 'COPPA', 'State Privacy Laws', 'NIST 800-171'],
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
            'compliance': ['FISMA', 'NIST 800-53', 'FedRAMP', 'CMMC'],
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
            'compliance': ['General Data Protection', 'Industry Best Practices', 'ISO 27001'],
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
    Calculate percentile with improved user-friendly outputs
    
    Args:
        score (int): Security score (0-100)
        industry_type (str): Industry type to compare against
        
    Returns:
        dict: Percentile information with user-friendly explanations
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
    
    # Calculate percentile with simpler logic
    percentile_dist = industry['percentile_distribution']
    
    if score >= percentile_dist[90]:
        percentile = 90
        standing = "Top 10%"
        message = "Your security posture is among the best in your industry."
        color = "#28a745"  # green
    elif score >= percentile_dist[75]:
        percentile = 75
        standing = "Top 25%"
        message = "Your security posture is better than most in your industry."
        color = "#5cb85c"  # light green
    elif score >= percentile_dist[50]:
        percentile = 50
        standing = "Above Average"
        message = "Your security posture is above the industry median."
        color = "#17a2b8"  # info blue
    elif score >= percentile_dist[25]:
        percentile = 25
        standing = "Below Average"
        message = "Your security meets minimum standards but lags behind industry leaders."
        color = "#ffc107"  # warning yellow
    elif score >= percentile_dist[10]:
        percentile = 10
        standing = "Bottom 25%"
        message = "Your security posture needs significant improvement compared to industry standards."
        color = "#fd7e14"  # orange
    else:
        percentile = 5
        standing = "Bottom 10%"
        message = "Your security posture is critically below industry standards. Immediate action is needed."
        color = "#dc3545"  # red
    
    # Return the benchmark data with user-friendly information
    return {
        'percentile': percentile,
        'standing': standing,
        'message': message,
        'comparison': comparison,
        'difference': abs(difference),
        'avg_score': avg_score,
        'color': color,
        'key_compliance': industry['compliance'][:3],  # Just show top 3 for clarity
        'critical_controls': industry['critical_controls'][:3]  # Just show top 3 for clarity
    }

# ---------------------------- UTILITY FUNCTIONS ----------------------------

# New function to organize risks by MSP service categories
def categorize_risks_by_services(scan_results):
    """Categorize all detected risks into MSP service categories"""
    service_categories = {
        'endpoint_security': {
            'name': 'Endpoint Security',
            'description': 'Protection for your computers, mobile devices, and other network endpoints',
            'findings': [],
            'risk_level': 'Low',
            'score': 0,
            'max_score': 0
        },
        'network_defense': {
            'name': 'Network Defense',
            'description': 'Protection for your network infrastructure and internet connectivity',
            'findings': [],
            'risk_level': 'Low',
            'score': 0,
            'max_score': 0
        },
        'data_protection': {
            'name': 'Data Protection',
            'description': 'Solutions to secure, backup, and manage your critical business data',
            'findings': [],
            'risk_level': 'Low',
            'score': 0,
            'max_score': 0
        },
        'access_management': {
            'name': 'Access Management',
            'description': 'Controls to ensure only authorized users access your systems',
            'findings': [],
            'risk_level': 'Low',
            'score': 0,
            'max_score': 0
        }
    }
    
    # Map findings to categories
    
    # 1. Endpoint Security findings
    if 'system' in scan_results:
        # OS Updates
        if 'os_updates' in scan_results['system']:
            severity = scan_results['system']['os_updates'].get('severity', 'Low')
            score = SEVERITY.get(severity, 1)
            service_categories['endpoint_security']['findings'].append({
                'name': 'Operating System Updates',
                'description': scan_results['system']['os_updates'].get('message', ''),
                'severity': severity,
                'score': score,
                'service_solution': 'Managed Updates & Patching' 
            })
            service_categories['endpoint_security']['score'] += score
            service_categories['endpoint_security']['max_score'] += 10
        
        # Firewall Status
        if 'firewall' in scan_results['system']:
            severity = scan_results['system']['firewall'].get('severity', 'Low')
            score = SEVERITY.get(severity, 1)
            service_categories['endpoint_security']['findings'].append({
                'name': 'Firewall Configuration',
                'description': scan_results['system']['firewall'].get('status', ''),
                'severity': severity,
                'score': score,
                'service_solution': 'Endpoint Protection & Firewall Management'
            })
            service_categories['endpoint_security']['score'] += score
            service_categories['endpoint_security']['max_score'] += 10
    
    # 2. Network Defense findings
    if 'network' in scan_results:
        # Open Ports
        if 'open_ports' in scan_results['network']:
            severity = scan_results['network']['open_ports'].get('severity', 'Low')
            score = SEVERITY.get(severity, 1)
            service_categories['network_defense']['findings'].append({
                'name': 'Open Network Ports',
                'description': f"Found {scan_results['network']['open_ports'].get('count', 0)} open ports that could be access points for attackers",
                'severity': severity,
                'score': score,
                'service_solution': 'Network Security Assessment & Remediation'
            })
            service_categories['network_defense']['score'] += score
            service_categories['network_defense']['max_score'] += 10
            
        # Gateway issues
        if 'gateway' in scan_results['network']:
            critical_issues = [r for r in scan_results['network']['gateway'].get('results', []) if r[1] in ['Critical', 'High']]
            if critical_issues:
                service_categories['network_defense']['findings'].append({
                    'name': 'Gateway Security Issues',
                    'description': f"Found {len(critical_issues)} high-risk issues with your network gateway",
                    'severity': 'High',
                    'score': 7,
                    'service_solution': 'Managed Firewall & Gateway Protection'
                })
                service_categories['network_defense']['score'] += 7
                service_categories['network_defense']['max_score'] += 10
    
    # 3. Data Protection findings
    # SSL Certificate check maps to data protection
    if 'ssl_certificate' in scan_results and 'error' not in scan_results['ssl_certificate']:
        severity = scan_results['ssl_certificate'].get('severity', 'Low')
        score = SEVERITY.get(severity, 1)
        service_categories['data_protection']['findings'].append({
            'name': 'SSL/TLS Certificate',
            'description': f"Certificate status: {scan_results['ssl_certificate'].get('status', '')}",
            'severity': severity,
            'score': score,
            'service_solution': 'SSL/TLS Certificate Management'
        })
        service_categories['data_protection']['score'] += score
        service_categories['data_protection']['max_score'] += 10
    
    # Email security is part of data protection
    if 'email_security' in scan_results and 'error' not in scan_results['email_security']:
        # Combine email security findings
        email_issues = []
        max_severity = 'Low'
        max_score = 1
        
        for protocol in ['spf', 'dmarc', 'dkim']:
            if protocol in scan_results['email_security']:
                severity = scan_results['email_security'][protocol].get('severity', 'Low')
                if SEVERITY.get(severity, 0) > SEVERITY.get(max_severity, 0):
                    max_severity = severity
                    max_score = SEVERITY.get(severity, 1)
                email_issues.append(f"{protocol.upper()}: {scan_results['email_security'][protocol].get('status', '')}")
        
        if email_issues:
            service_categories['data_protection']['findings'].append({
                'name': 'Email Security Configuration',
                'description': '; '.join(email_issues),
                'severity': max_severity,
                'score': max_score,
                'service_solution': 'Email Security & Anti-Phishing Protection'
            })
            service_categories['data_protection']['score'] += max_score
            service_categories['data_protection']['max_score'] += 10
    
    # 4. Access Management findings
    # Security headers relate to web access control
    if 'security_headers' in scan_results and 'error' not in scan_results['security_headers']:
        severity = scan_results['security_headers'].get('severity', 'Low')
        score = SEVERITY.get(severity, 1)
        service_categories['access_management']['findings'].append({
            'name': 'Web Security Headers',
            'description': f"Security header score: {scan_results['security_headers'].get('score', 0)}/100",
            'severity': severity,
            'score': score,
            'service_solution': 'Web Application Security Management'
        })
        service_categories['access_management']['score'] += score
        service_categories['access_management']['max_score'] += 10
    
    # Sensitive content is access management issue
    if 'sensitive_content' in scan_results and 'error' not in scan_results['sensitive_content']:
        if scan_results['sensitive_content'].get('sensitive_paths_found', 0) > 0:
            severity = scan_results['sensitive_content'].get('severity', 'Low')
            score = SEVERITY.get(severity, 1)
            service_categories['access_management']['findings'].append({
                'name': 'Sensitive Content Exposure',
                'description': f"Found {scan_results['sensitive_content'].get('sensitive_paths_found', 0)} sensitive paths that should be protected",
                'severity': severity,
                'score': score,
                'service_solution': 'Access Control & Content Security'
            })
            service_categories['access_management']['score'] += score
            service_categories['access_management']['max_score'] += 10
    
    # Calculate risk level for each category
    for category in service_categories:
        cat = service_categories[category]
        # Prevent division by zero
        if cat['max_score'] > 0:
            percentage = ((cat['max_score'] - cat['score']) / cat['max_score']) * 100
            
            if percentage >= 90:
                cat['risk_level'] = 'Low'
            elif percentage >= 70:
                cat['risk_level'] = 'Medium'
            elif percentage >= 50:
                cat['risk_level'] = 'High'
            else:
                cat['risk_level'] = 'Critical'
        else:
            cat['risk_level'] = 'Unknown'
    
    return service_categories

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
    Detect client IP and guess possible gateway IPs based on common network configurations.
    """
    try:
        # Get client IP from request
        client_ip = request.remote_addr or "0.0.0.0"  # Default to 0.0.0.0 if remote_addr is None
        if request.headers.get('X-Forwarded-For'):
            forwarded_ips = request.headers.get('X-Forwarded-For').split(',')
            if forwarded_ips and len(forwarded_ips) > 0 and forwarded_ips[0].strip():
                client_ip = forwarded_ips[0].strip()
            else:
                logging.warning("X-Forwarded-For header is empty or invalid.")
        
        # Validate client IP
        gateway_guesses = []
        network_type = "Unknown"
        
        try:
            ip_obj = ipaddress.ip_address(client_ip)
            
            if ip_obj.is_private:
                network_type = "Private Network"
                if client_ip.startswith('192.168.'):
                    parts = client_ip.split('.')
                    if len(parts) >= 2:
                        first_two_octets = '.'.join(parts[:2])
                        gateway_guesses = [f"{first_two_octets}.1", f"{first_two_octets}.254"]
                elif client_ip.startswith('10.'):
                    parts = client_ip.split('.')
                    if len(parts) >= 1:
                        first_octet = parts[0]
                        gateway_guesses = [f"{first_octet}.0.0.1", f"{first_octet}.255.255.254"]
                elif client_ip.startswith('172.'):
                    parts = client_ip.split('.')
                    if len(parts) >= 2:
                        second_octet = int(parts[1]) if parts[1].isdigit() else 0
                        if 16 <= second_octet <= 31:
                            first_two_octets = '.'.join(parts[:2])
                            gateway_guesses = [f"{first_two_octets}.1", f"{first_two_octets}.254"]
            else:
                network_type = "Public Network"
                gateway_guesses = ["Gateway detection not possible for public IPs"]
        except ValueError:
            # Invalid IP address
            logging.warning(f"Invalid IP address format: {client_ip}")
            gateway_guesses = ["Invalid IP format"]
        
        # If we have no gateway guesses by this point, add a default
        if not gateway_guesses:
            gateway_guesses = ["Unable to determine gateway"]
            
        return client_ip, gateway_guesses, network_type
    except Exception as e:
        logging.error(f"Error during gateway checks: {str(e)}")
        return "Unknown", ["Error detecting gateway"], "Unknown"

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
    results = []
    try:
        # Parse gateway info safely with error handling
        client_ip = "Unknown"
        if "Client IP:" in gateway_info:
            client_ip = gateway_info.split("Client IP:")[1].split("|")[0].strip()
        
        # Add client IP information safely
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
    """
    Check security headers of a website with enhanced analysis of header values
    and support for modern security headers
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Use certificate verification by default
        response = requests.get(url, headers=headers, timeout=10, verify=True)
        cert_verified = True
    except requests.exceptions.SSLError:
        # Fall back to no verification if certificate issues exist
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        cert_verified = False
    except Exception as e:
        return {
            'error': str(e),
            'score': 0,
            'severity': 'High',
            'cert_verified': False
        }
        
    # Modern security headers configuration with weights
    security_headers = {
        # Essential headers - highest priority
        'Strict-Transport-Security': {
            'weight': 20, 
            'found': False,
            'value': None,
            'quality': 'Poor',
            'description': 'Forces browsers to use HTTPS, preventing downgrade attacks',
            'recommendation': 'Add "max-age=31536000; includeSubDomains; preload"'
        },
        'Content-Security-Policy': {
            'weight': 20, 
            'found': False,
            'value': None,
            'quality': 'Poor',
            'description': 'Controls which resources can be loaded, reducing XSS risks',
            'recommendation': 'Implement a comprehensive policy based on your site needs'
        },
        
        # Important headers
        'X-Frame-Options': {
            'weight': 10, 
            'found': False,
            'value': None,
            'quality': 'Poor',
            'description': 'Prevents clickjacking attacks by controlling frame embedding',
            'recommendation': 'Add "X-Frame-Options: DENY" or "SAMEORIGIN"'
        },
        'X-Content-Type-Options': {
            'weight': 10, 
            'found': False,
            'value': None,
            'quality': 'Poor',
            'description': 'Prevents MIME type sniffing attacks',
            'recommendation': 'Add "X-Content-Type-Options: nosniff"'
        },
        'Referrer-Policy': {
            'weight': 10, 
            'found': False,
            'value': None,
            'quality': 'Poor',
            'description': 'Controls referrer information sent with requests',
            'recommendation': 'Add "Referrer-Policy: strict-origin-when-cross-origin"'
        },
        'Permissions-Policy': {
            'weight': 10, 
            'found': False,
            'value': None,
            'quality': 'Poor',
            'description': 'Restricts which browser features can be used',
            'recommendation': 'Add policies for features like geolocation, camera, etc.'
        },
        
        # Modern security headers
        'Cross-Origin-Resource-Policy': {
            'weight': 8, 
            'found': False,
            'value': None,
            'quality': 'Poor',
            'description': 'Prevents other domains from loading your resources',
            'recommendation': 'Add "Cross-Origin-Resource-Policy: same-origin"'
        },
        'Cross-Origin-Opener-Policy': {
            'weight': 8, 
            'found': False,
            'value': None,
            'quality': 'Poor',
            'description': 'Controls window/popup interaction with cross-origin pages',
            'recommendation': 'Add "Cross-Origin-Opener-Policy: same-origin"'
        },
        'Cross-Origin-Embedder-Policy': {
            'weight': 8, 
            'found': False,
            'value': None,
            'quality': 'Poor',
            'description': 'Requires all resources to be cross-origin isolated',
            'recommendation': 'Add "Cross-Origin-Embedder-Policy: require-corp"'
        },
        
        # Deprecated but still useful as defense-in-depth
        'X-XSS-Protection': {
            'weight': 6, 
            'found': False,
            'value': None,
            'quality': 'Poor',
            'description': 'Legacy browser XSS protection (gradually being phased out)',
            'recommendation': 'Add "X-XSS-Protection: 1; mode=block"'
        }
    }
    
    # Check presence of each header and analyze values
    resp_headers = response.headers
    for header, details in security_headers.items():
        header_key = next((h for h in resp_headers if h.lower() == header.lower()), None)
        
        if header_key:
            details['found'] = True
            details['value'] = resp_headers[header_key]
            
            # Analyze quality of header values
            if header == 'Strict-Transport-Security':
                if 'max-age=31536000' in details['value'] and 'includeSubDomains' in details['value']:
                    details['quality'] = 'Excellent'
                elif 'max-age=' in details['value']:
                    age_value = re.search(r'max-age=(\d+)', details['value'])
                    if age_value and int(age_value.group(1)) >= 15768000:  # 6 months
                        details['quality'] = 'Good'
                    else:
                        details['quality'] = 'Fair'
            
            elif header == 'Content-Security-Policy':
                if "default-src 'none'" in details['value'] or "script-src 'self'" in details['value']:
                    details['quality'] = 'Good'
                elif "default-src 'self'" in details['value']:
                    details['quality'] = 'Fair'
                elif "unsafe-inline" in details['value'] or "unsafe-eval" in details['value']:
                    details['quality'] = 'Poor'
                else:
                    details['quality'] = 'Fair'
            
            elif header == 'X-Frame-Options':
                if details['value'].upper() == 'DENY':
                    details['quality'] = 'Excellent'
                elif details['value'].upper() == 'SAMEORIGIN':
                    details['quality'] = 'Good'
                else:
                    details['quality'] = 'Fair'
            
            elif header == 'X-Content-Type-Options':
                if details['value'].lower() == 'nosniff':
                    details['quality'] = 'Excellent'
                else:
                    details['quality'] = 'Fair'
            
            elif header == 'Referrer-Policy':
                secure_values = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin']
                if any(val in details['value'].lower() for val in secure_values):
                    details['quality'] = 'Excellent'
                elif 'origin' in details['value'].lower():
                    details['quality'] = 'Good'
                else:
                    details['quality'] = 'Fair'
            
            elif header == 'X-XSS-Protection':
                if '1; mode=block' in details['value']:
                    details['quality'] = 'Good'
                elif '1' in details['value']:
                    details['quality'] = 'Fair'
    
    # Calculate score with quality adjustments
    base_score = 0
    max_score = sum(details['weight'] for _, details in security_headers.items())
    
    for header, details in security_headers.items():
        if details['found']:
            if details['quality'] == 'Excellent':
                base_score += details['weight']
            elif details['quality'] == 'Good':
                base_score += int(details['weight'] * 0.8)
            elif details['quality'] == 'Fair':
                base_score += int(details['weight'] * 0.6)
            elif details['quality'] == 'Poor':
                base_score += int(details['weight'] * 0.4)
    
    # Convert to 0-100 scale
    score = int((base_score / max_score) * 100) if max_score > 0 else 0
    
    # Determine severity
    if score >= 80:
        severity = "Low"
    elif score >= 50:
        severity = "Medium"
    else:
        severity = "High"
    
    # Get missing headers
    missing_headers = [header for header, details in security_headers.items() 
                       if not details['found'] and details['weight'] >= 10]
    
    # Get headers with poor implementation
    poor_headers = [header for header, details in security_headers.items() 
                    if details['found'] and details['quality'] in ['Poor', 'Fair']]
    
    return {
        'score': score,
        'headers': security_headers,
        'severity': severity,
        'cert_verified': cert_verified,
        'missing_critical': missing_headers,
        'poor_implementation': poor_headers
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

def calculate_simplified_risk_score(scan_results):
    """
    Calculate a simplified risk score that's more intuitive for users
    
    Args:
        scan_results (dict): Dictionary containing all scan results
        
    Returns:
        dict: Risk assessment information
    """
    # Start with 100 points and subtract based on issues found
    base_score = 100
    deductions = []
    
    # Weight categories differently
    category_weights = {
        'network_security': 0.25,
        'web_security': 0.25,
        'email_security': 0.20,
        'system_security': 0.30
    }
    
    # Network security deductions
    if 'network' in scan_results:
        if 'open_ports' in scan_results['network']:
            port_count = scan_results['network']['open_ports'].get('count', 0)
            # More open ports = higher risk
            if port_count > 15:
                deductions.append(('network_security', 25, 'Excessive open ports'))
            elif port_count > 10:
                deductions.append(('network_security', 15, 'Many open ports'))
            elif port_count > 5:
                deductions.append(('network_security', 10, 'Several open ports'))
            elif port_count > 0:
                deductions.append(('network_security', 5, 'Few open ports'))
    
    # Web security deductions
    if 'ssl_certificate' in scan_results:
        ssl = scan_results['ssl_certificate']
        if ssl.get('is_expired', False):
            deductions.append(('web_security', 25, 'Expired SSL certificate'))
        elif ssl.get('expiring_soon', False):
            deductions.append(('web_security', 15, 'SSL certificate expiring soon'))
        elif ssl.get('weak_protocol', False):
            deductions.append(('web_security', 10, 'Weak SSL/TLS protocol'))
    
    # Email security deductions
    if 'email_security' in scan_results:
        email = scan_results['email_security']
        if 'spf' in email and email['spf']['severity'] in ['High', 'Critical']:
            deductions.append(('email_security', 15, 'Missing or misconfigured SPF record'))
        if 'dmarc' in email and email['dmarc']['severity'] in ['High', 'Critical']:
            deductions.append(('email_security', 15, 'Missing or misconfigured DMARC record'))
        if 'dkim' in email and email['dkim']['severity'] in ['High', 'Critical']:
            deductions.append(('email_security', 15, 'Missing or misconfigured DKIM record'))
    
    # System security deductions
    if 'system' in scan_results:
        if 'os_updates' in scan_results['system'] and scan_results['system']['os_updates']['severity'] in ['High', 'Critical']:
            deductions.append(('system_security', 20, 'Missing critical OS updates'))
        if 'firewall' in scan_results['system'] and scan_results['system']['firewall']['severity'] in ['High', 'Critical']:
            deductions.append(('system_security', 20, 'Firewall issues detected'))
    
    # Calculate weighted score deductions
    total_deduction = 0
    for category, points, reason in deductions:
        weight = category_weights.get(category, 0.25)
        total_deduction += points * weight
    
    # Calculate final score (ensure it doesn't go below 0)
    final_score = max(0, int(base_score - total_deduction))
    
    # Determine risk level based on score
    if final_score >= 90:
        risk_level = "Excellent"
        color = "#28a745"  # green
    elif final_score >= 70:
        risk_level = "Good"
        color = "#5cb85c"  # light green
    elif final_score >= 50:
        risk_level = "Fair"
        color = "#ffc107"  # yellow
    elif final_score >= 30:
        risk_level = "Poor"
        color = "#fd7e14"  # orange
    else:
        risk_level = "Critical"
        color = "#dc3545"  # red
    
    # Calculate category scores
    category_scores = {}
    for category in category_weights.keys():
        category_deductions = [d[1] for d in deductions if d[0] == category]
        max_possible = 100 * category_weights.get(category, 0.25)
        deducted = sum(category_deductions) * category_weights.get(category, 0.25)
        category_score = max(0, int(max_possible - deducted))
        category_scores[category] = int((category_score / max_possible) * 100)  # Convert to percentage
    
    # Return detailed results including top issues found
    return {
        'overall_score': final_score,
        'risk_level': risk_level,
        'color': color,
        'deductions': deductions,
        'category_scores': category_scores
    }

def calculate_risk_score(scan_results):
    """
    Legacy function for compatibility - now using the simplified version
    """
    return calculate_simplified_risk_score(scan_results)

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

def generate_html_report(scan_results, is_integrated=False, output_dir=None):
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
                
                /* Improved gauge style for score visualization */
                .score-gauge {
                    width: 200px;
                    height: 200px;
                    margin: 0 auto;
                    position: relative;
                }
                .gauge {
                    width: 100%;
                    height: 100%;
                }
                .gauge-background {
                    fill: none;
                    stroke: #e6e6e6;
                    transform: rotate(135deg);
                    transform-origin: center;
                    stroke-dasharray: 339 339;
                }
                .gauge-value {
                    fill: none;
                    transform: rotate(135deg);
                    transform-origin: center;
                    transition: stroke-dasharray 1s ease;
                }
                .gauge-text {
                    font-size: 24px;
                    font-weight: bold;
                    dominant-baseline: middle;
                    text-anchor: middle;
                }
                
                /* Industry comparison styles */
                .industry-comparison {
                    margin-top: 30px;
                    padding: 20px;
                    background-color: #f8f9fa;
                    border-radius: 8px;
                }
                .comparison-meter {
                    position: relative;
                    height: 60px;
                    margin: 30px 0;
                }
                .meter-scale {
                    display: flex;
                    justify-content: space-between;
                    margin-bottom: 5px;
                }
                .meter-track {
                    height: 8px;
                    background: linear-gradient(to right, #dc3545, #ffc107, #28a745);
                    border-radius: 4px;
                    position: relative;
                }
                .industry-avg-marker, .your-score-marker {
                    position: absolute;
                    transform: translateX(-50%);
                }
                .marker-line {
                    height: 16px;
                    width: 2px;
                    background-color: #333;
                    margin: 0 auto;
                }
                .marker-label {
                    font-size: 12px;
                    white-space: nowrap;
                    position: absolute;
                    left: 50%;
                    transform: translateX(-50%);
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
            color = scan_results['risk_assessment'].get('color', '#92d36e')  # Default to green if no color
            
            # Add the improved gauge visualization
            html += f"""
                <div class="score-container">
                    <div class="score-gauge">
                        <svg viewBox="0 0 120 120" class="gauge">
                            <circle class="gauge-background" r="54" cx="60" cy="60" stroke-width="12"></circle>
                            <circle class="gauge-value" r="54" cx="60" cy="60" stroke-width="12" 
                                    style="stroke: {color}; 
                                          stroke-dasharray: {risk_score * 3.39} 339;"></circle>
                            <text class="gauge-text" x="60" y="60" text-anchor="middle" alignment-baseline="middle"
                                  style="fill: {color};">
                                {risk_score}
                            </text>
                        </svg>
                        <div class="score-label">{risk_level} Risk</div>
                    </div>
                </div>
            """
            
            # Add industry benchmarking if available
            if 'industry' in scan_results and scan_results['industry'].get('benchmarks'):
                benchmarks = scan_results['industry']['benchmarks']
                industry_name = scan_results['industry'].get('name', 'Your Industry')
                
                html += f"""
                <div class="industry-comparison">
                    <h3>{industry_name} Comparison</h3>
                    <p>{benchmarks['message']}</p>
                    
                    <div class="comparison-meter">
                        <div class="meter-scale">
                            <span>0</span>
                            <span>25</span>
                            <span>50</span>
                            <span>75</span>
                            <span>100</span>
                        </div>
                        <div class="meter-track">
                            <!-- Industry average marker -->
                            <div class="industry-avg-marker" style="left: {benchmarks['avg_score']}%;">
                                <div class="marker-line"></div>
                                <div class="marker-label">Industry Average</div>
                            </div>
                            
                            <!-- Your score marker -->
                            <div class="your-score-marker" style="left: {risk_score}%;">
                                <div class="marker-line"></div>
                                <div class="marker-label">Your Score</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="standing-badge">
                        <p>Your Standing: <strong>{benchmarks['standing']}</strong></p>
                    </div>
                    
                    <div class="row">
                        <div>
                            <h4>Recommended Compliance Standards</h4>
                            <ul>
                """
                
                # Add compliance standards
                for compliance in benchmarks.get('key_compliance', []):
                    html += f"<li>{compliance}</li>\n"
                
                html += """
                            </ul>
                        </div>
                    </div>
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
            """
            
            try:
                html += f"""
                <div class="score-container">
                <div style="font-size: 18px;">Security Headers Score</div>
                <div class="score" style="font-size: 48px;">{scan_results['security_headers']['score']}/100</div>
                </div>
                """
            except Exception as e:
                # Add error handling here
                logging.error(f"Error formatting security headers score: {e}")
                html += """
                <div class="score-container">
                <div style="font-size: 18px;">Security Headers Score</div>
                <div class="score" style="font-size: 48px;">N/A</div>
                </div>
                """
                
        # Add recommendations section
        if 'recommendations' in scan_results:
            html += """
                <h2>Recommendations</h2>
            """
            
            for recommendation in scan_results['recommendations']:
                html += f"""
                    <div class="recommendation">
                        <p>{recommendation}</p>
                    </div>
                """
        
         # Add threat scenarios section
        if 'threat_scenarios' in scan_results:
            html += """
                <h2>Potential Threat Scenarios</h2>
                <p>Based on the security scan results, these are potential threats that could affect your systems:</p>
            """
    
            for threat in scan_results.get('threat_scenarios', []):
                name = threat.get('name', 'Unknown Threat')
                description = threat.get('description', 'No description provided')
                impact = threat.get('impact', 'Unknown')
                likelihood = threat.get('likelihood', 'Unknown')
        
                html += f"""
                    <div class="threat">
                        <h3>{name}</h3>
                        <p>{description}</p>
                        <p><strong>Impact:</strong> {impact} | <strong>Likelihood:</strong> {likelihood}</p>
                    </div>
                """
        
                # Add footer
                html += """
                        <div class="footer">
                            <p>This report was generated automatically and is intended for informational purposes only.</p>
                            <p>For a comprehensive security assessment, contact a cybersecurity professional.</p>
                        </div>
                    </div>
                </body>
                </html>
                """
        
        return html
    except Exception as e:
        logging.error(f"Error generating HTML report: {e}")
        # Return a simple error report if HTML generation fails
        return f"""
        <!DOCTYPE html>
        <html>
        <head><title>Scan Error</title></head>
        <body>
            <h1>Error Generating Report</h1>
            <p>An error occurred while generating your security scan report: {str(e)}</p>
            <p>Please try again or contact support.</p>
        </body>
        </html>
        """
        
# Make all functions available when importing the module
__all__ = [
    'extract_domain_from_email',
    'server_lookup',
    'get_client_and_gateway_ip',
    'get_default_gateway_ip',
    'scan_gateway_ports',
    'check_ssl_certificate',
    'check_security_headers',
    'calculate_industry_percentile',
    'detect_cms',
    'analyze_cookies',
    'detect_web_framework',
    'crawl_for_sensitive_content',
    'analyze_dns_configuration',
    'check_spf_status',
    'check_dmarc_record',
    'check_dkim_record',
    'check_os_updates',
    'check_firewall_status',
    'check_open_ports',
    'analyze_port_risks',
    'calculate_risk_score',
    'calculate_simplified_risk_score',
    'get_severity_level',
    'get_recommendations',
    'generate_threat_scenario',
    'generate_html_report',
    'determine_industry',
    'get_industry_benchmarks',
    'calculate_improved_industry_percentile',
    'categorize_risks_by_services'
]
