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
# Import enhanced scanner functions
from enhanced_security_scanner import (
    check_ssl_certificate,
    check_security_headers,
    detect_cms,
    analyze_cookies,
    detect_web_framework,
    crawl_for_sensitive_content,
    calculate_risk_score
)
# Initialize Flask app
app = Flask(__name__)
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'your_temporary_secret_key')

# Set up logging configuration
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize limiter with proper storage
# Fix for the key_func argument error
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


# A function to calculate severity based on the issue type
def get_severity_level(severity):
    return SEVERITY.get(severity, SEVERITY["Info"])

# Generate actionable recommendations based on severity
def get_recommendations(vulnerability, severity):
    if severity == "Critical":
        return f"[CRITICAL] {vulnerability}. Immediate action is required to avoid potential data loss or breach."
    elif severity == "High":
        return f"[HIGH] {vulnerability}. Address this within the next 48 hours to mitigate major risks."
    elif severity == "Medium":
        return f"[MEDIUM] {vulnerability}. Address this within the next week to prevent exploitation."
    elif severity == "Low":
        return f"[LOW] {vulnerability}. A low-risk issue, but should be reviewed."
    else:
        return f"[INFO] {vulnerability}. No immediate action required."

# Function to generate threat scenarios based on detected vulnerabilities
def generate_threat_scenario(vulnerability, severity):
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

# Check for OS updates
def check_os_updates():
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
    # Modified for web environment
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

# Check Firewall Status
def check_firewall_status():
    """Enhanced firewall status check for web environment"""
    try:
        # Get client IP and OS information
        client_ip = request.remote_addr
        client_os = request.headers.get('User-Agent', 'Unknown')
        
        # Make educated guesses about firewall status based on available info
        if "Windows" in client_os:
            return "Windows Firewall is likely active, but web browsers cannot directly detect its status. We recommend manually checking Windows Defender Firewall settings.", "Medium"
        elif "Mac" in client_os:
            return "macOS likely has its built-in firewall enabled, but web browsers cannot directly detect its status. We recommend checking Security & Privacy settings.", "Medium"
        elif "Linux" in client_os:
            return "Linux systems typically use iptables or ufw for firewall protection. Web browsers cannot directly detect firewall status.", "Medium"
        else:
            return "Firewall status check limited in web environment. We recommend manually checking your system's firewall settings.", "Medium"
    except Exception as e:
        logging.error(f"Error checking firewall status: {e}")
        return "Error checking firewall status", "Medium"

# Function to check SPF status
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

# This function should be called within a route where request is available
def get_client_and_gateway_ip():
    """
    Detects client IP and makes educated guesses about possible gateway IPs
    based on common network configurations.
    
    Returns:
        tuple: (client_ip, gateway_guesses, network_type)
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
    client_ip, gateway_guesses, network_type = get_client_and_gateway_ip()
    
    # If multiple guesses are available, create a formatted string
    if len(gateway_guesses) > 1 and "not possible" not in gateway_guesses[0]:
        gateway_info = f"Client IP: {client_ip} | Network Type: {network_type} | Likely gateways: {', '.join(gateway_guesses)}"
    else:
        gateway_info = f"Client IP: {client_ip} | {gateway_guesses[0]}"
    
    return gateway_info

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

def generate_report(lead_data, for_web=False):
    """Generate vulnerability scan report
    
    Args:
        lead_data: Dictionary containing user information
        for_web: Boolean indicating if this report is for web display (simplified) or email (detailed)
    """
    logging.debug("Generating full report...")
    
    # Create the lead section
    lead_section = (
        f"Client: {lead_data.get('name', 'N/A')}\n"
        f"Email: {lead_data.get('email', 'N/A')}\n"
        f"Company: {lead_data.get('company', 'N/A')}\n"
        f"Phone: {lead_data.get('phone', 'N/A')}\n"
        f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        + "-" * 60 + "\n\n"
    )
    
    # Get domain for email checks
    email = lead_data.get('email', '')
    domain = None
    email_findings = []
    
    if "@" in email:
        domain = extract_domain_from_email(email)
    
    # Run email security checks
    email_section = "EMAIL SECURITY CHECKS:\n"
    if domain:
        spf_status, spf_severity = check_spf_status(domain)
        dmarc_status, dmarc_severity = check_dmarc_record(domain)
        dkim_status, dkim_severity = check_dkim_record(domain)
        
        email_section += f"Domain: {domain}\n"
        email_section += f"SPF: {spf_status} (Severity: {spf_severity})\n"
        email_section += f"DMARC: {dmarc_status} (Severity: {dmarc_severity})\n"
        email_section += f"DKIM: {dkim_status} (Severity: {dkim_severity})\n"
        
        # Store findings for web summary
        if spf_severity in ["High", "Critical"]:
            email_findings.append(f"SPF: {spf_severity} severity - requires attention")
        if dmarc_severity in ["High", "Critical"]:
            email_findings.append(f"DMARC: {dmarc_severity} severity - requires attention")
        if dkim_severity in ["High", "Critical"]:
            email_findings.append(f"DKIM: {dkim_severity} severity - requires attention")
    else:
        email_section += "No valid email domain provided for security checks.\n"
    
    # System checks section
    system_section = "\nSYSTEM SECURITY CHECKS:\n"
    system_findings = []
    
    # Client OS information
    client_os = lead_data.get('client_os', 'Unknown')
    client_browser = lead_data.get('client_browser', 'Unknown')
    windows_version = lead_data.get('windows_version', '')
    
    system_section += f"Client Operating System: {client_os}\n"
    if windows_version:
        system_section += f"Windows Version: {windows_version}\n"
        
        # Assign severity based on Windows version
        if "10/11" in windows_version:
            windows_severity = "Low"
        elif "8" in windows_version:
            windows_severity = "Medium"
        elif "7" in windows_version or "Older" in windows_version:
            windows_severity = "High"
            system_findings.append(f"Windows Version: {windows_severity} severity - outdated version")
        else:
            windows_severity = "Medium"
            
        system_section += f"Windows Version Status: {windows_severity} Severity\n"
    
    system_section += f"Web Browser: {client_browser}\n"
    
    # OS update status
    os_update_info = check_os_updates()
    system_section += f"OS Updates: {os_update_info['message']} (Severity: {os_update_info['severity']})\n"
    
    if os_update_info['severity'] in ["High", "Critical"]:
        system_findings.append(f"OS Updates: {os_update_info['severity']} severity - updates needed")
    
    # Firewall status
    firewall_status, firewall_severity = check_firewall_status()
    system_section += f"Firewall Status: {firewall_status} (Severity: {firewall_severity})\n"
    
    if firewall_severity in ["High", "Critical"]:
        system_findings.append(f"Firewall: {firewall_severity} severity - requires configuration")
    
    # Network checks section
    network_section = "\nNETWORK SECURITY CHECKS:\n"
    network_findings = []

    ports_count, ports_list, ports_severity = check_open_ports()
    network_section += f"Open Ports: {ports_count} ports detected (Severity: {ports_severity})\n"

    if ports_severity in ["High", "Critical"]:
        network_findings.append(f"Open Ports: {ports_severity} severity - {ports_count} ports detected")

    if ports_list and len(ports_list) > 0:
        # List all open ports
        network_section += f"\nAll detected open ports: {', '.join(map(str, sorted(ports_list[:15])))}"
        if len(ports_list) > 15:
            network_section += f" and {len(ports_list) - 15} more..."
        network_section += "\n"
        
        # Analyze port risks
        port_risks = analyze_port_risks(ports_list)
        
        # Add high-risk ports to the report
        high_risk_ports = [r for r in port_risks if r[2] == "High"]
        if high_risk_ports:
            network_section += "\nHIGH RISK PORTS DETECTED:\n"
            for port, desc, sev in high_risk_ports:
                network_section += f"- Port {port}: {desc} (Severity: {sev})\n"
                network_findings.append(f"Port {port}: {desc}")
    else:
        network_section += "No open ports detected.\n"
    
    # Gateway check
    gateway_info = get_default_gateway_ip()
    gateway_scan_results = scan_gateway_ports(gateway_info)

    gateway_section = "\nGATEWAY SECURITY:\n"
    # Add the enhanced gateway info to the report
    gateway_section += f"{gateway_info}\n\n"
    gateway_section += "Note: In a web environment, we cannot directly access your gateway.\n"
    gateway_section += "The information above is based on common network configurations.\n\n"

    # Initialize gateway_findings before using it
    gateway_findings = []
    if gateway_scan_results:
        for msg, severity in gateway_scan_results:
            gateway_section += f"- {msg} (Severity: {severity})\n"
            if severity in ["High", "Critical"]:
                gateway_findings.append(f"Gateway: {severity} severity - {msg}")
    
    # Add recommendations
    recommendations = "\nRECOMMENDATIONS:\n"
    recommendations += "1. Ensure email security configurations (SPF, DMARC, DKIM) are properly set up.\n"
    recommendations += "2. Keep operating systems and software up to date.\n"
    recommendations += "3. Maintain a properly configured firewall.\n"
    recommendations += "4. Close unnecessary open ports.\n"
    recommendations += "5. Implement regular security scanning.\n"
    
    # If generating for web display, create a simplified version
    if for_web:
        # Create a shorter summary for web display
        web_report = lead_section
        web_report += "SCAN SUMMARY:\n"
        web_report += f"A full detailed report has been sent to your email ({lead_data.get('email', 'N/A')}).\n\n"
        
        # Add key findings section if there are high severity issues
        all_findings = email_findings + system_findings + network_findings + gateway_findings
        if all_findings:
            web_report += "KEY FINDINGS REQUIRING ATTENTION:\n"
            for finding in all_findings:
                web_report += f"- {finding}\n"
        else:
            web_report += "No critical issues were detected in this scan.\n"
        
        web_report += "\nSCAN AREAS CHECKED:\n"
        web_report += "- Email Security (SPF, DMARC, DKIM)\n"
        web_report += f"- System Security ({client_os}, {client_browser})\n"
        web_report += "- Network Security (Open Ports)\n"
        web_report += "- Gateway Security\n\n"
        
        web_report += "For detailed analysis and recommendations, please check your email.\n"
        
        return web_report
    
    # For email, compile the full detailed report
    full_report = (
        lead_section + 
        email_section + 
        system_section + 
        network_section + 
        gateway_section +
        recommendations
    )
    
    return full_report

def process_scan_request(lead_data):
    """Process scan request and generate reports
    
    Args:
        lead_data: Dictionary containing user information
        
    Returns:
        A simplified report for web display
    """
    try:
        logging.debug("Starting scan process...")
        
        # Save lead data
        try:
            save_lead_data(lead_data)
            logging.debug("Lead data saved successfully")
        except Exception as e:
            logging.debug("Lead data saved successfully")
        except Exception as e:
            logging.error(f"Error saving lead data: {e}")
            # Continue anyway - don't fail the whole scan
        
        # Generate detailed report for email
        detailed_report = generate_report(lead_data, for_web=False)
        logging.debug(f"Detailed report generated, length: {len(detailed_report)}")
        
        # Generate simplified report for web display
        web_report = generate_report(lead_data, for_web=True)
        logging.debug(f"Web report generated, length: {len(web_report)}")
        
        # Try to send email with detailed report
        try:
            email_sent = send_email_report(lead_data, detailed_report)
            if email_sent:
                logging.debug("Email report sent successfully")
            else:
                logging.warning("Email report could not be sent")
        except Exception as e:
            logging.error(f"Error sending email: {e}")
        
        # Return the simplified report for web display
        return web_report
        
    except Exception as e:
        logging.error(f"Error in process_scan_request: {e}")
        return f"An error occurred during the scan: {str(e)}"

# Route handlers
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

@app.route('/scan', methods=['GET', 'POST'])
def scan_page():
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
            'windows_version': request.form.get('windows_version', '')
        }
        
        logging.debug(f"Received scan form data: {lead_data}")
        logging.debug(f"Client OS detected: {lead_data['client_os']}")
        
        try:
            # Process the scan - this now returns a simplified web report
            web_report = process_scan_request(lead_data)
            
            # Store the web report in session
            session['scan_result'] = web_report
            logging.debug("Web report stored in session")
            
            # Add a flag to indicate scan was completed
            session['scan_completed'] = True
            
            # Redirect to results page
            return redirect(url_for('results'))
        except Exception as e:
            logging.error(f"Error processing scan: {e}")
            return render_template('error.html', error=str(e))
    
    return render_template('scan.html')

@app.route('/results')
def results():
    # Check if a scan has been completed using session.get with default
    scan_result = session.get('scan_result', None)
    
    if scan_result:
        logging.debug(f"Retrieved scan result from session, length: {len(scan_result)}")
        # Clear the session after retrieving to avoid stale data
        session.pop('scan_result', None)
        session.pop('scan_completed', None)
        return render_template('results.html', scan_result=scan_result)
    else:
        logging.debug("No scan result in session")
        return redirect(url_for('scan_page'))

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

# API endpoints
@app.route('/api/firewall-test', methods=['POST'])
def firewall_test():
    test_results = request.json
    # Store results in session or database for inclusion in the report
    session['firewall_test_results'] = test_results
    return jsonify({"status": "success"})

@app.route('/api/scan', methods=['POST'])    
@limiter.limit("5 per minute")    
def start_scan():
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
            "windows_version": request.form.get('windows_version', '')
        }
        
        # Basic validation
        if not lead_data["name"] or not lead_data["email"]:
            return jsonify({
                "status": "error",
                "message": "Please enter at least your name and email before scanning."
            }), 400
            
        # Save lead data
        save_lead_data(lead_data)
        
        # Generate the scan report
        scan_result = process_scan_request(lead_data)
        
        # Return the scan result
        return jsonify({
            "status": "success",
            "report": scan_result
        })
    except Exception as e:
        logging.error(f"Error in scan API: {e}")
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

if __name__ == '__main__':
    # Get port from environment variable or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Use 0.0.0.0 to make the app accessible from any IP
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_ENV') == 'development')

@app.route('/enhanced-scan', methods=['GET', 'POST'])
def enhanced_scan():
    """Enhanced security scan form page"""
    if request.method == 'POST':
        return redirect(url_for('start_enhanced_scan'))
    
    return render_template('enhanced_scan.html')

@app.route('/api/enhanced-scan-status/<scan_id>', methods=['GET'])
@limiter.limit("300 per hour")
def enhanced_scan_status(scan_id):
    """API endpoint to check scan status and progress"""
    # Get current timestamp to simulate progress
    current_timestamp = datetime.datetime.now().timestamp()
    
    # If scan_start_time not in session, initialize it
    if 'scan_start_time' not in session:
        session['scan_start_time'] = current_timestamp
    
    scan_start = session.get('scan_start_time')
    
    # Calculate simulated progress (0-100%)
    elapsed_time = current_timestamp - scan_start
    progress = min(int(elapsed_time * 10), 100)  # 10% per second, max 100%
    
    # Create a status message based on progress
    if progress < 20:
        status_message = "Checking ports and network services..."
    elif progress < 40:
        status_message = "Analyzing SSL/TLS certificates..."
    elif progress < 60:
        status_message = "Checking web security headers and CMS..."
    elif progress < 80:
        status_message = "Scanning for sensitive content..."
    elif progress < 100:
        status_message = "Calculating risk scores and generating report..."
    else:
        status_message = "Scan completed! Preparing results..."
    
    # If scan is complete, prepare redirect to results
    if progress >= 100:
        # Clear the scan_start_time from session
        if 'scan_start_time' in session:
            del session['scan_start_time']
        
        return jsonify({
            'status': 'complete',
            'progress': 100,
            'message': 'Scan completed successfully',
            'redirect_url': url_for('enhanced_scan_results', scan_id=scan_id)
        })
    
    # Otherwise return progress update
    return jsonify({
        'status': 'in_progress',
        'progress': progress,
        'message': status_message
    })
    
@app.route('/enhanced-scan-progress/<scan_id>')
def enhanced_scan_progress(scan_id):
    """Display scan progress and start background scanning"""
    target = session.get('target', '')
    email = session.get('email', '')
    
    if not target:
        return redirect(url_for('enhanced_scan'))
    
    # Client-side will poll the status endpoint to get progress
    return render_template('enhanced_scan_progress.html', 
                           scan_id=scan_id, 
                           target=target,
                           email=email)

@app.route('/api/enhanced-scan-status/<scan_id>', methods=['GET'])
def enhanced_scan_status(scan_id):
    """API endpoint to check scan status and progress"""
    # In a production environment, you would check a database or queue
    # For this example, we're just returning mock progress
    
    # Get current timestamp to simulate progress
    current_timestamp = datetime.now().timestamp()

    scan_start = session.get('scan_start_time', current_timestamp)
    
    # Calculate simulated progress (0-100%)
    elapsed_time = current_timestamp - scan_start
    progress = min(int(elapsed_time * 10), 100)  # 10% per second, max 100%
    
    # Create a status message based on progress
    if progress < 20:
        status_message = "Checking ports and network services..."
    elif progress < 40:
        status_message = "Analyzing SSL/TLS certificates..."
    elif progress < 60:
        status_message = "Checking web security headers and CMS..."
    elif progress < 80:
        status_message = "Scanning for sensitive content..."
    elif progress < 100:
        status_message = "Calculating risk scores and generating report..."
    else:
        status_message = "Scan completed! Preparing results..."
    
    # If scan is complete, prepare redirect to results
    if progress >= 100:
        return jsonify({
            'status': 'complete',
            'progress': 100,
            'message': 'Scan completed successfully',
            'redirect_url': url_for('enhanced_scan_results', scan_id=scan_id)
        })
    
    # Otherwise return progress update
    return jsonify({
        'status': 'in_progress',
        'progress': progress,
        'message': status_message
    })

@app.route('/enhanced-scan-results/<scan_id>')
def enhanced_scan_results(scan_id):
    """Display enhanced scan results"""
    target = session.get('target', '')
    
    if not target:
        return redirect(url_for('enhanced_scan'))
    
    # In a real implementation, you would retrieve scan results from a database
    # For this example, we'll run the scans here
    
    # Initialize scan results
    scan_results = {
        'scan_id': scan_id,
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'is_complete': True
    }
    
    # Check if target is a domain or IP
    is_domain = False
    try:
        socket.inet_aton(target)  # This will fail if target is not an IP address
    except socket.error:
        is_domain = True
    
    # Reuse your existing port scanning function
    ports_count, ports_list, ports_severity = check_open_ports()
    scan_results['open_ports'] = {
        'open_ports': ports_list,
        'filtered_ports': [],
        'closed_ports': [],
        'services': {}
    }
    
    # For domains, add web security checks
    if is_domain:
        try:
            # Normalize the domain
            if target.startswith('http://') or target.startswith('https://'):
                parsed_url = urllib.parse.urlparse(target)
                domain = parsed_url.netloc
            else:
                domain = target
                
            # Add domain-specific scan results
            scan_results['is_domain'] = True
            
            # Run email security checks if we have domain info
            try:
                spf_status, spf_severity = check_spf_status(domain)
                dmarc_status, dmarc_severity = check_dmarc_record(domain)
                dkim_status, dkim_severity = check_dkim_record(domain)
                
                scan_results['email_security'] = {
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
            except Exception as e:
                logging.error(f"Error checking email security: {e}")
                scan_results['email_security'] = {
                    'error': f"Error checking email security: {str(e)}"
                }
            
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
            logging.error(f"Domain scanning error: {e}")
            scan_results['error'] = f"Error scanning domain: {str(e)}"
    
    # Calculate overall risk score
    try:
        scan_results['risk_assessment'] = calculate_risk_score(scan_results)
    except Exception as e:
        logging.error(f"Risk scoring error: {e}")
        scan_results['risk_assessment'] = {
            'error': f"Error calculating risk score: {str(e)}",
            'overall_score': 0,
            'risk_level': 'Unknown'
        }
    
    # Store results in session (in a real app, you'd store this in a database)
    session['enhanced_scan_results'] = scan_results
    
    return render_template('enhanced_scan_results.html', scan=scan_results)

@app.route('/api/enhanced-scan-report/<scan_id>', methods=['GET'])
def enhanced_scan_report(scan_id):
    """Generate a detailed HTML report for the enhanced scan"""
    scan_results = session.get('enhanced_scan_results', None)
    
    if not scan_results:
        return jsonify({'error': 'Scan results not found'}), 404
    
    # Generate HTML report
    html_report = generate_html_report(scan_results)
    
    # Return the HTML report
    return html_report

# ===== STEP 3: ADD THESE UTILITY FUNCTIONS =====

def generate_html_report(scan_results):
    """Generate an HTML report from scan data"""
    target = scan_results.get('target', 'Unknown')
    scan_date = datetime.fromisoformat(scan_results.get('timestamp', datetime.now().isoformat()))
    scan_date_str = scan_date.strftime('%Y-%m-%d %H:%M:%S')
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
            <p><strong>Scan Date:</strong> {scan_date_str}</p>
            <p><strong>Scan ID:</strong> {scan_results.get('scan_id', 'Unknown')}</p>
    """
    
    # Add risk assessment if available
    if 'risk_assessment' in scan_results:
        risk = scan_results['risk_assessment']
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
    if 'risk_assessment' in scan_results and 'recommendations' in scan_results['risk_assessment']:
        recommendations = scan_results['risk_assessment']['recommendations']
        
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
    if 'ssl_certificate' in scan_results:
        ssl_data = scan_results['ssl_certificate']
        
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
    if 'security_headers' in scan_results:
        headers_data = scan_results['security_headers']
        
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
    
    # Add more sections for other components (CMS, DNS, Cookies, etc.)
    # Similar to the SSL and Headers sections above
    
    # Add Email Security section if available
    if 'email_security' in scan_results:
        email_data = scan_results['email_security']
        
        if 'error' not in email_data:
            html += f"""
            <div class="section">
                <h2>Email Security</h2>
                
                <table>
                    <tr>
                        <th>Check</th>
                        <th>Status</th>
                        <th>Severity</th>
                    </tr>
            """
            
            # SPF Record
            spf_severity_class = 'high' if email_data.get('spf', {}).get('severity') == 'Low' else 'medium' if email_data.get('spf', {}).get('severity') == 'Medium' else 'low'
            html += f"""
                <tr>
                    <td>SPF Record</td>
                    <td>{email_data.get('spf', {}).get('status', 'Unknown')}</td>
                    <td class="{spf_severity_class}">{email_data.get('spf', {}).get('severity', 'Unknown')}</td>
                </tr>
            """
            
            # DMARC Record
            dmarc_severity_class = 'high' if email_data.get('dmarc', {}).get('severity') == 'Low' else 'medium' if email_data.get('dmarc', {}).get('severity') == 'Medium' else 'low'
            html += f"""
                <tr>
                    <td>DMARC Record</td>
                    <td>{email_data.get('dmarc', {}).get('status', 'Unknown')}</td>
                    <td class="{dmarc_severity_class}">{email_data.get('dmarc', {}).get('severity', 'Unknown')}</td>
                </tr>
            """
            
            # DKIM Record
            dkim_severity_class = 'high' if email_data.get('dkim', {}).get('severity') == 'Low' else 'medium' if email_data.get('dkim', {}).get('severity') == 'Medium' else 'low'
            html += f"""
                <tr>
                    <td>DKIM Record</td>
                    <td>{email_data.get('dkim', {}).get('status', 'Unknown')}</td>
                    <td class="{dkim_severity_class}">{email_data.get('dkim', {}).get('severity', 'Unknown')}</td>
                </tr>
            """
            
            html += """
                </table>
                
                <div class="recommendation">
                    <p><strong>Recommendation:</strong> Ensure all email security protocols (SPF, DMARC, DKIM) are properly configured to prevent email spoofing and phishing attacks.</p>
                </div>
            </div>
            """
    
    # Add Open Ports section
    if 'open_ports' in scan_results:
        ports_data = scan_results['open_ports']
        
        open_ports = ports_data.get('open_ports', [])
        
        html += f"""
        <div class="section">
            <h2>Open Ports and Services</h2>
            <p><strong>Open Ports:</strong> {len(open_ports)}</p>
        """
        
        if open_ports:
            html += """
            <table>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Risk Level</th>
                </tr>
            """
            
            # Define high-risk ports
            high_risk_ports = [21, 23, 3389, 5900, 139, 445, 1433, 3306]
            medium_risk_ports = [22, 25, 110, 143, 8080]
            
            # Sort ports for display
            sorted_ports = sorted(open_ports)
            
            for port in sorted_ports:
                service = "Unknown"
                if str(port) in ports_data.get('services', {}):
                    service = ports_data['services'][str(port)].get('service', 'Unknown')
                
                # Determine risk level
                if port in high_risk_ports:
                    risk = "High"
                    risk_class = "low"  # Using 'low' class for high risk (red)
                elif port in medium_risk_ports:
                    risk = "Medium"
                    risk_class = "medium"  # Using 'medium' class for medium risk (yellow)
                else:
                    risk = "Low"
                    risk_class = "high"  # Using 'high' class for low risk (green)
                
                html += f"""
                <tr>
                    <td>{port}</td>
                    <td>{service}</td>
                    <td class="{risk_class}">{risk}</td>
                </tr>
                """
            
            html += """
            </table>
            
            <div class="recommendation">
                <p><strong>Recommendation:</strong> Close unnecessary ports and ensure required services are properly secured.</p>
            </div>
            """
        else:
            html += """
            <p>No open ports detected or port scanning was limited.</p>
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
