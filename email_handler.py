import os
import logging
import smtplib
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

# Set up logging configuration if not already set
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.DEBUG,
                       format='%(asctime)s - %(levelname)s - %(message)s')

def create_comprehensive_text_summary(scan_results):
    """Create a comprehensive text summary of ALL scan results.
    
    Args:
        scan_results (dict): Dictionary containing all scan results
        
    Returns:
        str: Detailed text summary of the scan
    """
    summary = []
    
    # Overall Risk Assessment
    summary.append("OVERALL RISK ASSESSMENT")
    summary.append("======================")
    
    if 'risk_assessment' in scan_results and 'overall_score' in scan_results['risk_assessment']:
        risk_level = scan_results['risk_assessment']['risk_level']
        overall_score = scan_results['risk_assessment']['overall_score']
        summary.append(f"Risk Level: {risk_level} Risk (Score: {overall_score}/100)")
        
        # Add risk factors if available
        if 'risk_factors' in scan_results['risk_assessment']:
            summary.append("\nRisk Factor Breakdown:")
            for factor in scan_results['risk_assessment']['risk_factors']:
                summary.append(f"• {factor.get('name', 'Unknown Factor')}: Score {factor.get('score', 'N/A')}/10 (Weight: {factor.get('weight', 'N/A')}%)")
    
    # Key Recommendations
    if 'recommendations' in scan_results and scan_results['recommendations']:
        summary.append("\nKEY RECOMMENDATIONS")
        summary.append("==================")
        for rec in scan_results['recommendations']:
            summary.append(f"• {rec}")
    
    # Client System Information
    if 'client_info' in scan_results:
        summary.append("\nCLIENT SYSTEM INFORMATION")
        summary.append("========================")
        client_info = scan_results['client_info']
        if 'os' in client_info:
            summary.append(f"Operating System: {client_info['os']}")
        if 'windows_version' in client_info:
            summary.append(f"Windows Version: {client_info['windows_version']}")
        if 'browser' in client_info:
            summary.append(f"Browser: {client_info['browser']}")
    
    # System Security Status
    if 'system' in scan_results:
        summary.append("\nSYSTEM SECURITY STATUS")
        summary.append("=====================")
        system = scan_results['system']
        
        if 'os_updates' in system:
            summary.append(f"OS Updates: {system['os_updates'].get('message', 'Unknown')} (Severity: {system['os_updates'].get('severity', 'Unknown')})")
        
        if 'firewall' in system:
            summary.append(f"Firewall: {system['firewall'].get('status', 'Unknown')} (Severity: {system['firewall'].get('severity', 'Unknown')})")
    
    # Network Discovery & Gateway Information
    summary.append("\nNETWORK DISCOVERY")
    summary.append("===============")
    
    # Client IP and network type
    client_ip = scan_results.get('client_ip', 'Unknown')
    network_type = scan_results.get('network_type', 'Unknown')
    summary.append(f"Client IP: {client_ip}")
    summary.append(f"Network Type: {network_type}")
    
    # Gateway information
    if 'network' in scan_results and 'gateway' in scan_results['network']:
        gateway = scan_results['network']['gateway']
        if 'info' in gateway:
            summary.append(f"\nGateway Info: {gateway['info']}")
        
        if 'results' in gateway:
            summary.append("\nGateway Security Analysis:")
            for result in gateway['results']:
                if len(result) >= 2:
                    summary.append(f"• {result[0]} (Severity: {result[1]})")
    
    # Network Security - Open Ports
    if 'network' in scan_results and 'open_ports' in scan_results['network']:
        open_ports = scan_results['network']['open_ports']
        summary.append("\nNETWORK SECURITY - OPEN PORTS")
        summary.append("============================")
        
        if 'count' in open_ports:
            summary.append(f"Open Ports Count: {open_ports['count']} (Severity: {open_ports.get('severity', 'Unknown')})")
        
        if 'list' in open_ports and open_ports['list']:
            summary.append("\nOpen Ports List:")
            for port in open_ports['list']:
                # Determine risk level
                risk_level = "Low"
                if port in [21, 23, 3389, 5900, 445, 139]:
                    risk_level = "High"
                elif port in [80, 8080, 110, 143, 25]:
                    risk_level = "Medium"
                
                # Determine service
                service = "Unknown service"
                if port == 21:
                    service = "FTP - File Transfer Protocol"
                elif port == 22:
                    service = "SSH - Secure Shell"
                elif port == 23:
                    service = "Telnet - Insecure remote access"
                elif port == 25:
                    service = "SMTP - Email transmission"
                elif port == 80:
                    service = "HTTP - Web traffic (unencrypted)"
                elif port == 443:
                    service = "HTTPS - Secure web traffic"
                elif port == 3389:
                    service = "RDP - Remote Desktop Protocol"
                elif port == 5900:
                    service = "VNC - Virtual Network Computing"
                elif port == 8080:
                    service = "HTTP Alternate - Often used for proxies"
                elif port == 3306:
                    service = "MySQL Database"
                
                summary.append(f"• Port {port}: {service} (Risk: {risk_level})")
    
    # Web Security - SSL/TLS
    if 'ssl_certificate' in scan_results:
        summary.append("\nWEB SECURITY - SSL/TLS CERTIFICATE")
        summary.append("================================")
        ssl_cert = scan_results['ssl_certificate']
        
        if 'status' in ssl_cert:
            summary.append(f"Certificate Status: {ssl_cert['status']} (Severity: {ssl_cert.get('severity', 'Unknown')})")
        if 'issuer' in ssl_cert:
            summary.append(f"Issuer: {ssl_cert['issuer']}")
        if 'valid_until' in ssl_cert:
            summary.append(f"Valid Until: {ssl_cert['valid_until']}")
        if 'days_remaining' in ssl_cert:
            summary.append(f"Days Remaining: {ssl_cert['days_remaining']}")
        if 'protocol_version' in ssl_cert:
            summary.append(f"Protocol Version: {ssl_cert['protocol_version']}")
        if 'weak_protocol' in ssl_cert:
            summary.append(f"Weak Protocol: {'Yes' if ssl_cert['weak_protocol'] else 'No'}")
        
        # Add specific issues
        if 'is_expired' in ssl_cert and ssl_cert['is_expired']:
            summary.append("\nISSUE: SSL Certificate is expired and needs to be renewed immediately.")
        elif 'expiring_soon' in ssl_cert and ssl_cert['expiring_soon']:
            summary.append(f"\nISSUE: SSL Certificate will expire in {ssl_cert['days_remaining']} days.")
        if 'weak_protocol' in ssl_cert and ssl_cert['weak_protocol']:
            summary.append(f"\nISSUE: Using weak SSL/TLS protocol {ssl_cert['protocol_version']}. Upgrade to TLS 1.2 or higher.")
    
    # Security Headers
    if 'security_headers' in scan_results:
        summary.append("\nWEB SECURITY - HTTP HEADERS")
        summary.append("==========================")
        sec_headers = scan_results['security_headers']
        
        if 'score' in sec_headers:
            summary.append(f"Security Headers Score: {sec_headers['score']}/100 (Severity: {sec_headers.get('severity', 'Unknown')})")
        
        if 'headers' in sec_headers:
            summary.append("\nSecurity Headers Status:")
            for header, found in sec_headers['headers'].items():
                summary.append(f"• {header}: {'Present' if found else 'Missing'}")
    
    # CMS Information
    if 'cms' in scan_results and scan_results['cms'].get('cms_detected'):
        summary.append("\nCONTENT MANAGEMENT SYSTEM (CMS)")
        summary.append("==============================")
        cms = scan_results['cms']
        
        summary.append(f"CMS Name: {cms.get('cms_name', 'Unknown')}")
        summary.append(f"Version: {cms.get('version', 'Unknown')}")
        summary.append(f"Risk Level: {cms.get('severity', 'Unknown')}")
        
        if 'potential_vulnerabilities' in cms and cms['potential_vulnerabilities']:
            summary.append("\nPotential Vulnerabilities:")
            for vuln in cms['potential_vulnerabilities']:
                summary.append(f"• {vuln}")
    
    # Cookies Security
    if 'cookies' in scan_results:
        summary.append("\nCOOKIE SECURITY")
        summary.append("==============")
        cookies = scan_results['cookies']
        
        if 'score' in cookies:
            summary.append(f"Cookie Security Score: {cookies['score']}/100 (Severity: {cookies.get('severity', 'Unknown')})")
        
        if 'total_cookies' in cookies:
            summary.append(f"Total Cookies: {cookies['total_cookies']}")
            
            if 'secure_cookies' in cookies:
                summary.append(f"Secure Cookies: {cookies['secure_cookies']}/{cookies['total_cookies']}")
            if 'httponly_cookies' in cookies:
                summary.append(f"HttpOnly Cookies: {cookies['httponly_cookies']}/{cookies['total_cookies']}")
            if 'samesite_cookies' in cookies:
                summary.append(f"SameSite Cookies: {cookies['samesite_cookies']}/{cookies['total_cookies']}")
    
    # Web Framework Detection
    if 'frameworks' in scan_results and scan_results['frameworks'].get('count', 0) > 0:
        summary.append("\nWEB FRAMEWORKS")
        summary.append("=============")
        frameworks = scan_results['frameworks'].get('frameworks', [])
        summary.append(f"Detected Frameworks: {', '.join(frameworks)}")
    
    # Sensitive Content Analysis
    if 'sensitive_content' in scan_results:
        summary.append("\nSENSITIVE CONTENT ANALYSIS")
        summary.append("=========================")
        sensitive = scan_results['sensitive_content']
        
        paths_found = sensitive.get('sensitive_paths_found', 0)
        summary.append(f"Sensitive Paths Found: {paths_found} (Severity: {sensitive.get('severity', 'Unknown')})")
        
        if 'paths' in sensitive and sensitive['paths']:
            summary.append("\nDetected Sensitive Paths:")
            for path in sensitive['paths']:
                high_risk = path in ['/admin', '/wp-admin', '/administrator', '/phpmyadmin', '/.git', '/.env', '/config.php', '/wp-config.php']
                risk_level = "High" if high_risk else "Medium"
                
                # Determine recommendation
                recommendation = "Review access permissions"
                if path in ['/admin', '/wp-admin', '/administrator', '/phpmyadmin']:
                    recommendation = "Secure with strong authentication and restrict access by IP"
                elif path in ['/.git', '/.env', '/config.php', '/wp-config.php']:
                    recommendation = "Block access via web server configuration"
                elif path in ['/backup', '/db', '/logs']:
                    recommendation = "Move to location outside web root or block access"
                
                summary.append(f"• {path} (Risk: {risk_level}, Recommendation: {recommendation})")
    
    # Email Security
    if 'email_security' in scan_results:
        summary.append("\nEMAIL SECURITY")
        summary.append("=============")
        email_sec = scan_results['email_security']
        
        if 'domain' in email_sec:
            summary.append(f"Domain: {email_sec['domain']}")
        
        for protocol in ['spf', 'dmarc', 'dkim']:
            if protocol in email_sec:
                status = email_sec[protocol].get('status', 'Unknown')
                severity = email_sec[protocol].get('severity', 'Unknown')
                summary.append(f"{protocol.upper()} Record: {status} (Severity: {severity})")
    
    # DNS Configuration
    if 'dns_configuration' in scan_results:
        summary.append("\nDNS CONFIGURATION")
        summary.append("================")
        dns = scan_results['dns_configuration']
        
        if 'a_records' in dns:
            summary.append(f"A Records: {', '.join(dns['a_records'])}")
        if 'mx_records' in dns:
            summary.append(f"MX Records: {', '.join(dns['mx_records'])}")
        if 'ns_records' in dns:
            summary.append(f"NS Records: {', '.join(dns['ns_records'])}")
        if 'txt_records' in dns:
            summary.append(f"TXT Records: {len(dns['txt_records'])} records found")
        
        if 'issues' in dns and dns['issues']:
            summary.append("\nDetected DNS Issues:")
            for issue in dns['issues']:
                summary.append(f"• {issue}")
    
    # Threat Scenarios
    if 'threat_scenarios' in scan_results and scan_results['threat_scenarios']:
        summary.append("\nPOTENTIAL THREAT SCENARIOS")
        summary.append("=========================")
        for threat in scan_results['threat_scenarios']:
            summary.append(f"\n• {threat.get('name', 'Unknown Threat')}")
            summary.append(f"  Description: {threat.get('description', 'No description provided')}")
            summary.append(f"  Impact: {threat.get('impact', 'Unknown')} | Likelihood: {threat.get('likelihood', 'Unknown')}")
    
    return "\n".join(summary)

def send_email_report(lead_data, scan_results, html_report):
    """Send lead info and scan result to your email using a mail relay.
    
    Args:
        lead_data (dict): Dictionary containing lead information (name, email, etc.)
        scan_results (dict): Dictionary containing the full scan results
        html_report (str): HTML string containing the rendered report
    
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    try:
        # Use environment variables for credentials
        smtp_user = os.environ.get('SMTP_USER')
        smtp_password = os.environ.get('SMTP_PASSWORD')
        
        # Check if credentials are available
        if not smtp_user or not smtp_password:
            logging.error("SMTP credentials not found in environment variables")
            logging.warning("Using default test credentials - ONLY FOR DEVELOPMENT!")
            # For development only - REPLACE WITH REAL CREDENTIALS IN PRODUCTION!
            smtp_user = "your_email@example.com"  # Replace with your email
            smtp_password = "your_password"       # Replace with your password
            
        logging.debug(f"Attempting to send email with SMTP user: {smtp_user}")
        
        # Create a multipart message for HTML and text
        msg = MIMEMultipart('alternative')
        msg["Subject"] = f"Security Scan Report - {lead_data.get('company', 'Unknown Company')}"
        msg["From"] = smtp_user
        
        # Send to both the admin and the user
        admin_email = smtp_user
        user_email = lead_data.get("email", "")
        recipients = f"{admin_email}, {user_email}"
        msg["To"] = recipients
        
        logging.debug(f"Email recipients: {recipients}")
        
        # Create the comprehensive text summary
        comprehensive_summary = create_comprehensive_text_summary(scan_results)
        
        # Compose the plain text body
        text_body = f"""
Security Scan Report

CLIENT INFORMATION:
Name: {lead_data.get('name', '')}
Email: {lead_data.get('email', '')}
Company: {lead_data.get('company', '')}
Phone: {lead_data.get('phone', '')}
Timestamp: {lead_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}

--- COMPREHENSIVE SECURITY SCAN RESULTS ---

{comprehensive_summary}

--- END OF COMPREHENSIVE RESULTS ---

NEXT STEPS:
Our security experts can help you implement the recommendations from this report. 
Our services include:
• Vulnerability Remediation
• Network Security Configuration
• Email Security Setup
• System Security Updates
• Web Application Hardening
• Security Awareness Training
• Ongoing Security Monitoring

We look forward to partnering with you for all your IT and cybersecurity needs.
You can reach us through our website at cengatech.com, by email at sales@cengatech.com, or by phone at 470-481-0400.

Thank you,
The Cengatech Team
        """
        
        # Create text part
        part1 = MIMEText(text_body, 'plain')
        
        # Create HTML part - use the HTML report
        part2 = MIMEText(html_report, 'html')
        
        # Add parts to message
        msg.attach(part1)
        msg.attach(part2)
        
        # Try different ports if needed
        smtp_server = "mail.privateemail.com"  # Change to your SMTP server
        smtp_port = 587  # 587 is typical for authenticated TLS
        
        logging.debug(f"Connecting to SMTP server: {smtp_server}:{smtp_port}")
        
        try:
            with smtplib.SMTP(smtp_server, smtp_port, timeout=30) as server:
                logging.debug("SMTP connection established")
                server.ehlo()
                logging.debug("EHLO successful")
                server.starttls()
                logging.debug("STARTTLS successful")
                server.ehlo()
                logging.debug("Second EHLO successful")
                server.login(smtp_user, smtp_password)
                logging.debug("SMTP login successful")
                server.send_message(msg)
                logging.debug("Email sent successfully!")
                return True
        except Exception as smtp_error:
            logging.error(f"Primary SMTP attempt failed: {smtp_error}")
            
            # Fallback to alternative port or server
            try:
                smtp_port = 465  # Try alternative port for SSL
                logging.debug(f"Trying alternative port: {smtp_port}")
                
                with smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=30) as server:
                    logging.debug("SMTP_SSL connection established")
                    server.login(smtp_user, smtp_password)
                    logging.debug("SMTP login successful")
                    server.send_message(msg)
                    logging.debug("Email sent successfully via alternative method!")
                    return True
            except Exception as fallback_error:
                logging.error(f"Fallback SMTP attempt also failed: {fallback_error}")
                raise  # Re-raise to be caught by the outer exception handler
            
    except Exception as e:
        logging.error(f"Error sending email: {e}")
        if isinstance(e, smtplib.SMTPAuthenticationError):
            logging.error("SMTP Authentication failed - check username and password")
        elif isinstance(e, smtplib.SMTPConnectError):
            logging.error("Failed to connect to SMTP server - check server and port")
        elif isinstance(e, smtplib.SMTPDataError):
            logging.error("The SMTP server refused to accept the message data")
        elif isinstance(e, smtplib.SMTPRecipientsRefused):
            logging.error("All recipients were refused - check email addresses")
        return False
