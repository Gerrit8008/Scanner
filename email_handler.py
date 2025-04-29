import os
import logging
import smtplib
import json
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

# Set up logging configuration if not already set
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.DEBUG,
                       format='%(asctime)s - %(levelname)s - %(message)s')

def create_detailed_text_summary(scan_results):
    """Create a detailed text summary of all scan results.
    
    Args:
        scan_results (dict): Dictionary containing all scan results
        
    Returns:
        str: Detailed text summary of the scan
    """
    summary = []
    
    # Overall Risk Assessment
    if 'risk_assessment' in scan_results and 'overall_score' in scan_results['risk_assessment']:
        risk_level = scan_results['risk_assessment']['risk_level']
        overall_score = scan_results['risk_assessment']['overall_score']
        summary.append(f"OVERALL RISK ASSESSMENT: {risk_level} Risk (Score: {overall_score}/100)")
    
    # Key Recommendations
    if 'recommendations' in scan_results and scan_results['recommendations']:
        summary.append("\nKEY RECOMMENDATIONS:")
        for rec in scan_results['recommendations']:
            summary.append(f"• {rec}")
    
    # Client System Information
    if 'client_info' in scan_results:
        summary.append("\nCLIENT SYSTEM INFORMATION:")
        if 'os' in scan_results['client_info']:
            summary.append(f"Operating System: {scan_results['client_info']['os']}")
        if 'windows_version' in scan_results['client_info']:
            summary.append(f"Windows Version: {scan_results['client_info']['windows_version']}")
        if 'browser' in scan_results['client_info']:
            summary.append(f"Browser: {scan_results['client_info']['browser']}")
    
    # System Security
    if 'system' in scan_results:
        summary.append("\nSYSTEM SECURITY:")
        if 'os_updates' in scan_results['system']:
            summary.append(f"OS Updates: {scan_results['system']['os_updates']['message']} (Severity: {scan_results['system']['os_updates']['severity']})")
        if 'firewall' in scan_results['system']:
            summary.append(f"Firewall: {scan_results['system']['firewall']['status']} (Severity: {scan_results['system']['firewall']['severity']})")
    
    # Network Discovery & Gateway Information
    summary.append("\nNETWORK DISCOVERY:")
    client_ip = scan_results.get('client_ip', 'Unknown')
    network_type = scan_results.get('network_type', 'Unknown')
    summary.append(f"Client IP: {client_ip}")
    summary.append(f"Network Type: {network_type}")
    
    # Gateway port analysis
    if 'network' in scan_results and 'gateway' in scan_results['network']:
        summary.append("\nGATEWAY SECURITY ANALYSIS:")
        if 'info' in scan_results['network']['gateway']:
            summary.append(f"Gateway Info: {scan_results['network']['gateway']['info']}")
        if 'results' in scan_results['network']['gateway']:
            for result in scan_results['network']['gateway']['results']:
                if len(result) >= 2:
                    summary.append(f"• {result[0]} (Severity: {result[1]})")
    
    # Network Security
    if 'network' in scan_results and 'open_ports' in scan_results['network']:
        summary.append("\nNETWORK SECURITY:")
        if 'count' in scan_results['network']['open_ports']:
            summary.append(f"Open Ports: {scan_results['network']['open_ports']['count']} detected (Severity: {scan_results['network']['open_ports'].get('severity', 'Unknown')})")
        if 'list' in scan_results['network']['open_ports']:
            summary.append("Open Ports List:")
            for port in scan_results['network']['open_ports']['list']:
                risk_level = "High" if port in [21, 23, 3389, 5900, 445, 139] else "Medium" if port in [80, 8080, 110, 143, 25] else "Low"
                summary.append(f"• Port {port} (Risk: {risk_level})")
    
    # Web Security
    if 'ssl_certificate' in scan_results:
        summary.append("\nWEB SECURITY - SSL/TLS:")
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
    
    # Security Headers
    if 'security_headers' in scan_results:
        summary.append("\nSECURITY HEADERS:")
        if 'score' in scan_results['security_headers']:
            summary.append(f"Security Headers Score: {scan_results['security_headers']['score']}/100 (Severity: {scan_results['security_headers'].get('severity', 'Unknown')})")
        if 'headers' in scan_results['security_headers']:
            for header, found in scan_results['security_headers']['headers'].items():
                summary.append(f"• {header}: {'Present' if found else 'Missing'}")
    
    # CMS Information
    if 'cms' in scan_results and scan_results['cms'].get('cms_detected'):
        summary.append("\nCONTENT MANAGEMENT SYSTEM:")
        summary.append(f"CMS Name: {scan_results['cms'].get('cms_name', 'Unknown')}")
        summary.append(f"Version: {scan_results['cms'].get('version', 'Unknown')}")
        summary.append(f"Risk Level: {scan_results['cms'].get('severity', 'Unknown')}")
        if 'potential_vulnerabilities' in scan_results['cms'] and scan_results['cms']['potential_vulnerabilities']:
            summary.append("Potential Vulnerabilities:")
            for vuln in scan_results['cms']['potential_vulnerabilities']:
                summary.append(f"• {vuln}")
    
    # Cookies Security
    if 'cookies' in scan_results:
        summary.append("\nCOOKIE SECURITY:")
        if 'score' in scan_results['cookies']:
            summary.append(f"Cookie Security Score: {scan_results['cookies']['score']}/100 (Severity: {scan_results['cookies'].get('severity', 'Unknown')})")
        if 'total_cookies' in scan_results['cookies']:
            summary.append(f"Total Cookies: {scan_results['cookies']['total_cookies']}")
            if 'secure_cookies' in scan_results['cookies']:
                summary.append(f"Secure Cookies: {scan_results['cookies']['secure_cookies']}/{scan_results['cookies']['total_cookies']}")
            if 'httponly_cookies' in scan_results['cookies']:
                summary.append(f"HttpOnly Cookies: {scan_results['cookies']['httponly_cookies']}/{scan_results['cookies']['total_cookies']}")
            if 'samesite_cookies' in scan_results['cookies']:
                summary.append(f"SameSite Cookies: {scan_results['cookies']['samesite_cookies']}/{scan_results['cookies']['total_cookies']}")
    
    # Web Framework Detection
    if 'frameworks' in scan_results and scan_results['frameworks'].get('count', 0) > 0:
        summary.append("\nWEB FRAMEWORKS:")
        summary.append(f"Detected Frameworks: {', '.join(scan_results['frameworks'].get('frameworks', []))}")
    
    # Sensitive Content Analysis
    if 'sensitive_content' in scan_results:
        summary.append("\nSENSITIVE CONTENT ANALYSIS:")
        sensitive_paths_found = scan_results['sensitive_content'].get('sensitive_paths_found', 0)
        summary.append(f"Sensitive Paths Found: {sensitive_paths_found} (Severity: {scan_results['sensitive_content'].get('severity', 'Unknown')})")
        if 'paths' in scan_results['sensitive_content'] and scan_results['sensitive_content']['paths']:
            summary.append("Detected Sensitive Paths:")
            for path in scan_results['sensitive_content']['paths']:
                high_risk = path in ['/admin', '/wp-admin', '/administrator', '/phpmyadmin', '/.git', '/.env', '/config.php', '/wp-config.php']
                risk_level = "High" if high_risk else "Medium"
                summary.append(f"• {path} (Risk: {risk_level})")
    
    # Email Security
    if 'email_security' in scan_results:
        summary.append("\nEMAIL SECURITY:")
        if 'domain' in scan_results['email_security']:
            summary.append(f"Domain: {scan_results['email_security']['domain']}")
        if 'spf' in scan_results['email_security']:
            summary.append(f"SPF Record: {scan_results['email_security']['spf'].get('status', 'Unknown')} (Severity: {scan_results['email_security']['spf'].get('severity', 'Unknown')})")
        if 'dmarc' in scan_results['email_security']:
            summary.append(f"DMARC Record: {scan_results['email_security']['dmarc'].get('status', 'Unknown')} (Severity: {scan_results['email_security']['dmarc'].get('severity', 'Unknown')})")
        if 'dkim' in scan_results['email_security']:
            summary.append(f"DKIM Record: {scan_results['email_security']['dkim'].get('status', 'Unknown')} (Severity: {scan_results['email_security']['dkim'].get('severity', 'Unknown')})")
    
    # Threat Scenarios
    if 'threat_scenarios' in scan_results:
        summary.append("\nTHREAT SCENARIO ANALYSIS:")
        for threat in scan_results['threat_scenarios']:
            summary.append(f"\n- {threat.get('name', 'Unknown Threat')}")
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
        
        # Create the detailed text summary
        detailed_summary = create_detailed_text_summary(scan_results)
        
        # Compose the plain text body
        text_body = f"""
Security Scan Report

CLIENT INFORMATION:
Name: {lead_data.get('name', '')}
Email: {lead_data.get('email', '')}
Company: {lead_data.get('company', '')}
Phone: {lead_data.get('phone', '')}
Timestamp: {lead_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}

--- DETAILED SCAN RESULTS ---

{detailed_summary}

--- END OF DETAILED RESULTS ---

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
