import os
import logging
import smtplib
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from flask import current_app

# Set up logging configuration if not already set
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.DEBUG,
                       format='%(asctime)s - %(levelname)s - %(message)s')

def get_smtp_config():
    """
    Get SMTP configuration from environment variables with fallbacks to app config.
    
    Returns:
        dict: SMTP configuration
    """
    # Try to get from environment variables first
    smtp_config = {
        'server': os.environ.get('SMTP_SERVER', 'mail.privateemail.com'),
        'user': os.environ.get('SMTP_USER'),
        'password': os.environ.get('SMTP_PASSWORD'),
        'port': int(os.environ.get('SMTP_PORT', 587)),
        'ssl_port': int(os.environ.get('SMTP_SSL_PORT', 465)),
        'sender': os.environ.get('SMTP_SENDER')
    }
    
    # If running in Flask context, try to get from app config if env vars not set
    try:
        if not smtp_config['user'] and hasattr(current_app, 'config'):
            smtp_config['user'] = current_app.config.get('SMTP_USER')
            smtp_config['password'] = current_app.config.get('SMTP_PASSWORD')
            smtp_config['server'] = current_app.config.get('SMTP_SERVER', smtp_config['server'])
            smtp_config['port'] = int(current_app.config.get('SMTP_PORT', smtp_config['port']))
            smtp_config['ssl_port'] = int(current_app.config.get('SMTP_SSL_PORT', smtp_config['ssl_port']))
            smtp_config['sender'] = current_app.config.get('SMTP_SENDER', smtp_config['user'])
    except RuntimeError:
        # Not in Flask app context
        pass
        
    return smtp_config

def send_email_report(lead_data, scan_result):
    """Send lead info and scan result to your email using a mail relay.
    
    Args:
        lead_data (dict): Dictionary containing lead information (name, email, etc.)
        scan_result (str): String containing the full scan report content in HTML
    
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    try:
        # Get SMTP configuration
        smtp_config = get_smtp_config()
        smtp_user = smtp_config['user']
        smtp_password = smtp_config['password']
        smtp_server = smtp_config['server']
        smtp_port = smtp_config['port']
        smtp_ssl_port = smtp_config['ssl_port']
        sender_email = smtp_config['sender'] or smtp_user
        
        # Check if credentials are available
        if not smtp_user or not smtp_password:
            logging.error("SMTP credentials not found in environment variables or app config")
            logging.warning("Using default test credentials - ONLY FOR DEVELOPMENT!")
            # For development only - REPLACE WITH REAL CREDENTIALS IN PRODUCTION!
            smtp_user = "your_email@example.com"  # Replace with your email
            smtp_password = "your_password"       # Replace with your password
            sender_email = smtp_user
            
        logging.debug(f"Attempting to send email with SMTP user: {smtp_user}")
        
        # Create a multipart message for HTML and text
        msg = MIMEMultipart('alternative')
        msg["Subject"] = f"Security Scan Report - {lead_data.get('company', 'Unknown Company')}"
        msg["From"] = sender_email
        
        # Send to both the admin and the user
        admin_email = sender_email
        user_email = lead_data.get("email", "")
        
        # Make sure emails are valid
        if not user_email or '@' not in user_email:
            logging.error(f"Invalid user email address: {user_email}")
            return False
            
        # If admin and user are the same, just use one
        if admin_email == user_email:
            recipients = user_email
        else:
            recipients = f"{admin_email}, {user_email}"
            
        msg["To"] = recipients
        
        logging.debug(f"Email recipients: {recipients}")
        
        # Compose the plain text body
        text_body = f"""
        Security Scan Report
        
        Client Information:
        Name: {lead_data.get('name', '')}
        Email: {lead_data.get('email', '')}
        Company: {lead_data.get('company', '')}
        Phone: {lead_data.get('phone', '')}
        Timestamp: {lead_data.get('timestamp', '')}
        
        --- Begin Scan Report Summary ---
        
        A detailed security scan was performed for {lead_data.get('company', 'your company')}.
        Please see the attached HTML report or view it in your browser.
        
        --- End of Summary ---
        
        We look forward to partnering with you for all your IT and cybersecurity needs.
        You can reach us through our website at cengatech.com, by email at sales@cengatech.com, or by phone at 470-481-0400.
        
        Thank you,
        The Cengatech Team
        """
        
        # Create text part
        part1 = MIMEText(text_body, 'plain')
        
        # Create HTML part - use the scan_result which should be HTML
        part2 = MIMEText(scan_result, 'html')
        
        # Add parts to message
        msg.attach(part1)
        msg.attach(part2)
        
        # Try sending with primary settings first
        logging.debug(f"Connecting to SMTP server: {smtp_server}:{smtp_port}")
        
        try:
            # First try with TLS
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
            
            # Fallback to SSL
            try:
                logging.debug(f"Trying alternative SSL connection on port: {smtp_ssl_port}")
                
                with smtplib.SMTP_SSL(smtp_server, smtp_ssl_port, timeout=30) as server:
                    logging.debug("SMTP_SSL connection established")
                    server.login(smtp_user, smtp_password)
                    logging.debug("SMTP login successful")
                    server.send_message(msg)
                    logging.debug("Email sent successfully via SSL!")
                    return True
            except Exception as fallback_error:
                logging.error(f"Fallback SMTP attempt also failed: {fallback_error}")
                
                # Last resort - try different port combinations
                try:
                    alternative_ports = [25, 2525]
                    for port in alternative_ports:
                        try:
                            logging.debug(f"Trying alternative port: {port}")
                            with smtplib.SMTP(smtp_server, port, timeout=30) as server:
                                server.ehlo()
                                if port != 25:  # Port 25 typically doesn't support TLS
                                    server.starttls()
                                    server.ehlo()
                                server.login(smtp_user, smtp_password)
                                server.send_message(msg)
                                logging.debug(f"Email sent successfully via port {port}!")
                                return True
                        except Exception as e:
                            logging.debug(f"Failed with port {port}: {e}")
                            continue
                    
                    raise Exception("All SMTP connection attempts failed")
                except Exception as e:
                    logging.error(f"All SMTP attempts failed: {e}")
                    raise
            
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
