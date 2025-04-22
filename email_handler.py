import os
import logging
import smtplib
from email.message import EmailMessage
from datetime import datetime

# Set up logging configuration if not already set
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.DEBUG, 
                      format='%(asctime)s - %(levelname)s - %(message)s')

def send_email_report(lead_data, scan_result):
    """Send lead info and scan result to your email using a mail relay.
    
    Args:
        lead_data (dict): Dictionary containing lead information (name, email, etc.)
        scan_result (str): String containing the full scan report content
        
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
            return False
            
        logging.debug(f"Attempting to send email with SMTP user: {smtp_user}")
        
        msg = EmailMessage()
        msg["Subject"] = f"New Vulnerability Scan - {lead_data.get('company', 'Unknown Company')}"
        msg["From"] = smtp_user

        # Send to both the admin and the user
        admin_email = smtp_user
        user_email = lead_data.get("email", "")
        recipients = f"{admin_email}, {user_email}"
        msg["To"] = recipients
        
        logging.debug(f"Email recipients: {recipients}")

        # Compose the body
        body = f"""
        A new scan has been initiated with the following details:

        Name: {lead_data.get('name', '')}
        Email: {lead_data.get('email', '')}
        Company: {lead_data.get('company', '')}
        Phone: {lead_data.get('phone', '')}
        Timestamp: {lead_data.get('timestamp', '')}

        --- Begin Scan Report ---

        {scan_result}

        --- End of Report ---
        
        We look forward to partnering with you for all your IT and cybersecurity needs.
        You can reach us through our website at cengatech.com, by email at sales@cengatech.com, or by phone at 470-481-0400.

        Thank you,
        The Cengatech Team
        """
        msg.set_content(body)

        # Try different ports if needed
        smtp_server = "mail.privateemail.com"
        smtp_port = 587  # 587 is typical for authenticated TLS
        
        logging.debug(f"Connecting to SMTP server: {smtp_server}:{smtp_port}")

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
