import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Get email credentials from environment variables (or use defaults for development)
EMAIL_HOST = os.environ.get('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.environ.get('EMAIL_PORT', 587))
EMAIL_USER = os.environ.get('EMAIL_USER', 'your-email@gmail.com')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', 'your-app-password')
EMAIL_FROM = os.environ.get('EMAIL_FROM', 'Security Scanner <your-email@gmail.com>')

def send_email_report(lead_data, report_content, is_html=False, is_integrated=False):
    """
    Send security scan report via email.
    
    Args:
        lead_data (dict): Dictionary containing user information
        report_content (str): The report content (text or HTML)
        is_html (bool): Whether the report is in HTML format
        is_integrated (bool): Whether this is an integrated scan report
        
    Returns:
        bool: Success status
    """
    try:
        # Get recipient email
        recipient = lead_data.get('email', '')
        if not recipient:
            logging.error("No recipient email provided")
            return False
            
        # Create message container
        msg = MIMEMultipart('alternative')
        
        # Determine subject line based on scan type
        if is_integrated:
            msg['Subject'] = f"Your Comprehensive Security Scan Report - {datetime.now().strftime('%Y-%m-%d')}"
        else:
            msg['Subject'] = f"Your Security Scan Report - {datetime.now().strftime('%Y-%m-%d')}"
            
        msg['From'] = EMAIL_FROM
        msg['To'] = recipient
        
        # Attach content in appropriate format
        if is_html:
            # Add HTML version
            msg.attach(MIMEText(report_content, 'html'))
            
            # Also add a plain text version for email clients that don't support HTML
            plain_text = "Your security scan report is attached. Please view this email in an HTML-capable email client for best results."
            msg.attach(MIMEText(plain_text, 'plain'))
        else:
            # Add plain text version only
            msg.attach(MIMEText(report_content, 'plain'))
        
        # Check if we're in development or production mode
        is_development = os.environ.get('FLASK_ENV') == 'development'
        
        if is_development:
            # In development, log instead of sending
            logging.info(f"[DEV MODE] Would send email to {recipient}")
            logging.info(f"[DEV MODE] Subject: {msg['Subject']}")
            if not is_html:
                logging.info
