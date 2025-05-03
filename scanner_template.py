# scanner_template.py
import os
import shutil
import logging
import json
import re
from jinja2 import Template

# Directory to store generated scanner files
SCANNERS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scanners')
os.makedirs(SCANNERS_DIR, exist_ok=True)

# Template directory with original scanner files
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')

def generate_scanner(client_id, client_data):
    """Generate customized scanner files for a client"""
    try:
        # Create directory for this client's scanner
        client_dir = os.path.join(SCANNERS_DIR, f"client_{client_id}")
        os.makedirs(client_dir, exist_ok=True)
        
        # Copy template files to client directory
        template_files = [
            'index.html',
            'scan.html',
            'results.html',
            'error.html'
        ]
        
        for filename in template_files:
            source_path = os.path.join(TEMPLATE_DIR, filename)
            dest_path = os.path.join(client_dir, filename)
            
            # Read template file
            with open(source_path, 'r') as file:
                template_content = file.read()
            
            # Replace placeholders with client data
            template = Template(template_content)
            customized_content = template.render(
                business_name=client_data.get('business_name', 'Security Scanner'),
                scanner_name=client_data.get('scanner_name', 'Vulnerability Scanner'),
                primary_color=client_data.get('primary_color', '#FF6900'),
                secondary_color=client_data.get('secondary_color', '#808588'),
                contact_email=client_data.get('contact_email', 'support@example.com'),
                contact_phone=client_data.get('contact_phone', ''),
                business_domain=client_data.get('business_domain', 'example.com'),
                current_year="2025"
            )
            
            # Write customized file
            with open(dest_path, 'w') as file:
                file.write(customized_content)
        
        # Generate custom CSS
        generate_custom_css(client_dir, client_data)
        
        # Copy logo and favicon if provided
        if 'logo_path' in client_data and client_data['logo_path']:
            logo_dest = os.path.join(client_dir, 'static', 'images', 'logo.png')
            os.makedirs(os.path.dirname(logo_dest), exist_ok=True)
            shutil.copy(client_data['logo_path'], logo_dest)
        
        if 'favicon_path' in client_data and client_data['favicon_path']:
            favicon_dest = os.path.join(client_dir, 'static', 'favicon.ico')
            os.makedirs(os.path.dirname(favicon_dest), exist_ok=True)
            shutil.copy(client_data['favicon_path'], favicon_dest)
        
        # Generate config file
        config = {
            'client_id': client_id,
            'business_name': client_data.get('business_name', ''),
            'scanner_name': client_data.get('scanner_name', ''),
            'contact_email': client_data.get('contact_email', ''),
            'default_scans': client_data.get('default_scans', []),
            'email_subject': client_data.get('email_subject', ''),
            'email_intro': client_data.get('email_intro', '')
        }
        
        with open(os.path.join(client_dir, 'config.json'), 'w') as f:
            json.dump(config, f, indent=2)
        
        return True
    except Exception as e:
        logging.error(f"Error generating scanner: {e}")
        import traceback
        traceback.print_exc()
        return False

def generate_custom_css(client_dir, client_data):
    """Generate custom CSS file with client colors"""
    try:
        # Create static/css directory
        css_dir = os.path.join(client_dir, 'static', 'css')
        os.makedirs(css_dir, exist_ok=True)
        
        # Define custom CSS content
        primary_color = client_data.get('primary_color', '#FF6900')
        secondary_color = client_data.get('secondary_color', '#808588')
        
        custom_css = f"""
        /* Custom colors for client {client_data.get('business_name')} */
        :root {{
            --primary-color: {primary_color};
            --primary-dark: {darken_color(primary_color)};
            --secondary-color: {secondary_color};
        }}
        
        /* Custom header styles */
        .header {{
            background-color: var(--secondary-color);
        }}
        
        /* Custom button styles */
        .btn-primary, .service-inquiry-btn {{
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }}
        
        .btn-primary:hover, .service-inquiry-btn:hover {{
            background-color: var(--primary-dark);
            border-color: var(--primary-dark);
        }}
        
        /* Custom card header */
        .card-header {{
            background-color: var(--primary-color);
        }}
        """
        
        # Write custom CSS to file
        with open(os.path.join(css_dir, 'custom.css'), 'w') as f:
            f.write(custom_css)
        
        return True
    except Exception as e:
        logging.error(f"Error generating custom CSS: {e}")
        return False

def darken_color(hex_color):
    """Darken a hex color for hover states"""
    # Remove # if present
    hex_color = hex_color.lstrip('#')
    
    # Convert to RGB
    r = int(hex_color[0:2], 16)
    g = int(hex_color[2:4], 16)
    b = int(hex_color[4:6], 16)
    
    # Darken by 15%
    factor = 0.85
    r = max(0, int(r * factor))
    g = max(0, int(g * factor))
    b = max(0, int(b * factor))
    
    # Convert back to hex
    return f"#{r:02x}{g:02x}{b:02x}"
