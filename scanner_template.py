# In scanner_template.py
import os
import shutil
import logging
import json
from datetime import datetime
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
        
        # Subdirectories for static files
        static_dir = os.path.join(client_dir, 'static')
        css_dir = os.path.join(static_dir, 'css')
        js_dir = os.path.join(static_dir, 'js')
        images_dir = os.path.join(static_dir, 'images')
        
        os.makedirs(css_dir, exist_ok=True)
        os.makedirs(js_dir, exist_ok=True)
        os.makedirs(images_dir, exist_ok=True)
        
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
            company_name = client_data.get('business_name', 'Security Scanner')
            scanner_name = client_data.get('scanner_name', company_name + ' Security Scanner')
            
            customized_content = template.render(
                business_name=company_name,
                scanner_name=scanner_name,
                primary_color=client_data.get('primary_color', '#FF6900'),
                secondary_color=client_data.get('secondary_color', '#808588'),
                contact_email=client_data.get('contact_email', 'support@example.com'),
                contact_phone=client_data.get('contact_phone', ''),
                business_domain=client_data.get('business_domain', 'example.com'),
                current_year=datetime.now().strftime('%Y')
            )
            
            # Write customized file
            with open(dest_path, 'w') as file:
                file.write(customized_content)
        
        # Generate custom CSS
        generate_custom_css(client_dir, client_data)
        
        # Copy static files (JS, default images)
        for filename in os.listdir(os.path.join(TEMPLATE_DIR, '../static/js')):
            source_path = os.path.join(TEMPLATE_DIR, '../static/js', filename)
            dest_path = os.path.join(js_dir, filename)
            if os.path.isfile(source_path):
                shutil.copy(source_path, dest_path)
        
        # Copy default images
        for filename in os.listdir(os.path.join(TEMPLATE_DIR, '../static/images')):
            source_path = os.path.join(TEMPLATE_DIR, '../static/images', filename)
            dest_path = os.path.join(images_dir, filename)
            if os.path.isfile(source_path):
                shutil.copy(source_path, dest_path)
        
        # Copy logo and favicon if provided
        if 'logo_path' in client_data and client_data['logo_path'] and os.path.exists(client_data['logo_path']):
            logo_dest = os.path.join(images_dir, 'logo.png')
            shutil.copy(client_data['logo_path'], logo_dest)
        
        if 'favicon_path' in client_data and client_data['favicon_path'] and os.path.exists(client_data['favicon_path']):
            favicon_dest = os.path.join(static_dir, 'favicon.ico')
            shutil.copy(client_data['favicon_path'], favicon_dest)
        
        # Generate config file
        config = {
            'client_id': client_id,
            'business_name': client_data.get('business_name', ''),
            'scanner_name': scanner_name,
            'contact_email': client_data.get('contact_email', ''),
            'default_scans': client_data.get('default_scans', []),
            'email_subject': client_data.get('email_subject', ''),
            'email_intro': client_data.get('email_intro', ''),
            'api_key': client_data.get('api_key', ''),
            'created_at': datetime.now().isoformat(),
            'template_version': '1.0'
        }
        
        with open(os.path.join(client_dir, 'config.json'), 'w') as f:
            json.dump(config, f, indent=2)
        
        # Update client record in database to show successful deployment
        from client_db import update_deployment_status
        update_deployment_status(client_id, 'active', config_path=os.path.join(client_dir, 'config.json'))
        
        logging.info(f"Scanner generated successfully for client {client_id}")
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
        
        # Copy the base CSS file
        base_css_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/css/styles.css')
        if os.path.exists(base_css_path):
            shutil
