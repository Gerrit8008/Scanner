# In scanner_router.py
from flask import Blueprint, request, redirect, url_for, render_template, abort
from client_db import get_client_by_subdomain
from jinja2 import Template

scanner_bp = Blueprint('scanner', __name__)

@scanner_bp.route('/<subdomain>/', defaults={'path': ''})
@scanner_bp.route('/<subdomain>/<path:path>')
def route_scanner(subdomain, path):
    """Route requests to the appropriate client scanner"""
    # Find client by subdomain
    client = get_client_by_subdomain(subdomain)
    
    if not client:
        abort(404)
    
    # Check if client is active
    if not client.get('active', 0):
        return render_template('error.html', error="This scanner is currently inactive.")
    
    # Get the client's scanner directory
    scanner_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 
        'scanners', 
        f"client_{client['id']}"
    )
    
    if not os.path.exists(scanner_dir):
        return render_template('error.html', error="Scanner configuration not found.")
    
    # Handle different paths
    if path == '':
        # Serve index.html
        template_path = os.path.join(scanner_dir, 'index.html')
    else:
        # Serve requested path
        template_path = os.path.join(scanner_dir, path)
    
    # Check if file exists
    if not os.path.exists(template_path):
        # Check if it's a scan request
        if path == 'scan':
            # Redirect to main scan page with client_id
            return redirect(url_for('scan_page', client_id=client['id']))
        
        # Check if it's a results request
        if path == 'results':
            # Redirect to main results page with client_id
            return redirect(url_for('results', client_id=client['id']))
        
        # File not found
        abort(404)
    
    # Serve static files directly
    if path.startswith('static/'):
        with open(template_path, 'rb') as f:
            return f.read()
    
    # Render template
    with open(template_path, 'r') as f:
        template_content = f.read()
    
    template = Template(template_content)
    return template.render(client=client)
