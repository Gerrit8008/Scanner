from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
import os
import uuid
import json
from client_db import (
    create_client, get_client_by_id, update_client, delete_client, 
    get_client_by_api_key, log_scan, regenerate_api_key
)
from scanner_template import generate_scanner, update_scanner

# Create blueprint for API routes
api_bp = Blueprint('api', __name__)

# Directory for file uploads
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Middleware to check API key
def api_key_required(f):
    def decorated_function(*args, **kwargs):
        # Check for API key in headers
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({
                'status': 'error',
                'message': 'Missing API key'
            }), 401
        
        # Get client by API key
        client = get_client_by_api_key(api_key)
        
        if not client:
            return jsonify({
                'status': 'error',
                'message': 'Invalid API key'
            }), 401
            
        # Set client in request context for the view function
        kwargs['client'] = client
        return f(*args, **kwargs)
    
    # Preserve the function's metadata
    decorated_function.__name__ = f.__name__
    decorated_function.__doc__ = f.__doc__
    
    return decorated_function

@api_bp.route('/api/create-scanner', methods=['POST'])
def create_scanner():
    """API endpoint to create a new customized scanner"""
    try:
        # Extract form data
        client_data = {
            'business_name': request.form.get('business_name', ''),
            'business_domain': request.form.get('business_domain', ''),
            'contact_email': request.form.get('contact_email', ''),
            'contact_phone': request.form.get('contact_phone', ''),
            'scanner_name': request.form.get('scanner_name', ''),
            'primary_color': request.form.get('primary_color', '#FF6900'),
            'secondary_color': request.form.get('secondary_color', '#808588'),
            'email_subject': request.form.get('email_subject', 'Your Security Scan Report'),
            'email_intro': request.form.get('email_intro', ''),
            'subscription': request.form.get('subscription', 'basic'),
            'default_scans': request.form.getlist('default_scans[]')
        }
        
        # Use admin user ID 1 for scanner creation through API
        user_id = 1  
        
        # Handle file uploads
        if 'logo' in request.files:
            logo_file = request.files['logo']
            if logo_file.filename:
                logo_filename = secure_filename(f"{uuid.uuid4()}_{logo_file.filename}")
                logo_path = os.path.join(UPLOAD_FOLDER, logo_filename)
                logo_file.save(logo_path)
                client_data['logo_path'] = logo_path
        
        if 'favicon' in request.files:
            favicon_file = request.files['favicon']
            if favicon_file.filename:
                favicon_filename = secure_filename(f"{uuid.uuid4()}_{favicon_file.filename}")
                favicon_path = os.path.join(UPLOAD_FOLDER, favicon_filename)
                favicon_file.save(favicon_path)
                client_data['favicon_path'] = favicon_path
        
        # Create client record in the database
        result = create_client(client_data, user_id)
        
        if not result or result.get('status') == 'error':
            return jsonify({
                'status': 'error',
                'message': 'Failed to save client data'
            }), 500
        
        # Generate custom scanner files
        scanner_result = generate_scanner(result['client_id'], client_data)
        
        if not scanner_result:
            return jsonify({
                'status': 'error',
                'message': 'Failed to generate scanner files'
            }), 500
        
        # Return success response
        return jsonify({
            'status': 'success',
            'message': 'Scanner created successfully',
            'client_id': result['client_id'],
            'api_key': result['api_key'],
            'subdomain': result['subdomain'],
            'scanner_url': f"https://{result['subdomain']}.yourscannerdomain.com"
        }), 201
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error creating scanner: {str(e)}'
        }), 500

@api_bp.route('/api/v1/scan', methods=['POST'])
@api_key_required
def api_scan(client):
    """API endpoint for running scans via API"""
    try:
        # Extract scan parameters
        scan_data = request.get_json()
        
        # Create a unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Log the scan to the database
        target = scan_data.get('target', client.get('business_domain', ''))
        scan_type = scan_data.get('scan_type', 'comprehensive')
        log_scan(client['id'], scan_id, target, scan_type)
        
        # Here you would integrate with your scanning engine
        # For this example, we'll just return a successful response
        
        return jsonify({
            'status': 'success',
            'message': 'Scan initiated',
            'scan_id': scan_id,
            'client_id': client['id'],
            'client_name': client['business_name']
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error processing scan: {str(e)}'
        }), 500

@api_bp.route('/api/v1/clients/<int:client_id>/update', methods=['PUT', 'POST'])
def update_client_scanner(client_id):
    """API endpoint to update an existing scanner"""
    # Check for API key in headers
    api_key = request.headers.get('X-API-Key')
    
    if not api_key:
        return jsonify({
            'status': 'error',
            'message': 'Missing API key'
        }), 401
    
    # Verify this is an admin API key or the client's own API key
    client = get_client_by_api_key(api_key)
    
    if not client or (client['id'] != client_id and client.get('role', '') != 'admin'):
        return jsonify({
            'status': 'error',
            'message': 'Unauthorized to update this client'
        }), 403
    
    try:
        # Extract form data
        client_data = {}
        
        # Extract data from form or JSON
        if request.is_json:
            json_data = request.get_json()
            client_data = {
                'business_name': json_data.get('business_name'),
                'business_domain': json_data.get('business_domain'),
                'contact_email': json_data.get('contact_email'),
                'contact_phone': json_data.get('contact_phone'),
                'scanner_name': json_data.get('scanner_name'),
                'primary_color': json_data.get('primary_color'),
                'secondary_color': json_data.get('secondary_color'),
                'email_subject': json_data.get('email_subject'),
                'email_intro': json_data.get('email_intro'),
                'subscription_level': json_data.get('subscription_level'),
                'default_scans': json_data.get('default_scans', [])
            }
        else:
            client_data = {
                'business_name': request.form.get('business_name'),
                'business_domain': request.form.get('business_domain'),
                'contact_email': request.form.get('contact_email'),
                'contact_phone': request.form.get('contact_phone'),
                'scanner_name': request.form.get('scanner_name'),
                'primary_color': request.form.get('primary_color'),
