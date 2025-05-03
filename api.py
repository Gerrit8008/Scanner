# api.py
import os
import json
import uuid
import shutil
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from client_db import save_client, get_client_by_api_key
from scanner_template import generate_scanner

# Create blueprint for API routes
api_bp = Blueprint('api', __name__)

# Directory for file uploads
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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
        
        # Save client data to database
        result = save_client(client_data)
        
        if not result:
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
            'api_key': result['api_key'],
            'subdomain': result['subdomain'],
            'scanner_url': f"https://{result['subdomain']}.yourscannerdomain.com"
        }), 201
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': f'Error creating scanner: {str(e)}'
        }), 500

@api_bp.route('/api/v1/scan', methods=['POST'])
def api_scan():
    """API endpoint for running scans via API"""
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
    
    # Process scan request with client customizations
    try:
        # Extract scan parameters
        scan_data = request.get_json()
        
        # Add the scan to the queue
        # This would integrate with your existing scan functionality
        # but with client customizations applied
        
        return jsonify({
            'status': 'success',
            'message': 'Scan initiated',
            'scan_id': str(uuid.uuid4())
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error processing scan: {str(e)}'
        }), 500
