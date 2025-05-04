from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
import os
import uuid
import json
from flask import Blueprint, request, jsonify, flash, redirect, url_for
from client_db import (
    create_client, get_client_by_id, update_client, delete_client, 
    get_client_by_api_key, log_scan, regenerate_api_key, list_clients
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
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                # AJAX request
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to save client data'
                }), 500
            else:
                # Regular form submission
                return redirect(url_for('customize_scanner', error='Failed to save client data'))
        
        # Generate custom scanner files
        scanner_result = generate_scanner(result['client_id'], client_data)
        
        if not scanner_result:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                # AJAX request
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to generate scanner files'
                }), 500
            else:
                # Regular form submission
                return redirect(url_for('customize_scanner', error='Failed to generate scanner files'))
        
        # Return success response
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            # AJAX request
            return jsonify({
                'status': 'success',
                'message': 'Scanner created successfully',
                'client_id': result['client_id'],
                'api_key': result['api_key'],
                'subdomain': result['subdomain'],
                'scanner_url': f"https://{result['subdomain']}.yourscannerdomain.com"
            }), 201
        else:
            # Regular form submission
            return redirect(url_for('admin.dashboard'))
    
    except Exception as e:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            # AJAX request
            return jsonify({
                'status': 'error',
                'message': f'Error creating scanner: {str(e)}'
            }), 500
        else:
            # Regular form submission
            return redirect(url_for('customize_scanner', error=f'Error: {str(e)}'))

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
        # Extract data from form or JSON
        client_data = {}
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
                'secondary_color': request.form.get('secondary_color'),
                'email_subject': request.form.get('email_subject'),
                'email_intro': request.form.get('email_intro'),
                'subscription_level': request.form.get('subscription_level'),
                'default_scans': request.form.getlist('default_scans[]')
            }
        
        # Remove None values
        client_data = {k: v for k, v in client_data.items() if v is not None}
        
        # Handle file uploads
        if 'logo' in request.files and request.files['logo'].filename:
            logo_file = request.files['logo']
            logo_filename = secure_filename(f"{client_id}_{logo_file.filename}")
            logo_path = os.path.join(UPLOAD_FOLDER, logo_filename)
            logo_file.save(logo_path)
            client_data['logo_path'] = logo_path
        
        if 'favicon' in request.files and request.files['favicon'].filename:
            favicon_file = request.files['favicon']
            favicon_filename = secure_filename(f"{client_id}_{favicon_file.filename}")
            favicon_path = os.path.join(UPLOAD_FOLDER, favicon_filename)
            favicon_file.save(favicon_path)
            client_data['favicon_path'] = favicon_path
        
        # Update client in database
        result = update_client(client_id, client_data, 1)  # Admin user_id = 1
        
        if not result or result.get('status') == 'error':
            return jsonify({
                'status': 'error',
                'message': result.get('message', 'Failed to update client data')
            }), 500
        
        # Update scanner files
        scanner_result = update_scanner(client_id, client_data)
        
        if not scanner_result:
            return jsonify({
                'status': 'error',
                'message': 'Failed to update scanner files'
            }), 500
        
        # Get updated client data
        updated_client = get_client_by_id(client_id)
        
        # Return success response
        return jsonify({
            'status': 'success',
            'message': 'Scanner updated successfully',
            'client': {
                'id': updated_client['id'],
                'business_name': updated_client['business_name'],
                'scanner_name': updated_client['scanner_name'],
                'subdomain': updated_client.get('subdomain', '')
            }
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error updating scanner: {str(e)}'
        }), 500

@api_bp.route('/api/v1/clients/<int:client_id>', methods=['GET'])
def get_client_details(client_id):
    """API endpoint to get client details"""
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
            'message': 'Unauthorized to view this client'
        }), 403
    
    try:
        # Get client details
        client_data = get_client_by_id(client_id)
        
        if not client_data:
            return jsonify({
                'status': 'error',
                'message': 'Client not found'
            }), 404
        
        # Filter sensitive data
        filtered_data = {
            'id': client_data['id'],
            'business_name': client_data['business_name'],
            'business_domain': client_data['business_domain'],
            'contact_email': client_data['contact_email'],
            'scanner_name': client_data['scanner_name'],
            'subscription_level': client_data['subscription_level'],
            'subscription_status': client_data['subscription_status'],
            'created_at': client_data['created_at'],
            'active': client_data['active'] == 1,
            'subdomain': client_data.get('subdomain', ''),
            'primary_color': client_data.get('primary_color', ''),
            'secondary_color': client_data.get('secondary_color', ''),
            'default_scans': client_data.get('default_scans', [])
        }
        
        # Return client data
        return jsonify({
            'status': 'success',
            'client': filtered_data
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error retrieving client details: {str(e)}'
        }), 500

@api_bp.route('/api/v1/clients', methods=['GET'])
def list_all_clients():
    """API endpoint to list all clients (admin only)"""
    # Check for API key in headers
    api_key = request.headers.get('X-API-Key')
    
    if not api_key:
        return jsonify({
            'status': 'error',
            'message': 'Missing API key'
        }), 401
    
    # Verify this is an admin API key
    client = get_client_by_api_key(api_key)
    
    if not client or client.get('role', '') != 'admin':
        return jsonify({
            'status': 'error',
            'message': 'Unauthorized access'
        }), 403
    
    try:
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        # Get filter parameters
        filters = {}
        if 'subscription' in request.args:
            filters['subscription'] = request.args.get('subscription')
        if 'status' in request.args:
            filters['status'] = request.args.get('status')
        if 'search' in request.args:
            filters['search'] = request.args.get('search')
        
        # Get client list
        result = list_clients(page, per_page, filters)
        
        # Return client list
        return jsonify({
            'status': 'success',
            'clients': result['clients'],
            'pagination': result['pagination']
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error retrieving clients: {str(e)}'
        }), 500

@api_bp.route('/api/v1/clients/<int:client_id>/regenerate-api-key', methods=['POST'])
def regenerate_client_api_key(client_id):
    """API endpoint to regenerate a client's API key (admin only)"""
    # Check for API key in headers
    api_key = request.headers.get('X-API-Key')
    
    if not api_key:
        return jsonify({
            'status': 'error',
            'message': 'Missing API key'
        }), 401
    
    # Verify this is an admin API key
    client = get_client_by_api_key(api_key)
    
    if not client or client.get('role', '') != 'admin':
        return jsonify({
            'status': 'error',
            'message': 'Unauthorized access'
        }), 403
    
    try:
        # Regenerate API key
        result = regenerate_api_key(client_id)
        
        if not result or result.get('status') == 'error':
            return jsonify({
                'status': 'error',
                'message': result.get('message', 'Failed to regenerate API key')
            }), 500
        
        # Return new API key
        return jsonify({
            'status': 'success',
            'message': 'API key regenerated successfully',
            'api_key': result['api_key']
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error regenerating API key: {str(e)}'
        }), 500

@api_bp.route('/api/process-payment', methods=['POST'])
def process_payment():
    """Process payment for scanner subscription"""
    try:
        # Get payment details from request
        payment_data = request.json
        
        # Here you would integrate with a payment processor like Stripe
        # For example:
        # payment_result = stripe.PaymentIntent.create(
        #     amount=payment_data['amount'],
        #     currency='usd',
        #     payment_method=payment_data['payment_method_id'],
        #     confirm=True
        # )
        
        # For now, simulate successful payment
        payment_successful = True
        
        if payment_successful:
            return jsonify({
                "status": "success",
                "message": "Payment processed successfully"
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Payment failed"
            }), 400
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Payment processing error: {str(e)}"
        }), 500

@api_bp.route('/api/v1/clients/<int:client_id>/delete', methods=['DELETE'])
def delete_client_api(client_id):
    """API endpoint to delete a client (admin only)"""
    # Check for API key in headers
    api_key = request.headers.get('X-API-Key')
    
    if not api_key:
        return jsonify({
            'status': 'error',
            'message': 'Missing API key'
        }), 401
    
    # Verify this is an admin API key
    client = get_client_by_api_key(api_key)
    
    if not client or client.get('role', '') != 'admin':
        return jsonify({
            'status': 'error',
            'message': 'Unauthorized access'
        }), 403
    
    try:
        # Delete client
        result = delete_client(client_id)
        
        if not result or result.get('status') == 'error':
            return jsonify({
                'status': 'error',
                'message': result.get('message', 'Failed to delete client')
            }), 500
        
        # Return success response
        return jsonify({
            'status': 'success',
            'message': 'Client deleted successfully'
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error deleting client: {str(e)}'
        }), 500
