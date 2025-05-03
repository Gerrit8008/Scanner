from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.utils import secure_filename
import os
import uuid
from client_db import (
    authenticate_user, verify_session, logout_user, 
    create_user, get_user_by_id, list_users,
    get_client_by_id, list_clients, create_client, update_client, delete_client,
    regenerate_api_key, get_dashboard_summary
)
from scanner_template import generate_scanner, update_scanner

# Define upload folder
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Middleware to require admin login
def admin_required(f):
    def decorated_function(*args, **kwargs):
        session_token = session.get('session_token')
        
        if not session_token:
            return redirect(url_for('auth.login', next=request.url))
        
        result = verify_session(session_token)
        
        if result['status'] != 'success' or result['user']['role'] != 'admin':
            flash('You need admin privileges to access this page', 'danger')
            return redirect(url_for('auth.login'))
        
        # Add user info to kwargs
        kwargs['user'] = result['user']
        return f(*args, **kwargs)
    
    # Preserve function metadata
    decorated_function.__name__ = f.__name__
    decorated_function.__doc__ = f.__doc__
    return decorated_function

@admin_bp.route('/templates/admin/admin-dashboard')
@admin_required
def dashboard(user):
    """Admin dashboard with summary statistics"""
    # Get dashboard summary data
    summary = get_dashboard_summary()
    
    # Get recent clients
    recent_clients = list_clients(page=1, per_page=5)['clients']
    
    # Render dashboard template
    return render_template(
        'templates_admin/admin-dashboard.html',
        user=user,
        summary=summary,
        recent_clients=recent_clients
    )

@admin_bp.route('/templates/admin/client-management')
@admin_required
def client_list(user):
    """Client management page"""
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
    
    # Render client list template
    return render_template(
        'templates/admin/client-management.html',
        user=user,
        clients=result['clients'],
        pagination=result['pagination'],
        filters=filters
    )

@admin_bp.route('/admin/clients/<int:client_id>')
@admin_required
def client_detail(user, client_id):
    """Client detail page"""
    # Get client details
    client = get_client_by_id(client_id)
    
    if not client:
        flash('Client not found', 'danger')
        return redirect(url_for('admin.client_list'))
    
    # Render client detail template
    return render_template(
        'admin/client-detail.html',
        user=user,
        client=client
    )

@admin_bp.route('/admin/clients/create', methods=['GET', 'POST'])
@admin_required
def client_create(user):
    """Create new client"""
    if request.method == 'POST':
        # Extract form data
        client_data = {
            'business_name': request.form.get('business_name', ''),
            'business_domain': request.form.get('business_domain', ''),
            'contact_email': request.form.get('contact_email', ''),
            'contact_phone': request.form.get('contact_phone', ''),
            'scanner_name': request.form.get('scanner_name', ''),
            'subscription': request.form.get('subscription', 'basic'),
            'primary_color': request.form.get('primary_color', '#FF6900'),
            'secondary_color': request.form.get('secondary_color', '#808588'),
            'email_subject': request.form.get('email_subject', 'Your Security Scan Report'),
            'email_intro': request.form.get('email_intro', ''),
            'default_scans': request.form.getlist('default_scans[]')
        }
        
        # Handle file uploads
        if 'logo' in request.files and request.files['logo'].filename:
            logo_file = request.files['logo']
            logo_filename = secure_filename(f"{uuid.uuid4()}_{logo_file.filename}")
            logo_path = os.path.join(UPLOAD_FOLDER, logo_filename)
            logo_file.save(logo_path)
            client_data['logo_path'] = logo_path
        
        if 'favicon' in request.files and request.files['favicon'].filename:
            favicon_file = request.files['favicon']
            favicon_filename = secure_filename(f"{uuid.uuid4()}_{favicon_file.filename}")
            favicon_path = os.path.join(UPLOAD_FOLDER, favicon_filename)
            favicon_file.save(favicon_path)
            client_data['favicon_path'] = favicon_path
        
        # Create client
        result = create_client(client_data, user['user_id'])
        
        if result['status'] == 'success':
            # Generate scanner files
            scanner_result = generate_scanner(result['client_id'], client_data)
            
            if scanner_result:
                flash('Client created successfully', 'success')
                return redirect(url_for('admin.client_detail', client_id=result['client_id']))
            else:
                flash('Client created but scanner generation failed', 'warning')
                return redirect(url_for('admin.client_detail', client_id=result['client_id']))
        else:
            flash(f'Failed to create client: {result.get("message", "Unknown error")}', 'danger')
    
    # Render client create form
    return render_template(
        'admin/client-create.html',
        user=user
    )

@admin_bp.route('/admin/clients/<int:client_id>/edit', methods=['GET', 'POST'])
@admin_required
def client_edit(user, client_id):
    """Edit client"""
    # Get client details
    client = get_client_by_id(client_id)
    
    if not client:
        flash('Client not found', 'danger')
        return redirect(url_for('admin.client_list'))
    
    if request.method == 'POST':
        # Extract form data
        client_data = {
            'business_name': request.form.get('business_name'),
            'business_domain': request.form.get('business_domain'),
            'contact_email': request.form.get('contact_email'),
            'contact_phone': request.form.get('contact_phone'),
            'scanner_name': request.form.get('scanner_name'),
            'subscription_level': request.form.get('subscription_level'),
            'subscription_status': request.form.get('subscription_status'),
            'primary_color': request.form.get('primary_color'),
            'secondary_color': request.form.get('secondary_color'),
            'email_subject': request.form.get('email_subject'),
            'email_intro': request.form.get('email_intro'),
            'default_scans': request.form.getlist('default_scans[]'),
            'active': request.form.get('active') == 'on'
        }
        
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
        
        # Update client
        result = update_client(client_id, client_data, user['user_id'])
        
        if result['status'] == 'success':
            # Update scanner files
            scanner_result = update_scanner(client_id, client_data)
            
            if scanner_result:
                flash('Client updated successfully', 'success')
            else:
                flash('Client updated but scanner update failed', 'warning')
            
            return redirect(url_for('admin.client_detail', client_id=client_id))
        else:
            flash(f'Failed to update client: {result.get("message", "Unknown error")}', 'danger')
    
    # Render client edit form
    return render_template(
        'admin/client-edit.html',
        user=user,
        client=client
    )

@admin_bp.route('/admin/clients/<int:client_id>/delete', methods=['POST'])
@admin_required
def client_delete(user, client_id):
    """Delete client"""
    # Delete client
    result = delete_client(client_id)
    
    if result['status'] == 'success':
        flash('Client deleted successfully', 'success')
    else:
        flash(f'Failed to delete client: {result.get("message", "Unknown error")}', 'danger')
    
    return redirect(url_for('admin.client_list'))

@admin_bp.route('/admin/clients/<int:client_id>/regenerate-api-key', methods=['POST'])
@admin_required
def client_regenerate_api_key(user, client_id):
    """Regenerate client API key"""
    # Regenerate API key
    result = regenerate_api_key(client_id)
    
    if result['status'] == 'success':
        return jsonify({
            'status': 'success',
            'message': 'API key regenerated successfully',
            'api_key': result['api_key']
        })
    else:
        return jsonify({
            'status': 'error',
            'message': result.get('message', 'Failed to regenerate API key')
        }), 400

@admin_bp.route('/admin/users')
@admin_required
def user_list(user):
    """User management page"""
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Get user list
    users = list_users(page, per_page)
    
    # Render user list template
    return render_template(
        'admin/user-management.html',
        user=user,
        users=users['users'],
        pagination=users['pagination']
    )

@admin_bp.route('/admin/users/create', methods=['GET', 'POST'])
@admin_required
def user_create(user):
    """Create new user"""
    if request.method == 'POST':
        # Extract form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'client')
        
        # Create user
        result = create_user(username, email, password, role)
        
        if result['status'] == 'success':
            flash('User created successfully', 'success')
            return redirect(url_for('admin.user_list'))
        else:
            flash(f'Failed to create user: {result.get("message", "Unknown error")}', 'danger')
    
    # Render user create form
    return render_template(
        'admin/user-create.html',
        user=user
    )
