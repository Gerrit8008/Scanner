# auth.py
import os
import logging
from flask import Blueprint, request, jsonify, session, redirect, url_for, render_template
from werkzeug.utils import secure_filename
from client_db import (
    authenticate_user, verify_session, logout_user, 
    create_user, create_client, get_client_by_id, update_client, 
    list_clients, delete_client, regenerate_api_key
)

# Create blueprint for authentication routes
auth_bp = Blueprint('auth', __name__)

# Middleware to verify admin access
def admin_required(f):
    def decorated_function(*args, **kwargs):
        session_token = session.get('session_token')
        if not session_token:
            return redirect(url_for('auth.login', next=request.url))
            
        result = verify_session(session_token)
        if result['status'] != 'success' or result['user']['role'] != 'admin':
            return redirect(url_for('auth.login', next=request.url))
            
        # Add user info to kwargs
        kwargs['user'] = result['user']
        return f(*args, **kwargs)
        
    # Preserve the original function's name and docstring
    decorated_function.__name__ = f.__name__
    decorated_function.__doc__ = f.__doc__
    return decorated_function

# Login route
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('admin/login.html', error="Please provide username and password")
            
        result = authenticate_user(username, password)
        
        if result['status'] == 'success':
            # Store session token in cookie
            session['session_token'] = result['session_token']
            session['username'] = result['username']
            session['role'] = result['role']
            
            # Redirect to appropriate dashboard
            if result['role'] == 'admin':
                return redirect(url_for('admin.dashboard'))
            else:
                return redirect(url_for('client.dashboard'))
        else:
            return render_template('admin/login.html', error=result['message'])
    
    # GET request - show login form
    return render_template('admin/login.html')

# Logout route
@auth_bp.route('/logout')
def logout():
    session_token = session.get('session_token')
    if session_token:
        logout_user(session_token)
        
    # Clear session
    session.clear()
    return redirect(url_for('auth.login'))

# Admin routes
@auth_bp.route('/admin/dashboard')
@admin_required
def admin_dashboard(user):
    return render_template('admin/admin-dashboard.html', user=user)

@auth_bp.route('/admin/clients')
@admin_required
def client_management(user):
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Handle filters
    filters = {}
    if 'subscription' in request.args:
        filters['subscription'] = request.args.get('subscription')
    if 'status' in request.args:
        filters['status'] = request.args.get('status')
    if 'search' in request.args:
        filters['search'] = request.args.get('search')
    
    result = list_clients(page, per_page, filters)
    
    if result['status'] == 'success':
        return render_template(
            'admin/client-management.html',
            clients=result['clients'],
            pagination=result['pagination'],
            filters=filters,
            user=user
        )
    else:
        return render_template(
            'admin/client-management.html',
            error=result['message'],
            user=user
        )

@auth_bp.route('/admin/clients/<int:client_id>')
@admin_required
def client_detail(client_id, user):
    client_data = get_client_by_id(client_id)
    
    if not client_data:
        return render_template('admin/error.html', error="Client not found", user=user)
    
    return render_template('admin/client-detail.html', client=client_data, user=user)

@auth_bp.route('/admin/clients/<int:client_id>/edit', methods=['GET', 'POST'])
@admin_required
def client_edit(client_id, user):
    if request.method == 'POST':
        # Get form data
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
            'default_
            @auth_bp.route('/admin/clients/<int:client_id>/edit', methods=['GET', 'POST'])
@admin_required
def client_edit(client_id, user):
    if request.method == 'POST':
        # Get form data
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
        UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        
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
            return redirect(url_for('auth.client_detail', client_id=client_id))
        else:
            # Get client data to repopulate form
            client_data = get_client_by_id(client_id)
            return render_template('admin/client-edit.html', 
                                client=client_data, 
                                error=result['message'], 
                                user=user)
    
    # GET request - show edit form with client data
    client_data = get_client_by_id(client_id)
    
    if not client_data:
        return render_template('admin/error.html', error="Client not found", user=user)
    
    return render_template('admin/client-edit.html', client=client_data, user=user)

@auth_bp.route('/admin/clients/create', methods=['GET', 'POST'])
@admin_required
def client_create(user):
    if request.method == 'POST':
        # Get form data
        client_data = {
            'business_name': request.form.get('business_name'),
            'business_domain': request.form.get('business_domain'),
            'contact_email': request.form.get('contact_email'),
            'contact_phone': request.form.get('contact_phone'),
            'scanner_name': request.form.get('scanner_name'),
            'subscription': request.form.get('subscription', 'basic'),
            'primary_color': request.form.get('primary_color', '#FF6900'),
            'secondary_color': request.form.get('secondary_color', '#808588'),
            'email_subject': request.form.get('email_subject', 'Your Security Scan Report'),
            'email_intro': request.form.get('email_intro'),
            'default_scans': request.form.getlist('default_scans[]')
        }
        
        # Handle file uploads
        UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        
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
            from scanner_template import generate_scanner
            scanner_result = generate_scanner(result['client_id'], client_data)
            
            if scanner_result:
                return redirect(url_for('auth.client_detail', client_id=result['client_id']))
            else:
                return render_template('admin/client-create.html', 
                                    error="Client created but scanner generation failed", 
                                    user=user)
        else:
            return render_template('admin/client-create.html', 
                                error=result['message'], 
                                user=user)
    
    # GET request - show create form
    return render_template('admin/client-create.html', user=user)

@auth_bp.route('/admin/clients/<int:client_id>/delete', methods=['POST'])
@admin_required
def client_delete(client_id, user):
    result = delete_client(client_id)
    
    if result['status'] == 'success':
        return redirect(url_for('auth.client_management'))
    else:
        return render_template('admin/error.html', error=result['message'], user=user)

@auth_bp.route('/admin/clients/<int:client_id>/regenerate-api-key', methods=['POST'])
@admin_required
def client_regenerate_api_key(client_id, user):
    result = regenerate_api_key(client_id)
    
    if result['status'] == 'success':
        return jsonify(result)
    else:
        return jsonify(result), 400

# User management routes
@auth_bp.route('/admin/users')
@admin_required
def user_management(user):
    # Logic to list users
    return render_template('admin/user-management.html', user=user)

@auth_bp.route('/admin/users/create', methods=['GET', 'POST'])
@admin_required
def user_create(user):
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'client')
        
        result = create_user(username, email, password, role)
        
        if result['status'] == 'success':
            return redirect(url_for('auth.user_management'))
        else:
            return render_template('admin/user-create.html', 
                                error=result['message'], 
                                user=user)
    
    # GET request - show create form
    return render_template('admin/user-create.html', user=user)
