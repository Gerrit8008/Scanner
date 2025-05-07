# auth_routes.py - Enhanced authentication routes for Flask

from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.utils import secure_filename
import os
import logging
from datetime import datetime
from flask import Blueprint
from client_db import CLIENT_DB_PATH, verify_session
from auth_helper import (
    create_user, authenticate_user, logout_user,
    get_all_users, get_user_by_id, update_user, delete_user,
    get_login_stats, init_user_tables  # Make sure init_user_tables is imported here
)

# Create blueprint for authentication routes
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# Make sure the user tables exist
init_user_tables()

# Middleware to require login
def login_required(f):
    def decorated_function(*args, **kwargs):
        session_token = session.get('session_token')
        
        if not session_token:
            return redirect(url_for('auth.login', next=request.url))
        
        result = verify_session(session_token)
        
        if result['status'] != 'success':
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('auth.login', next=request.url))
        
        # Add user info to kwargs
        kwargs['user'] = result['user']
        return f(*args, **kwargs)
    
    # Preserve function metadata
    decorated_function.__name__ = f.__name__
    decorated_function.__doc__ = f.__doc__
    return decorated_function

# Middleware to require admin access
def admin_required(f):
    def decorated_function(*args, **kwargs):
        session_token = session.get('session_token')
        
        if not session_token:
            return redirect(url_for('auth.login', next=request.url))
        
        result = verify_session(session_token)
        
        if result['status'] != 'success' or result['user']['role'] != 'admin':
            flash('You need administrative privileges to access this page', 'danger')
            return redirect(url_for('auth.login'))
        
        # Add user info to kwargs
        kwargs['user'] = result['user']
        return f(*args, **kwargs)
    
    # Preserve function metadata
    decorated_function.__name__ = f.__name__
    decorated_function.__doc__ = f.__doc__
    return decorated_function

# Registration route
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page"""
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name', '')
        
        # Basic validation
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return render_template('auth/register.html', 
                                 username=username, 
                                 email=email,
                                 full_name=full_name)
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('auth/register.html', 
                                 username=username, 
                                 email=email,
                                 full_name=full_name)
        
        # Create user
        result = create_user(username, email, password, full_name)
        
        if result['status'] == 'success':
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash(f'Registration failed: {result["message"]}', 'danger')
            return render_template('auth/register.html', 
                                 username=username, 
                                 email=email,
                                 full_name=full_name)
    
    # GET request - show registration form
    return render_template('auth/register.html')

# Login route (enhanced)
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login page with enhanced security"""
    # Check if already logged in
    session_token = session.get('session_token')
    if session_token:
        result = verify_session(session_token)
        if result['status'] == 'success':
            user = result['user']
            # Redirect based on role
            if user['role'] == 'admin':
                return redirect(url_for('admin.dashboard'))
            else:
                return redirect(url_for('client.dashboard'))
    
    # Get 'next' parameter for redirection after login
    next_url = request.args.get('next', '')
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        next_url = request.form.get('next', '')
        
        if not username or not password:
            return render_template('auth/login.html', error="Please provide username and password", next=next_url)
            
        # Get client IP for security logging
        ip_address = request.remote_addr
        result = authenticate_user(username, password, ip_address)
        
        if result['status'] == 'success':
            # Store session token in cookie
            session['session_token'] = result['session_token']
            session['username'] = result['username']
            session['role'] = result['role']
            session['user_id'] = result['user_id']
            
            # Set session expiration based on remember me option
            if remember:
                session.permanent = True
            
            # Debug logging to verify redirect logic
            import logging
            logging.debug(f"Login successful for user {username}, role: {result['role']}")
            logging.debug(f"Redirecting to: {next_url if next_url else 'default based on role'}")
            
            # Redirect based on next parameter or role
            if next_url:
                return redirect(next_url)
            elif result['role'] == 'admin':
                return redirect(url_for('admin.dashboard'))
            else:
                return redirect(url_for('client.dashboard'))
        else:
            return render_template('auth/login.html', error=result['message'], next=next_url)
    
    # Detect if this is an admin or client login based on URL
    role = 'Admin' if (request.referrer and '/admin' in request.referrer) or '/admin' in next_url else 'Client'
    
    # GET request - show login form
    return render_template('auth/login.html', role=role, next=next_url)
# Logout route
@auth_bp.route('/logout')
def logout():
    """User logout with session invalidation"""
    session_token = session.get('session_token')
    if session_token:
        logout_user(session_token)
        
    # Clear session
    session.clear()
    flash('You have been successfully logged out', 'info')
    return redirect(url_for('auth.login'))

# User profile route
@auth_bp.route('/profile')
@login_required
def profile(user):
    """User profile page"""
    # Get user details
    user_details = get_user_by_id(user['user_id'])
    
    if user_details['status'] != 'success':
        flash('Error loading user profile', 'danger')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/profile.html',
                          user=user,
                          user_details=user_details['user'],
                          profile=user_details.get('profile', {}),
                          login_history=user_details.get('login_history', []))

# Update profile route
@auth_bp.route('/profile/update', methods=['POST'])
@login_required
def update_profile(user):
    """Update user profile"""
    # Get form data
    user_data = {
        'full_name': request.form.get('full_name'),
        'email': request.form.get('email'),
    }
    
    # Only update password if provided
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    
    if password:
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('auth.profile'))
        
        user_data['password'] = password
    
    # Update user
    result = update_user(user['user_id'], user_data, user['user_id'])
    
    if result['status'] == 'success':
        flash('Profile updated successfully', 'success')
    else:
        flash(f'Profile update failed: {result["message"]}', 'danger')
    
    return redirect(url_for('auth.profile'))

# User management routes (admin only)
@auth_bp.route('/admin/users')
@admin_required
def admin_users(user):
    """Admin user management page"""
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Get filter parameters
    search = request.args.get('search')
    role = request.args.get('role')
    
    # Get users
    result = get_all_users(page, per_page, search, role)
    
    if result['status'] != 'success':
        flash(f'Error loading users: {result["message"]}', 'danger')
        return redirect(url_for('admin.dashboard'))
    
    return render_template('admin/user-management.html',
                          user=user,
                          users=result['users'],
                          pagination=result['pagination'],
                          search=search,
                          role_filter=role)

# Admin create user route
@auth_bp.route('/admin/users/create', methods=['GET', 'POST'])
@admin_required
def admin_create_user(user):
    """Admin create user page"""
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name', '')
        role = request.form.get('role', 'client')
        
        # Basic validation
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return render_template('admin/user-create.html',
                                 user=user,
                                 form_data={
                                     'username': username,
                                     'email': email,
                                     'full_name': full_name,
                                     'role': role
                                 })
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('admin/user-create.html',
                                 user=user,
                                 form_data={
                                     'username': username,
                                     'email': email,
                                     'full_name': full_name,
                                     'role': role
                                 })
        
        # Create user
        result = create_user(username, email, password, full_name, role)
        
        if result['status'] == 'success':
            flash('User created successfully', 'success')
            return redirect(url_for('auth.admin_users'))
        else:
            flash(f'User creation failed: {result["message"]}', 'danger')
            return render_template('admin/user-create.html',
                                 user=user,
                                 form_data={
                                     'username': username,
                                     'email': email,
                                     'full_name': full_name,
                                     'role': role
                                 })
    
    # GET request - show user creation form
    return render_template('admin/user-create.html', user=user)

# Admin view user route
@auth_bp.route('/admin/users/<int:user_id>')
@admin_required
def admin_view_user(user, user_id):
    """Admin view user details page"""
    # Get user details
    user_details = get_user_by_id(user_id)
    
    if user_details['status'] != 'success':
        flash(f'User not found: {user_details["message"]}', 'danger')
        return redirect(url_for('auth.admin_users'))
    
    return render_template('admin/user-detail.html',
                          user=user,
                          target_user=user_details['user'],
                          profile=user_details.get('profile', {}),
                          login_history=user_details.get('login_history', []),
                          audit_logs=user_details.get('audit_logs', []))

# Admin edit user route
@auth_bp.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user, user_id):
    """Admin edit user page"""
    # Get user details
    user_details = get_user_by_id(user_id)
    
    if user_details['status'] != 'success':
        flash(f'User not found: {user_details["message"]}', 'danger')
        return redirect(url_for('auth.admin_users'))
    
    if request.method == 'POST':
        # Get form data
        user_data = {
            'username': request.form.get('username'),
            'email': request.form.get('email'),
            'full_name': request.form.get('full_name'),
            'role': request.form.get('role'),
            'active': 1 if request.form.get('active') == 'on' else 0
        }
        
        # Only update password if provided
        password = request.form.get('password')
        if password:
            user_data['password'] = password
        
        # Update user
        result = update_user(user_id, user_data, user['user_id'])
        
        if result['status'] == 'success':
            flash('User updated successfully', 'success')
            return redirect(url_for('auth.admin_view_user', user_id=user_id))
        else:
            flash(f'User update failed: {result["message"]}', 'danger')
    
    # Render edit user form
    return render_template('admin/user-edit.html',
                          user=user,
                          target_user=user_details['user'])

# Admin delete user route
@auth_bp.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user, user_id):
    """Admin delete user"""
    # Cannot delete yourself
    if user_id == user['user_id']:
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('auth.admin_users'))
    
    # Delete user
    result = delete_user(user_id, user['user_id'])
    
    if result['status'] == 'success':
        flash('User deleted successfully', 'success')
    else:
        flash(f'User deletion failed: {result["message"]}', 'danger')
    
    return redirect(url_for('auth.admin_users'))

# API endpoint for checking username availability
@auth_bp.route('/api/check-username', methods=['POST'])
def check_username():
    """Check if a username is available"""
    username = request.json.get('username')
    
    if not username:
        return jsonify({'available': False, 'message': 'Username is required'})
    
    # Connect to database
    from client_db import CLIENT_DB_PATH
    import sqlite3
    
    conn = sqlite3.connect(CLIENT_DB_PATH)
    cursor = conn.cursor()
    
    # Check if username exists
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    existing_user = cursor.fetchone()
    
    conn.close()
    
    if existing_user:
        return jsonify({'available': False, 'message': 'Username is already taken'})
    
    return jsonify({'available': True, 'message': 'Username is available'})

# API endpoint for checking email availability
@auth_bp.route('/api/check-email', methods=['POST'])
def check_email():
    """Check if an email is available"""
    email = request.json.get('email')
    
    if not email:
        return jsonify({'available': False, 'message': 'Email is required'})
    
    # Connect to database
    from client_db import CLIENT_DB_PATH
    import sqlite3
    
    conn = sqlite3.connect(CLIENT_DB_PATH)
    cursor = conn.cursor()
    
    # Check if email exists
    cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
    existing_user = cursor.fetchone()
    
    conn.close()
    
    if existing_user:
        return jsonify({'available': False, 'message': 'Email is already registered'})
    
    return jsonify({'available': True, 'message': 'Email is available'})

# API endpoint for getting login statistics (admin only)
@auth_bp.route('/api/login-stats')
@admin_required
def api_login_stats(user):
    """Get login statistics for admin dashboard"""
    stats = get_login_stats()
    
    if stats['status'] != 'success':
        return jsonify({
            'status': 'error',
            'message': stats.get('message', 'Failed to retrieve login statistics')
        }), 500
    
    return jsonify({
        'status': 'success',
        'data': stats['stats']
    })

@auth_bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password_request():
    """Password reset request page"""
    if request.method == 'POST':
        email = request.form.get('email')
        
        if not email:
            return render_template('auth/reset-password-request.html', error="Please provide your email")
        
        # Create password reset token - this function should be in client_db.py
        # If not implemented yet, we'll just flash a message and redirect
        try:
            from client_db import create_password_reset_token
            result = create_password_reset_token(email)
        except (ImportError, AttributeError):
            # Function not available yet, just show success message anyway
            # This prevents email enumeration
            pass
        
        # Always show success to prevent email enumeration
        flash('If your email is registered, you will receive reset instructions shortly', 'info')
        return redirect(url_for('auth.login'))
    
    # GET request - show reset password form
    return render_template('auth/reset-password-request.html')

@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_confirm(token):
    """Password reset confirmation page"""
    # Verify the token
    try:
        from client_db import verify_password_reset_token
        token_result = verify_password_reset_token(token)
    except (ImportError, AttributeError):
        # Function not available yet
        token_result = {'status': 'error', 'message': 'Invalid or expired token'}
    
    if token_result.get('status') != 'success':
        flash('Invalid or expired reset token', 'danger')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not password or password != confirm_password:
            return render_template('auth/reset-password-confirm.html', 
                                token=token,
                                error="Passwords do not match")
        
        # Update the password
        try:
            from client_db import update_user_password
            result = update_user_password(token_result['user_id'], password)
        except (ImportError, AttributeError):
            # Function not available yet
            result = {'status': 'error', 'message': 'Password update functionality not implemented'}
        
        if result.get('status') == 'success':
            flash('Your password has been updated successfully', 'success')
            return redirect(url_for('auth.login'))
        else:
            return render_template('auth/reset-password-confirm.html', 
                                token=token,
                                error=result.get('message', 'Failed to update password'))
    
    # GET request - show reset password form
    return render_template('auth/reset-password-confirm.html', token=token)
