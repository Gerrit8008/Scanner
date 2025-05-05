# auth.py
import os
import logging
import uuid
from flask import Blueprint, request, jsonify, session, redirect, url_for, render_template, flash
from werkzeug.utils import secure_filename
from client_db import (
    authenticate_user, verify_session, logout_user, 
    create_user
)

# Create blueprint for authentication routes
auth_bp = Blueprint('auth', __name__)

# Login route
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
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
    role = 'Admin' if '/admin' in request.referrer or '/admin' in next_url else 'Client'
    
    # GET request - show login form
    return render_template('auth/login.html', role=role, next=next_url)

# Logout route
@auth_bp.route('/logout')
def logout():
    session_token = session.get('session_token')
    if session_token:
        logout_user(session_token)
        
    # Clear session
    session.clear()
    return redirect(url_for('auth.login'))

# Password reset request route
@auth_bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form.get('email')
        
        if not email:
            return render_template('auth/reset-password-request.html', error="Please provide your email")
        
        # Create password reset token
        from client_db import create_password_reset_token
        result = create_password_reset_token(email)
        
        # Always show success to prevent email enumeration
        flash('If your email is registered, you will receive reset instructions shortly', 'info')
        return redirect(url_for('auth.login'))
    
    # GET request - show reset password form
    return render_template('auth/reset-password-request.html')

# Password reset confirmation route
@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_confirm(token):
    # Verify the token
    from client_db import verify_password_reset_token
    token_result = verify_password_reset_token(token)
    
    if token_result['status'] != 'success':
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
        from client_db import update_user_password
        result = update_user_password(token_result['user_id'], password)
        
        if result['status'] == 'success':
            flash('Your password has been updated successfully', 'success')
            return redirect(url_for('auth.login'))
        else:
            return render_template('auth/reset-password-confirm.html', 
                                token=token,
                                error=result['message'])
    
    # GET request - show reset password form
    return render_template('auth/reset-password-confirm.html', token=token)
