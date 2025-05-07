# Save this as auth_patched.py

from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import logging
import os
import sqlite3
from datetime import datetime, timedelta

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

# Import the fixed authentication function
from fix_auth import authenticate_user_wrapper, CLIENT_DB_PATH

# Create blueprint for authentication routes
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# Login route
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Fixed login route that correctly passes parameters to authenticate_user"""
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
            
        # Get client IP and user agent for security logging
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        
        # Use the fixed authentication function with the correct number of parameters
        result = authenticate_user_wrapper(username, password, ip_address, user_agent)
        
        if result['status'] == 'success':
            # Store session token in cookie
            session['session_token'] = result['session_token']
            session['username'] = result['username']
            session['role'] = result['role']
            
            # Log successful login
            logger.info(f"User {username} logged in successfully")
            
            # Redirect based on next parameter or role
            if next_url:
                return redirect(next_url)
            elif result['role'] == 'admin':
                return redirect(url_for('admin.dashboard'))
            else:
                return redirect(url_for('client.dashboard'))
        else:
            logger.warning(f"Failed login attempt for user: {username}")
            return render_template('auth/login.html', error=result['message'], next=next_url)
    
    # Detect if this is an admin or client login based on URL
    role = 'Admin' if (request.referrer and '/admin' in request.referrer) or '/admin' in next_url else 'Client'
    
    # GET request - show login form
    return render_template('auth/login.html', role=role, next=next_url)

# Add the verify_session function here for completeness
def verify_session(session_token):
    """Verify a session token"""
    try:
        if not session_token:
            return {"status": "error", "message": "No session token provided"}
        
        # Create a new connection for each verification
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Find the session and join with user data
        cursor.execute('''
        SELECT s.*, u.username, u.email, u.role, u.full_name, u.id as user_id
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.session_token = ? AND u.active = 1
        ''', (session_token,))
        
        session = cursor.fetchone()
        
        if not session:
            conn.close()
            return {"status": "error", "message": "Invalid or expired session"}
        
        # Check if session is expired
        if 'expires_at' in session and session['expires_at']:
            try:
                expires_at = datetime.fromisoformat(session['expires_at'])
                now = datetime.now()
                if now > expires_at:
                    conn.close()
                    return {"status": "error", "message": "Session expired"}
            except Exception as date_err:
                logger.warning(f"Error parsing session expiry: {date_err}")
        
        # Return success with user info
        result = {
            "status": "success",
            "user": {
                "user_id": session['user_id'],
                "username": session['username'],
                "email": session['email'],
                "role": session['role'],
                "full_name": session.get('full_name', '')
            }
        }
        
        conn.close()
        return result
    
    except Exception as e:
        logger.error(f"Session verification error: {str(e)}")
        return {"status": "error", "message": f"Session verification failed: {str(e)}"}

# Logout route
@auth_bp.route('/logout')
def logout():
    """Logout a user by invalidating their session"""
    session_token = session.get('session_token')
    if session_token:
        try:
            # Connect to database
            conn = sqlite3.connect(CLIENT_DB_PATH)
            cursor = conn.cursor()
            
            # Delete the session
            cursor.execute('DELETE FROM sessions WHERE session_token = ?', (session_token,))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error during logout: {e}")
        
    # Clear session
    session.clear()
    return redirect(url_for('auth.login'))
