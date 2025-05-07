from flask import Blueprint, request, redirect, url_for, flash, session, render_template
import secrets
import hashlib
import sqlite3
import os
from datetime import datetime, timedelta

emergency_bp = Blueprint('emergency', __name__)

# Database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

@emergency_bp.route('/emergency-login', methods=['GET', 'POST'])
def emergency_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('auth/login.html', error="Please provide username and password")
        
        try:
            # Manual authentication
            conn = sqlite3.connect(CLIENT_DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Find user
            cursor.execute('SELECT * FROM users WHERE username = ? AND active = 1', (username,))
            user = cursor.fetchone()
            
            if user:
                # Verify password
                try:
                    salt = user['salt']
                    stored_hash = user['password_hash']
                    
                    password_hash = hashlib.pbkdf2_hmac(
                        'sha256', 
                        password.encode(), 
                        salt.encode(), 
                        100000
                    ).hex()
                    
                    if password_hash == stored_hash:
                        # Create session manually
                        session_token = secrets.token_hex(32)
                        created_at = datetime.now().isoformat()
                        expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
                        
                        # Insert session
                        cursor.execute('''
                        INSERT INTO sessions (
                            user_id, session_token, created_at, expires_at, ip_address
                        ) VALUES (?, ?, ?, ?, ?)
                        ''', (user['id'], session_token, created_at, expires_at, request.remote_addr))
                        
                        conn.commit()
                        
                        # Set session variables
                        session['session_token'] = session_token
                        session['username'] = user['username']
                        session['role'] = user['role']
                        
                        flash('Emergency login successful', 'success')
                        if user['role'] == 'admin':
                            return redirect(url_for('admin.dashboard'))
                        else:
                            return redirect(url_for('client.dashboard'))
                except Exception as verify_error:
                    flash(f'Password verification error: {str(verify_error)}', 'danger')
            
            flash('Invalid credentials', 'danger')
            conn.close()
        except Exception as e:
            flash(f'Login error: {str(e)}', 'danger')
        
    return render_template('auth/login.html', emergency=True)
