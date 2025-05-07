# Save this as auth_hotfix.py in your application directory
# This file contains a direct hotfix for the authentication system

import os
import sqlite3
import secrets
import hashlib
import logging
from datetime import datetime, timedelta
from flask import session, request

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def hotfix_auth():
    """Apply the authentication hotfix by monkey patching the authenticate_user function"""
    try:
        # Import the client_db module
        import client_db
        
        # Define the fixed authenticate_user function
        def fixed_authenticate_user(username_or_email, password, ip_address=None, user_agent=None):
            """Fixed authenticate_user with proper handling of all parameters"""
            try:
                # Connect to database
                conn = sqlite3.connect(CLIENT_DB_PATH)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Find user by username or email
                cursor.execute('''
                SELECT * FROM users 
                WHERE (username = ? OR email = ?) AND active = 1
                ''', (username_or_email, username_or_email))
                
                user = cursor.fetchone()
                
                if not user:
                    # Use constant time comparison to prevent timing attacks
                    dummy_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), b'dummy', 100000).hex()
                    secrets.compare_digest(dummy_hash, dummy_hash)  # Constant time comparison
                    
                    # Log failed login attempt
                    logger.warning(f"Failed login attempt for non-existent user: {username_or_email} from IP: {ip_address}")
                    
                    conn.close()
                    return {"status": "error", "message": "Invalid credentials"}
                
                # Verify password
                try:
                    # Use pbkdf2_hmac if salt exists (new format)
                    salt = user['salt']
                    stored_hash = user['password_hash']
                    
                    # Compute hash with pbkdf2
                    password_hash = hashlib.pbkdf2_hmac(
                        'sha256', 
                        password.encode(), 
                        salt.encode(), 
                        100000  # Same iterations as used for storing
                    ).hex()
                    
                    password_correct = (password_hash == stored_hash)
                    
                except Exception as pw_error:
                    # Fallback to simple hash if pbkdf2 fails
                    try:
                        password_hash = hashlib.sha256((password + user['salt']).encode()).hexdigest()
                        password_correct = (password_hash == user['password_hash'])
                    except Exception as fallback_error:
                        logger.error(f"Error in password verification: {fallback_error}")
                        password_correct = False
                
                if not password_correct:
                    logger.warning(f"Failed login attempt for user: {user['username']} (ID: {user['id']}) from IP: {ip_address}")
                    
                    conn.close()
                    return {"status": "error", "message": "Invalid credentials"}
                
                # Create a session token
                session_token = secrets.token_hex(32)
                created_at = datetime.now().isoformat()
                expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
                
                logger.debug(f"Creating session for user {user['username']} (ID: {user['id']})")
                
                # Store session in database
                cursor.execute('''
                INSERT INTO sessions (
                    user_id, 
                    session_token, 
                    created_at, 
                    expires_at, 
                    ip_address
                ) VALUES (?, ?, ?, ?, ?)
                ''', (user['id'], session_token, created_at, expires_at, ip_address))
                
                # Update last login timestamp
                cursor.execute('''
                UPDATE users 
                SET last_login = ? 
                WHERE id = ?
                ''', (created_at, user['id']))
                
                conn.commit()
                
                logger.info(f"Authentication successful for user: {user['username']} (ID: {user['id']}) from IP: {ip_address}")
                
                conn.close()
                
                return {
                    "status": "success",
                    "user_id": user['id'],
                    "username": user['username'],
                    "email": user['email'],
                    "role": user['role'],
                    "session_token": session_token
                }
            
            except Exception as e:
                logger.error(f"Authentication error: {e}")
                
                return {"status": "error", "message": f"Authentication failed due to a system error"}
        
        # Replace the original authenticate_user with our fixed version
        logger.info("Applying authentication hotfix...")
        client_db.authenticate_user = fixed_authenticate_user
        logger.info("Authentication hotfix applied successfully!")
        
        return True
    except Exception as e:
        logger.error(f"Failed to apply authentication hotfix: {e}")
        return False

# Create emergency admin user
def create_emergency_admin():
    """Create an emergency admin user"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Check if admin user exists
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        admin = cursor.fetchone()
        
        # Generate secure password
        salt = secrets.token_hex(16)
        password = 'admin123'
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt.encode(), 
            100000
        ).hex()
        
        if admin:
            # Update admin password
            cursor.execute('''
            UPDATE users SET 
                password_hash = ?, 
                salt = ?,
                role = 'admin',
                active = 1
            WHERE username = 'admin'
            ''', (password_hash, salt))
            logger.info("Admin user updated with new password")
        else:
            # Create new admin user
            cursor.execute('''
            INSERT INTO users (
                username, 
                email, 
                password_hash, 
                salt, 
                role, 
                full_name, 
                created_at, 
                active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            ''', ('admin', 'admin@example.com', password_hash, salt, 'admin', 'System Administrator', datetime.now().isoformat()))
            logger.info("Admin user created successfully")
        
        conn.commit()
        conn.close()
        
        return {
            "status": "success",
            "username": "admin",
            "password": "admin123"
        }
    except Exception as e:
        logger.error(f"Error creating admin user: {e}")
        return {
            "status": "error",
            "message": str(e)
        }

# Add the hotfix application to app.py's before_first_request decorator
def register_auth_hotfix(app):
    """Register the authentication hotfix with the Flask app"""
    @app.before_first_request
    def apply_hotfix():
        logger.info("Applying authentication hotfix before first request...")
        hotfix_auth()
        admin_result = create_emergency_admin()
        if admin_result["status"] == "success":
            logger.info(f"Emergency admin created/updated: username: {admin_result['username']}, password: {admin_result['password']}")
        
    return app

# If run directly, apply the hotfix and create admin user
if __name__ == "__main__":
    hotfix_auth()
    admin_result = create_emergency_admin()
    if admin_result["status"] == "success":
        print(f"Emergency admin created/updated:")
        print(f"Username: {admin_result['username']}")
        print(f"Password: {admin_result['password']}")
    else:
        print(f"Error: {admin_result['message']}")
