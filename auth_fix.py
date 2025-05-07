#!/usr/bin/env python3
# auth_fix.py - Fix for the authentication system mismatch

import os
import sqlite3
import secrets
import hashlib
import logging
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def fix_authentication_system():
    """
    Apply the fix to the authentication system by patching or replacing the appropriate files
    """
    logger.info("Starting authentication system fix...")
    
    # 1. Create the correct authenticate_user function with proper parameter handling
    create_fixed_authenticate_user()
    
    # 2. Create a modified version of auth.py that uses the fixed function
    result = patch_auth_file()
    
    # 3. Create/Update admin user with known credentials
    create_admin_user()
    
    logger.info("Authentication system fix completed!")
    return result

def create_fixed_authenticate_user():
    """Create a fixed version of the authenticate_user function in fix_auth.py"""
    
    fix_auth_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fix_auth.py')
    
    with open(fix_auth_path, 'w') as f:
        f.write("""import os
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def authenticate_user(username_or_email, password, ip_address=None, user_agent=None):
    \"\"\"
    Fixed authenticate_user function that properly handles all parameters
    
    Args:
        username_or_email: Username or email for login
        password: Password for login
        ip_address: IP address of the request (optional)
        user_agent: User agent string (optional)
        
    Returns:
        dict: Authentication result
    \"\"\"
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
            logger.warning(f"Error in password verification with pbkdf2: {pw_error}, falling back to simple hash")
            # Fallback to simple hash if pbkdf2 fails
            try:
                password_hash = hashlib.sha256((password + user['salt']).encode()).hexdigest()
                password_correct = (password_hash == user['password_hash'])
            except Exception as fallback_error:
                logger.error(f"Error in fallback password verification: {fallback_error}")
                password_correct = False
        
        if not password_correct:
            conn.close()
            return {"status": "error", "message": "Invalid credentials"}
        
        # Create a session token
        session_token = secrets.token_hex(32)
        created_at = datetime.now().isoformat()
        expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
        
        # Store session in database
        cursor.execute('''
        INSERT INTO sessions (
            user_id, 
            session_token, 
            created_at, 
            expires_at, 
            ip_address,
            user_agent
        ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (user['id'], session_token, created_at, expires_at, ip_address, user_agent))
        
        # Update last login timestamp
        cursor.execute('''
        UPDATE users 
        SET last_login = ? 
        WHERE id = ?
        ''', (created_at, user['id']))
        
        conn.commit()
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
        return {"status": "error", "message": f"Authentication failed: {str(e)}"}

# Apply the fix by creating a hotfix module
def apply_authentication_fix():
    \"\"\"Apply authentication fix by monkey patching the original function\"\"\"
    import importlib
    try:
        # Import the client_db module where the original function is
        client_db = importlib.import_module('client_db')
        
        # Replace the authenticate_user function with our fixed version
        client_db.authenticate_user = authenticate_user
        
        return True
    except Exception as e:
        logger.error(f"Failed to apply authentication fix: {e}")
        return False

# Create admin user
def create_admin_user(password="admin123"):
    \"\"\"Create or reset the admin user password\"\"\"
    try:
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Check if admin user exists
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        admin_user = cursor.fetchone()
        
        # Generate secure password hash
        salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt.encode(), 
            100000
        ).hex()
        
        current_time = datetime.now().isoformat()
        
        if admin_user:
            # Update existing admin user
            cursor.execute('''
            UPDATE users SET 
                password_hash = ?, 
                salt = ?,
                role = 'admin',
                updated_at = ?,
                active = 1
            WHERE username = 'admin'
            ''', (password_hash, salt, current_time))
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
            ''', ('admin', 'admin@example.com', password_hash, salt, 'admin', 'System Administrator', current_time))
        
        conn.commit()
        conn.close()
        
        logger.info("Admin user created/updated successfully")
        return True
    except Exception as e:
        logger.error(f"Error creating admin user: {e}")
        return False

if __name__ == "__main__":
    # Test the fix
    apply_authentication_fix()
    create_admin_user()
    print("Authentication fix applied and admin user created/updated")
    print("Username: admin")
    print("Password: admin123")
""")
    
    logger.info("Created fixed authenticate_user function in fix_auth.py")
    return True

def patch_auth_file():
    """Create a patched version of auth.py that uses the fixed authenticate function"""
    
    auth_hotfix_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'auth_hotfix.py')
    
    with open(auth_hotfix_path, 'w') as f:
        f.write("""# Save this as auth_hotfix.py in your application directory
# This file contains a direct hotfix for the authentication system

def register_auth_hotfix(app):
    \"\"\"Register the authentication hotfix with the Flask app\"\"\"
    @app.before_first_request
    def apply_hotfix():
        # Import and apply the fix
        from fix_auth import apply_authentication_fix, create_admin_user
        
        # Apply the fix to the authenticate_user function
        apply_authentication_fix()
        
        # Create/update admin user with known credentials
        create_admin_user()
        
        app.logger.info("Authentication hotfix applied successfully")
    
    return app
""")
    
    logger.info("Created auth_hotfix.py for patching authentication system")
    return True

def create_admin_user():
    """Create or update the admin user with known credentials"""
    try:
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Check if admin user exists
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        admin_user = cursor.fetchone()
        
        # Generate secure password hash
        salt = secrets.token_hex(16)
        password = 'admin123'
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt.encode(), 
            100000
        ).hex()
        
        current_time = datetime.now().isoformat()
        
        if admin_user:
            # Update existing admin user
            cursor.execute('''
            UPDATE users SET 
                password_hash = ?, 
                salt = ?,
                role = 'admin',
                active = 1
            WHERE username = 'admin'
            ''', (password_hash, salt))
            logger.info("Updated existing admin user")
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
            ''', ('admin', 'admin@example.com', password_hash, salt, 'admin', 'System Administrator', current_time))
            logger.info("Created new admin user")
        
        conn.commit()
        conn.close()
        
        logger.info("Admin user created/updated - Username: admin, Password: admin123")
        return True
    except Exception as e:
        logger.error(f"Error creating admin user: {e}")
        return False

if __name__ == "__main__":
    fix_authentication_system()
