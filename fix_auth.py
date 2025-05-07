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

def authenticate_user(username_or_email, password, ip_address=None, user_agent=None):
    """
    Fixed authenticate_user function that properly handles all parameters
    
    Args:
        username_or_email: Username or email for login
        password: Password for login
        ip_address: IP address of the request (optional)
        user_agent: User agent string (optional)
        
    Returns:
        dict: Authentication result
    """
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

def apply_authentication_fix():
    """Apply authentication fix by monkey patching the original function"""
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

def create_admin_user(password="admin123"):
    """Create or reset the admin user password"""
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
                role = 'admin'
            WHERE username = 'admin'
            ''', (password_hash, salt))
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
