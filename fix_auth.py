# Save this as fix_auth.py

import os
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta
from fix_auth import authenticate_user_wrapper as authenticate_user

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def authenticate_user(conn, cursor, username_or_email, password, ip_address=None, user_agent=None):
    """
    Fixed authenticate_user with proper handling of all parameters
    
    Args:
        conn: Database connection
        cursor: Database cursor
        username_or_email: Username or email for login
        password: Password for login
        ip_address: IP address of the request (optional)
        user_agent: User agent string (optional)
        
    Returns:
        dict: Authentication result
    """
    try:
        # Find user by username or email
        cursor.execute('''
        SELECT * FROM users 
        WHERE (username = ? OR email = ?) AND active = 1
        ''', (username_or_email, username_or_email))
        
        user = cursor.fetchone()
        
        if not user:
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
                password_correct = False
        
        if not password_correct:
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
        
        # Return successful authentication result
        return {
            "status": "success",
            "user_id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "role": user['role'],
            "session_token": session_token
        }
    
    except Exception as e:
        print(f"Authentication error: {e}")
        return {"status": "error", "message": f"Authentication failed: {str(e)}"}

# Add a wrapper function that handles the database connection itself
def authenticate_user_wrapper(username_or_email, password, ip_address=None, user_agent=None):
    """
    Wrapper for authenticate_user that handles database connection
    
    This function has the same signature as the original authenticate_user function
    but takes care of creating and closing the database connection.
    """
    try:
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Call the actual authenticate function
        result = authenticate_user(conn, cursor, username_or_email, password, ip_address, user_agent)
        
        # Commit changes if successful
        if result['status'] == 'success':
            conn.commit()
        
        # Close connection
        conn.close()
        
        return result
        
    except Exception as e:
        print(f"Authentication wrapper error: {e}")
        return {"status": "error", "message": f"Authentication failed: {str(e)}"}

# Test the function with direct usage
if __name__ == "__main__":
    # Test authentication with admin user
    result = authenticate_user_wrapper('admin', 'admin123')
    print(f"Authentication result: {result}")
