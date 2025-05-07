import os
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def authenticate_user(username_or_email, password, ip_address=None, user_agent=None, remember=False):
    """
    Updated authenticate_user function that accepts all parameters
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
        salt = user['salt']
        stored_hash = user['password_hash']
        
        # Compute hash with pbkdf2
        try:
            password_hash = hashlib.pbkdf2_hmac(
                'sha256', 
                password.encode(), 
                salt.encode(), 
                100000  # Same iterations as used for storing
            ).hex()
        except:
            # Fallback to simple hash if pbkdf2 fails
            password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        
        if password_hash != stored_hash:
            conn.close()
            return {"status": "error", "message": "Invalid credentials"}
        
        # Create a session token
        session_token = secrets.token_hex(32)
        created_at = datetime.now().isoformat()
        
        # Set expiration based on remember flag
        if remember:
            expires_at = (datetime.now() + timedelta(days=30)).isoformat()
        else:
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
        print(f"Authentication error: {e}")
        return {"status": "error", "message": f"Authentication failed: {str(e)}"}

# Function to verify and update auth.py
def update_auth_file():
    """Update the auth.py file with the correct function signature"""
    auth_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'auth.py')
    
    if os.path.exists(auth_file):
        with open(auth_file, 'r') as f:
            content = f.read()
        
        # Replace the authenticate_user import
        if 'from client_db import authenticate_user' in content:
            content = content.replace(
                'from client_db import authenticate_user', 
                '# Import the fixed authenticate_user function\nfrom fix_auth import authenticate_user'
            )
            
            with open(auth_file, 'w') as f:
                f.write(content)
            
            print(f"Updated {auth_file} to use the fixed authenticate_user function")
            return True
    return False

# Run the function
if __name__ == "__main__":
    print("Fixing authenticate_user function...")
    updated = update_auth_file()
    
    if updated:
        print("Auth file updated successfully!")
    else:
        print("Couldn't update auth.py. You may need to manually fix the function signature.")
