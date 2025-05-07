#!/usr/bin/env python3
# apply_auth_fix.py - Apply the authentication fix to the system

import os
import sys
import shutil
import sqlite3
import secrets
import hashlib
from datetime import datetime

print("Starting authentication system fix...")

# Get the absolute path to the current directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Define paths to files
CLIENT_DB_PATH = os.path.join(BASE_DIR, 'client_scanner.db')
AUTH_PY_PATH = os.path.join(BASE_DIR, 'auth.py')
AUTH_BACKUP_PATH = os.path.join(BASE_DIR, 'auth.py.bak')
FIX_AUTH_PATH = os.path.join(BASE_DIR, 'fix_auth.py')
AUTH_PATCHED_PATH = os.path.join(BASE_DIR, 'auth_patched.py')

# Step 1: Back up the original auth.py file
if os.path.exists(AUTH_PY_PATH):
    print(f"Backing up original auth.py to {AUTH_BACKUP_PATH}")
    try:
        shutil.copy2(AUTH_PY_PATH, AUTH_BACKUP_PATH)
        print("Backup successful")
    except Exception as e:
        print(f"Error backing up auth.py: {e}")
        print("Continuing anyway...")
else:
    print("Warning: auth.py not found in the current directory!")

# Step 2: Create fix_auth.py if it doesn't exist
if not os.path.exists(FIX_AUTH_PATH):
    print("Creating fix_auth.py...")
    try:
        with open(FIX_AUTH_PATH, 'w') as f:
            f.write("""import os
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def authenticate_user(conn, cursor, username_or_email, password, ip_address=None, user_agent=None):
    \"\"\"
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
    \"\"\"
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
    \"\"\"
    Wrapper for authenticate_user that handles database connection
    
    This function has the same signature as the original authenticate_user function
    but takes care of creating and closing the database connection.
    \"\"\"
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
""")
        print("fix_auth.py created successfully")
    except Exception as e:
        print(f"Error creating fix_auth.py: {e}")
        sys.exit(1)

# Step 3: Patch the auth.py file
print("Patching auth.py...")
try:
    with open(AUTH_PY_PATH, 'r') as f:
        original_content = f.read()
    
    # Look for the authenticate_user import and replace it
    if 'from client_db import authenticate_user' in original_content:
        modified_content = original_content.replace(
            'from client_db import authenticate_user', 
            '# Import the fixed authentication function\nfrom fix_auth import authenticate_user_wrapper as authenticate_user'
        )
        
        # Write the modified content back to auth.py
        with open(AUTH_PY_PATH, 'w') as f:
            f.write(modified_content)
        
        print("auth.py patched successfully")
    else:
        print("Warning: Could not find authenticate_user import in auth.py")
        print("Trying alternate approach with auth_patched.py...")
        
        if os.path.exists(AUTH_PATCHED_PATH):
            shutil.copy2(AUTH_PATCHED_PATH, AUTH_PY_PATH)
            print("Replaced auth.py with auth_patched.py")
        else:
            print("auth_patched.py not found. Could not apply fix!")
            sys.exit(1)
except Exception as e:
    print(f"Error patching auth.py: {e}")
    sys.exit(1)

# Step 4: Create emergency admin user
print("Creating emergency admin user...")
try:
    conn = sqlite3.connect(CLIENT_DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Check if admin user exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    admin_exists = cursor.fetchone()[0] > 0
    
    if not admin_exists:
        # Create salt and hash password
        salt = secrets.token_hex(16)
        password = 'admin123'
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt.encode(), 
            100000
        ).hex()
        
        # Insert admin user
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
        
        conn.commit()
        print("Emergency admin user created successfully")
        print("  Username: admin")
        print("  Password: admin123")
    else:
        print("Admin user already exists, resetting password...")
        
        # Reset admin password
        salt = secrets.token_hex(16)
        password = 'admin123'
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt.encode(), 
            100000
        ).hex()
        
        cursor.execute('''
        UPDATE users 
        SET password_hash = ?, salt = ?, active = 1
        WHERE username = 'admin'
        ''', (password_hash, salt))
        
        conn.commit()
        print("Admin password reset successfully")
        print("  Username: admin")
        print("  Password: admin123")
    
    conn.close()
except Exception as e:
    print(f"Error creating/updating admin user: {e}")
    sys.exit(1)

print("\nAuthentication fix applied successfully!")
print("You can now log in with:")
print("  Username: admin")
print("  Password: admin123")
print("\nIf you still experience issues, please restart the application.")
