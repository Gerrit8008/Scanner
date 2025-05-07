import sqlite3
import secrets
import hashlib
import os
from datetime import datetime, timedelta

# Database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

# Create emergency admin user
def create_emergency_admin():
    """Create an emergency admin user directly in the database"""
    try:
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Check if emergency admin exists
        cursor.execute("SELECT id FROM users WHERE username = 'emergency_admin'")
        admin = cursor.fetchone()
        
        if admin:
            print("Emergency admin already exists")
            conn.close()
            return True
            
        # Create salt and hash password
        salt = secrets.token_hex(16)
        password = 'admin123'
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt.encode(), 
            100000
        ).hex()
        
        # Insert the admin user
        cursor.execute('''
        INSERT INTO users (
            username,
            email,
            password_hash,
            salt,
            role,
            created_at,
            active
        ) VALUES (?, ?, ?, ?, ?, ?, 1)
        ''', (
            'emergency_admin',
            'emergency@example.com',
            password_hash,
            salt,
            'admin',
            datetime.now().isoformat()
        ))
        
        # Get the new user ID
        user_id = cursor.lastrowid
        
        # Create a session token
        session_token = secrets.token_hex(32)
        created_at = datetime.now().isoformat()
        expires_at = (datetime.now() + timedelta(days=30)).isoformat()
        
        # Insert session 
        cursor.execute('''
        INSERT INTO sessions (
            user_id,
            session_token,
            created_at,
            expires_at
        ) VALUES (?, ?, ?, ?)
        ''', (
            user_id,
            session_token,
            created_at,
            expires_at
        ))
        
        # Commit changes
        conn.commit()
        conn.close()
        
        print("Emergency admin created successfully")
        print(f"Username: emergency_admin")
        print(f"Password: admin123")
        print(f"Session token: {session_token}")
        return True
    except Exception as e:
        print(f"Error creating emergency admin: {str(e)}")
        return False

if __name__ == "__main__":
    create_emergency_admin()
