#!/usr/bin/env python3
# create_test_admin.py - Script to create a test admin user

import os
import sqlite3
import logging
import secrets
import hashlib
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def create_test_admin():
    """Create a test admin user if it doesn't exist"""
    try:
        # Connect to the database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Check if test_admin user already exists
        cursor.execute("SELECT id FROM users WHERE username = 'test_admin'")
        test_admin = cursor.fetchone()
        
        if test_admin:
            logging.info("Test admin user already exists")
            
            # Update the password just to be sure
            salt = secrets.token_hex(16)
            password = 'test_admin'
            password_hash = hashlib.pbkdf2_hmac(
                'sha256', 
                password.encode(), 
                salt.encode(), 
                100000
            ).hex()
            
            cursor.execute('''
            UPDATE users 
            SET password_hash = ?, salt = ?, updated_at = ?
            WHERE username = 'test_admin'
            ''', (password_hash, salt, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
            logging.info("Test admin password updated to: test_admin")
            return True
        
        # Create salt and hash password
        salt = secrets.token_hex(16)
        password = 'test_admin'
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt.encode(), 
            100000
        ).hex()
        
        # Insert test admin user
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
        ''', ('test_admin', 'test_admin@example.com', password_hash, salt, 'admin', 'Test Administrator', datetime.now().isoformat()))
        
        # Commit changes
        conn.commit()
        conn.close()
        
        logging.info("Test admin user created successfully")
        logging.info("Username: test_admin")
        logging.info("Password: test_admin")
        logging.info("Email: test_admin@example.com")
        
        return True
    except Exception as e:
        logging.error(f"Error creating test admin user: {e}")
        return False

if __name__ == "__main__":
    if create_test_admin():
        print("Test admin user has been created or updated")
        print("Username: test_admin")
        print("Password: test_admin")
        print("Email: test_admin@example.com")
    else:
        print("Failed to create test admin user. Check the logs for details.")
