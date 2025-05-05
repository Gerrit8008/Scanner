#!/usr/bin/env python3
# reset_admin_password.py - Script to reset admin password

import os
import sqlite3
import logging
import traceback
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

def reset_admin_password(new_password="admin123"):
    """Reset the admin user password"""
    try:
        # Connect to the database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Check if admin user exists
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        admin = cursor.fetchone()
        
        if not admin:
            logging.error("Admin user does not exist")
            conn.close()
            return False
        
        # Create salt and hash password
        salt = secrets.token_hex(16)
        
        # Use the exact same hashing method as in auth_helper.py
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            new_password.encode(), 
            salt.encode(), 
            100000  # More iterations for better security
        ).hex()
        
        # Update the admin password
        cursor.execute('''
        UPDATE users 
        SET password_hash = ?, salt = ?, updated_at = ?
        WHERE username = 'admin'
        ''', (password_hash, salt, datetime.now().isoformat()))
        
        # Commit changes
        conn.commit()
        conn.close()
        
        logging.info(f"Admin password reset successfully to: {new_password}")
        return True
    except Exception as e:
        logging.error(f"Error resetting admin password: {e}")
        logging.debug(traceback.format_exc())
        return False

if __name__ == "__main__":
    if reset_admin_password():
        print("Admin password has been reset to 'admin123'")
    else:
        print("Failed to reset admin password. Check the logs for details.")
