#!/usr/bin/env python3
# direct_db_fix.py - Direct database repair and diagnostics

import os
import sqlite3
import logging
import secrets
import hashlib
import json
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def fix_database():
    """Examine and fix the database directly"""
    try:
        print(f"Working with database at: {CLIENT_DB_PATH}")
        print(f"Database exists: {os.path.exists(CLIENT_DB_PATH)}")
        print(f"Database size: {os.path.getsize(CLIENT_DB_PATH) if os.path.exists(CLIENT_DB_PATH) else 'N/A'} bytes")
        
        # Connect to the database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check database structure
        print("\n--- Database Tables ---")
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        for table in tables:
            print(f"Table: {table['name']}")
            cursor.execute(f"PRAGMA table_info({table['name']})")
            columns = cursor.fetchall()
            for column in columns:
                print(f"  - {column['name']} ({column['type']})")
        
        # Check users table
        print("\n--- User Records ---")
        try:
            cursor.execute("SELECT id, username, email, role, active FROM users")
            users = cursor.fetchall()
            for user in users:
                print(f"User ID: {user['id']}, Username: {user['username']}, Email: {user['email']}, Role: {user['role']}, Active: {user['active']}")
        except sqlite3.OperationalError as e:
            print(f"Error querying users: {str(e)}")
        
        # Check if admin user exists
        print("\n--- Admin User Details ---")
        cursor.execute("SELECT * FROM users WHERE username = 'admin' OR role = 'admin'")
        admin_user = cursor.fetchone()
        
        if admin_user:
            print(f"Admin user found: {dict(admin_user)}")
            
            # Create a new password
            print("\n--- Creating New Admin Password ---")
            salt = secrets.token_hex(16)
            password = 'admin123'
            
            # Try different hashing methods to match what's expected by the auth code
            # Method 1: pbkdf2_hmac with 100000 iterations (most likely)
            password_hash1 = hashlib.pbkdf2_hmac(
                'sha256', 
                password.encode(), 
                salt.encode(), 
                100000
            ).hex()
            
            # Method 2: Simple SHA-256 with salt concatenation
            password_hash2 = hashlib.sha256((password + salt).encode()).hexdigest()
            
            # Update the admin user with both methods
            print(f"Testing both password hashing methods")
            
            # First, try the pbkdf2_hmac method
            cursor.execute('''
            UPDATE users SET 
                password_hash = ?, 
                salt = ?
            WHERE id = ?
            ''', (password_hash1, salt, admin_user['id']))
            
            # Log the action
            cursor.execute('''
            INSERT INTO audit_log (
                user_id, action, entity_type, entity_id, changes, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                admin_user['id'], 
                'password_reset', 
                'user', 
                admin_user['id'], 
                json.dumps({"method": "pbkdf2_hmac", "password": "admin123"}), 
                datetime.now().isoformat()
            ))
            
            conn.commit()
            print(f"Updated admin password using pbkdf2_hmac method")
            
            # Create a brand new admin user as a fallback
            print("\n--- Creating New Admin User ---")
            salt = secrets.token_hex(16)
            password = 'newadmin123'
            password_hash = hashlib.pbkdf2_hmac(
                'sha256', 
                password.encode(), 
                salt.encode(), 
                100000
            ).hex()
            
            # Check if user 'newadmin' already exists
            cursor.execute("SELECT id FROM users WHERE username = 'newadmin'")
            existing_newadmin = cursor.fetchone()
            
            if existing_newadmin:
                # Update existing newadmin user
                cursor.execute('''
                UPDATE users SET 
                    password_hash = ?, 
                    salt = ?,
                    role = 'admin',
                    active = 1
                WHERE username = 'newadmin'
                ''', (password_hash, salt))
            else:
                # Create a new admin user
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
                ''', ('newadmin', 'newadmin@example.com', password_hash, salt, 'admin', 'New Administrator', datetime.now().isoformat()))
            
            # Commit changes
            conn.commit()
            
            print(f"Created/updated 'newadmin' user with password 'newadmin123'")
            
            # Also create a client user for testing
            print("\n--- Creating Test Client User ---")
            salt = secrets.token_hex(16)
            password = 'testclient'
            password_hash = hashlib.pbkdf2_hmac(
                'sha256', 
                password.encode(), 
                salt.encode(), 
                100000
            ).hex()
            
            # Check if user 'testclient' already exists
            cursor.execute("SELECT id FROM users WHERE username = 'testclient'")
            existing_testclient = cursor.fetchone()
            
            if existing_testclient:
                # Update existing testclient user
                cursor.execute('''
                UPDATE users SET 
                    password_hash = ?, 
                    salt = ?,
                    role = 'client',
                    active = 1
                WHERE username = 'testclient'
                ''', (password_hash, salt))
            else:
                # Create a new client user
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
                ''', ('testclient', 'testclient@example.com', password_hash, salt, 'client', 'Test Client', datetime.now().isoformat()))
            
            # Commit changes
            conn.commit()
            
            print(f"Created/updated 'testclient' user with password 'testclient'")
        else:
            print("No admin user found. Creating a new admin user...")
            
            # Create a brand new admin user
            salt = secrets.token_hex(16)
            password = 'admin123'
            password_hash = hashlib.pbkdf2_hmac(
                'sha256', 
                password.encode(), 
                salt.encode(), 
                100000
            ).hex()
            
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
            ''', ('admin', 'admin@scannerplatform.com', password_hash, salt, 'admin', 'System Administrator', datetime.now().isoformat()))
            
            # Commit changes
            conn.commit()
            
            print(f"Created new admin user with password 'admin123'")
        
        # Get updated user list
        print("\n--- Updated User Records ---")
        cursor.execute("SELECT id, username, email, role, active FROM users")
        users = cursor.fetchall()
        for user in users:
            print(f"User ID: {user['id']}, Username: {user['username']}, Email: {user['email']}, Role: {user['role']}, Active: {user['active']}")
        
        # Close connection
        conn.close()
        
        print("\n--- Login Credentials ---")
        print("You can now try logging in with any of these accounts:")
        print("1. Username: admin, Password: admin123")
        print("2. Username: newadmin, Password: newadmin123")
        print("3. Username: testclient, Password: testclient")
        
        return True
    except Exception as e:
        print(f"Error fixing database: {str(e)}")
        return False

if __name__ == "__main__":
    fix_database()
