#!/usr/bin/env python3
# db_fix.py - Comprehensive database fix for security scanner app

import os
import sqlite3
import secrets
import hashlib
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def fix_database():
    """
    Comprehensive fix for database issues:
    1. Ensure tables exist with correct schema
    2. Create admin user
    3. Clear problematic sessions
    """
    try:
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Step 1: Ensure tables exist
        logger.info("Checking and creating database tables...")
        
        # Users table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT DEFAULT 'client',
            full_name TEXT,
            created_at TEXT,
            last_login TEXT,
            active INTEGER DEFAULT 1
        )
        """)
        
        # Sessions table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            created_at TEXT,
            expires_at TEXT,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)
        
        # Clients table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            business_name TEXT NOT NULL,
            business_domain TEXT NOT NULL,
            contact_email TEXT NOT NULL,
            contact_phone TEXT,
            scanner_name TEXT,
            subscription_level TEXT DEFAULT 'basic',
            subscription_status TEXT DEFAULT 'active',
            subscription_start TEXT,
            subscription_end TEXT,
            api_key TEXT UNIQUE,
            created_at TEXT,
            created_by INTEGER,
            updated_at TEXT,
            updated_by INTEGER,
            active INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES users(id),
            FOREIGN KEY (updated_by) REFERENCES users(id)
        )
        """)
        
        # Step 2: Clear all sessions to fix any issues
        logger.info("Clearing all sessions...")
        cursor.execute("DELETE FROM sessions")
        
        # Step 3: Create or update admin user
        logger.info("Creating/updating admin user...")
        
        # Generate password hash
        salt = secrets.token_hex(16)
        password = 'admin123'
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt.encode(), 
            100000
        ).hex()
        
        # Check if admin user exists
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        admin_user = cursor.fetchone()
        
        if admin_user:
            # Update existing admin
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
            ''', ('admin', 'admin@example.com', password_hash, salt, 'admin', 'Administrator', datetime.now().isoformat()))
            logger.info("Created new admin user")
        
        # Get admin user ID
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        admin_id = cursor.fetchone()[0]
        
        # Create client record for admin if it doesn't exist
        cursor.execute("SELECT id FROM clients WHERE user_id = ?", (admin_id,))
        admin_client = cursor.fetchone()
        
        if not admin_client:
            # Create client record for admin
            cursor.execute('''
            INSERT INTO clients (
                user_id,
                business_name,
                business_domain,
                contact_email,
                scanner_name,
                subscription_level,
                subscription_status,
                created_at,
                created_by,
                active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ''', (
                admin_id,
                'Admin Organization',
                'example.com',
                'admin@example.com',
                'Security Scanner',
                'enterprise',
                'active',
                datetime.now().isoformat(),
                admin_id
            ))
            logger.info("Created client record for admin user")
        
        # Commit changes
        conn.commit()
        conn.close()
        
        logger.info("Database fix completed successfully!")
        logger.info("You can now login with:")
        logger.info("Username: admin")
        logger.info("Password: admin123")
        
        return True
    except Exception as e:
        logger.error(f"Error fixing database: {e}")
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return False

if __name__ == "__main__":
    fix_database()
