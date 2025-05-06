#!/usr/bin/env python3
# repair_auth_system.py - Comprehensive repair for auth system

import os
import sqlite3
import secrets
import hashlib
import uuid
from datetime import datetime

# Database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def repair_auth_system():
    """Comprehensive repair of the authentication system"""
    results = []
    
    # Check if database exists
    results.append(f"Database path: {CLIENT_DB_PATH}")
    results.append(f"Database exists: {os.path.exists(CLIENT_DB_PATH)}")
    
    try:
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        table_names = [table['name'] for table in tables]
        results.append(f"Existing tables: {table_names}")
        
        # Create required tables if they don't exist
        if 'users' not in table_names:
            results.append("Creating users table...")
            cursor.execute('''
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
                active BOOLEAN DEFAULT 1
            )
            ''')
        
        if 'clients' not in table_names:
            results.append("Creating clients table...")
            cursor.execute('''
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
                active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (created_by) REFERENCES users(id),
                FOREIGN KEY (updated_by) REFERENCES users(id)
            )
            ''')
        
        if 'sessions' not in table_names:
            results.append("Creating sessions table...")
            cursor.execute('''
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
            ''')
        
        # Ensure clients table has user_id column
        if 'clients' in table_names:
            cursor.execute("PRAGMA table_info(clients)")
            columns = cursor.fetchall()
            column_names = [column[1] for column in columns]
            
            if 'user_id' not in column_names:
                results.append("Adding user_id column to clients table...")
                cursor.execute("ALTER TABLE clients ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE")
        
        # Create admin user if not exists
        cursor.execute("SELECT * FROM users WHERE username = 'admin'")
        admin_user = cursor.fetchone()
        
        if not admin_user:
            results.append("Creating admin user...")
            # Generate secure password
            password = 'admin123'
            salt = secrets.token_hex(16)
            password_hash = hashlib.pbkdf2_hmac(
                'sha256', 
                password.encode(), 
                salt.encode(), 
                100000
            ).hex()
            
            current_time = datetime.now().isoformat()
            
            cursor.execute('''
            INSERT INTO users (
                username, email, password_hash, salt, role, full_name, created_at, active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            ''', ('admin', 'admin@example.com', password_hash, salt, 'admin', 'System Administrator', current_time))
            
            admin_id = cursor.lastrowid
            results.append(f"Admin user created with ID: {admin_id}")
            results.append("Admin credentials: username='admin', password='admin123'")
            
            # Create client record for admin
            api_key = str(uuid.uuid4())
            cursor.execute('''
            INSERT INTO clients (
                user_id, business_name, business_domain, contact_email, 
                scanner_name, subscription_level, subscription_status, 
                subscription_start, api_key, created_at, created_by, active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ''', (
                admin_id, 'Admin Organization', 'example.com', 'admin@example.com',
                'Security Scanner', 'enterprise', 'active',
                current_time, api_key, current_time, admin_id
            ))
            results.append("Admin client record created")
        else:
            results.append(f"Admin user already exists (ID: {admin_user['id']})")
            
            # Make sure the admin has a client record
            cursor.execute("SELECT * FROM clients WHERE user_id = ?", (admin_user['id'],))
            admin_client = cursor.fetchone()
            
            if not admin_client:
                results.append("Creating client record for existing admin...")
                api_key = str(uuid.uuid4())
                current_time = datetime.now().isoformat()
                
                cursor.execute('''
                INSERT INTO clients (
                    user_id, business_name, business_domain, contact_email, 
                    scanner_name, subscription_level, subscription_status, 
                    subscription_start, api_key, created_at, created_by, active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ''', (
                    admin_user['id'], 'Admin Organization', 'example.com', admin_user['email'],
                    'Security Scanner', 'enterprise', 'active',
                    current_time, api_key, current_time, admin_user['id']
                ))
                results.append("Admin client record created")
            else:
                results.append(f"Admin client record already exists (ID: {admin_client['id']})")
        
        # Ensure user-client relationships
        cursor.execute("SELECT id, username, email, role FROM users")
        users = cursor.fetchall()
        
        for user in users:
            cursor.execute("SELECT * FROM clients WHERE user_id = ?", (user['id'],))
            client = cursor.fetchone()
            
            if not client:
                results.append(f"Creating client record for user {user['username']}...")
                api_key = str(uuid.uuid4())
                current_time = datetime.now().isoformat()
                
                cursor.execute('''
                INSERT INTO clients (
                    user_id, business_name, business_domain, contact_email, 
                    scanner_name, subscription_level, subscription_status, 
                    subscription_start, api_key, created_at, created_by, active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ''', (
                    user['id'], f"{user['username']}'s Business", "example.com", user['email'],
                    "Security Scanner", "basic", "active",
                    current_time, api_key, current_time, user['id']
                ))
                results.append(f"Client record created for user {user['username']}")
        
        # Clear any stuck sessions
        cursor.execute("DELETE FROM sessions")
        results.append("Cleared all sessions for a fresh start")
        
        # Commit changes
        conn.commit()
        conn.close()
        
        results.append("Auth system repair completed successfully!")
        results.append("-------------------------------------")
        results.append("You can now login with:")
        results.append("Username: admin")
        results.append("Password: admin123")
        
        return "\n".join(results)
    except Exception as e:
        if conn:
            conn.rollback()
            conn.close()
        return f"Error: {str(e)}"

if __name__ == "__main__":
    print(repair_auth_system())
