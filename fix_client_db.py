#!/usr/bin/env python3
# fix_client_db.py - Fix the client-user relationship in the database

import os
import sqlite3
import uuid
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def fix_client_user_relationship():
    """Fix the relationship between users and clients"""
    results = []
    try:
        # Connect to the database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check if the database file exists
        results.append(f"Working with database at: {CLIENT_DB_PATH}")
        results.append(f"Database exists: {os.path.exists(CLIENT_DB_PATH)}")
        
        # Check database structure
        results.append("Checking database tables...")
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        results.append(f"Found tables: {[table[0] for table in tables]}")
        
        # Check if clients table exists
        clients_table_exists = 'clients' in [table[0] for table in tables]
        if not clients_table_exists:
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
            results.append("Clients table created!")
        else:
            # Check if user_id column exists in clients table
            cursor.execute("PRAGMA table_info(clients)")
            columns = cursor.fetchall()
            column_names = [column[1] for column in columns]
            
            if 'user_id' not in column_names:
                results.append("Adding user_id column to clients table...")
                cursor.execute("ALTER TABLE clients ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE")
                results.append("user_id column added successfully!")
        
        # Get all users
        cursor.execute("SELECT id, username, email, role FROM users")
        users = cursor.fetchall()
        results.append(f"Found {len(users)} users")
        
        # Create client records for each user
        for user in users:
            cursor.execute("SELECT * FROM clients WHERE user_id = ?", (user['id'],))
            client = cursor.fetchone()
            
            if not client:
                results.append(f"Creating client record for user {user['username']}...")
                # Generate API key
                api_key = str(uuid.uuid4())
                current_time = datetime.now().isoformat()
                
                # Default business name is the username
                business_name = f"{user['username'].capitalize()}'s Business"
                business_domain = "example.com"
                contact_email = user['email']
                
                # Set subscription level based on role
                subscription_level = 'enterprise' if user['role'] == 'admin' else 'basic'
                
                cursor.execute('''
                INSERT INTO clients (
                    user_id, 
                    business_name, 
                    business_domain, 
                    contact_email, 
                    scanner_name, 
                    subscription_level, 
                    subscription_status, 
                    subscription_start, 
                    api_key, 
                    created_at, 
                    created_by, 
                    active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ''', (
                    user['id'],
                    business_name,
                    business_domain,
                    contact_email,
                    "Security Scanner",
                    subscription_level,
                    "active",
                    current_time,
                    api_key,
                    current_time,
                    user['id']
                ))
                results.append(f"Client record created for user {user['username']}")
            else:
                # Make sure user_id is set correctly
                if client.get('user_id') != user['id']:
                    cursor.execute("UPDATE clients SET user_id = ? WHERE id = ?", (user['id'], client['id']))
                    results.append(f"Updated user_id for client {client['id']}")
                else:
                    results.append(f"Client record already exists for user {user['username']}")
        
        # Verify client records
        cursor.execute("SELECT id, user_id, business_name FROM clients")
        clients = cursor.fetchall()
        results.append(f"Found {len(clients)} client records")
        for client in clients:
            results.append(f"Client ID: {client['id']}, User ID: {client['user_id']}, Name: {client['business_name']}")
        
        # Commit all changes
        conn.commit()
        conn.close()
        
        results.append("Database fix completed! You should now be able to log in.")
        
        return "\n".join(results)
    except Exception as e:
        results.append(f"Error: {str(e)}")
        return "\n".join(results)

if __name__ == "__main__":
    print(fix_client_user_relationship())
