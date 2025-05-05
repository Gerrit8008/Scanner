#!/usr/bin/env python3
# recreate_database.py - Script to recreate client_scanner.db with all necessary tables

import os
import sqlite3
import logging
import traceback
from datetime import datetime
import secrets
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def recreate_database():
    """Recreate the database with required tables"""
    try:
        # Check if database file exists and remove it if it does
        if os.path.exists(CLIENT_DB_PATH):
            logging.warning(f"Existing database found at {CLIENT_DB_PATH}. Backing it up.")
            backup_path = f"{CLIENT_DB_PATH}.bak.{datetime.now().strftime('%Y%m%d%H%M%S')}"
            try:
                os.rename(CLIENT_DB_PATH, backup_path)
                logging.info(f"Backed up existing database to {backup_path}")
            except Exception as e:
                logging.warning(f"Could not backup database: {str(e)}")
                # Try to delete it instead
                try:
                    os.remove(CLIENT_DB_PATH)
                    logging.info(f"Deleted corrupted database file")
                except Exception as del_error:
                    logging.error(f"Failed to delete database: {str(del_error)}")
                    logging.error("You may need to manually delete the file")
                    return False
        
        # Create a new database connection
        logging.info(f"Creating new database file at {CLIENT_DB_PATH}")
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Create schema
        logging.info("Creating database schema")
        cursor.executescript('''
-- Users table for authentication and access control
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
);

-- Clients table to store basic client information
CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

-- Customizations table for branding and visual options
CREATE TABLE IF NOT EXISTS customizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    primary_color TEXT,
    secondary_color TEXT,
    logo_path TEXT,
    favicon_path TEXT,
    email_subject TEXT,
    email_intro TEXT,
    email_footer TEXT,
    default_scans TEXT,  -- JSON array of default scan types
    css_override TEXT,
    html_override TEXT,
    last_updated TEXT,
    updated_by INTEGER,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

-- Deployed scanners table to track scanner instances
CREATE TABLE IF NOT EXISTS deployed_scanners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    subdomain TEXT UNIQUE,
    domain TEXT,
    deploy_status TEXT,
    deploy_date TEXT,
    last_updated TEXT,
    config_path TEXT,
    template_version TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

-- Scan history table to track scanning activity
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    scan_id TEXT UNIQUE NOT NULL,
    timestamp TEXT,
    target TEXT,
    scan_type TEXT,
    status TEXT,
    report_path TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

-- Sessions table for user login sessions
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_token TEXT UNIQUE NOT NULL,
    created_at TEXT,
    expires_at TEXT,
    ip_address TEXT,
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Audit log table for tracking changes
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id INTEGER NOT NULL,
    changes TEXT,
    timestamp TEXT NOT NULL,
    ip_address TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Password reset tokens table
CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    reset_token TEXT UNIQUE NOT NULL,
    created_at TEXT,
    expires_at TEXT,
    used BOOLEAN DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Client billing table for subscriptions
CREATE TABLE IF NOT EXISTS client_billing (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    plan_id TEXT,
    billing_cycle TEXT,
    amount REAL,
    currency TEXT DEFAULT 'USD',
    start_date TEXT,
    next_billing_date TEXT,
    payment_method TEXT,
    status TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

-- Billing transactions table for payment history
CREATE TABLE IF NOT EXISTS billing_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    transaction_id TEXT UNIQUE,
    amount REAL,
    currency TEXT DEFAULT 'USD',
    payment_method TEXT,
    status TEXT,
    timestamp TEXT,
    notes TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

-- Migrations table for tracking applied migrations
CREATE TABLE IF NOT EXISTS migrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    applied_at TEXT NOT NULL
);

-- Create indices for better performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_clients_business_name ON clients(business_name);
CREATE INDEX IF NOT EXISTS idx_clients_api_key ON clients(api_key);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
        ''')
        
        # Create admin user
        logging.info("Creating admin user")
        salt = secrets.token_hex(16)
        password = 'admin123'
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt.encode(), 
            100000
        ).hex()
        
        cursor.execute('''
        INSERT INTO users (username, email, password_hash, salt, role, full_name, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', ('admin', 'admin@scannerplatform.com', password_hash, salt, 'admin', 'System Administrator', datetime.now().isoformat()))
        
        # Log the database initialization
        cursor.execute('''
        INSERT INTO migrations (name, applied_at)
        VALUES (?, ?)
        ''', ('001_initial_schema', datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        logging.info(f"Database recreated successfully at {CLIENT_DB_PATH}")
        logging.info("Admin user created with username 'admin' and password 'admin123'")
        logging.info("Please change the default admin password immediately!")
        
        # Verify the database to make sure it's working
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = 'admin'")
        admin_user = cursor.fetchone()
        conn.close()
        
        if admin_user:
            logging.info("Database verification successful!")
            return True
        else:
            logging.error("Database verification failed: Could not retrieve admin user")
            return False
            
    except Exception as e:
        logging.error(f"Error recreating database: {e}")
        logging.debug(traceback.format_exc())
        return False

if __name__ == "__main__":
    success = recreate_database()
    if success:
        print("Database recreated successfully!")
    else:
        print("Database recreation failed. Check the logs for details.")
