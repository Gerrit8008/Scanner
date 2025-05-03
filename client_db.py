# client_db.py
import os
import sqlite3
import json
import logging
import traceback
import uuid
import hashlib
import secrets
from datetime import datetime

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def get_client_by_subdomain(subdomain):
    """Retrieve client by subdomain"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Query for the client
        cursor.execute('''
        SELECT c.*, cu.*, ds.subdomain, ds.deploy_status
        FROM clients c
        JOIN customizations cu ON c.id = cu.client_id
        JOIN deployed_scanners ds ON c.id = ds.client_id
        WHERE ds.subdomain = ? AND c.active = 1
        ''', (subdomain,))
        
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return None
        
        # Convert row to dictionary
        client_data = dict(row)
        
        # Parse the default_scans JSON field
        if 'default_scans' in client_data and client_data['default_scans']:
            try:
                client_data['default_scans'] = json.loads(client_data['default_scans'])
            except json.JSONDecodeError:
                client_data['default_scans'] = []
        
        conn.close()
        return client_data
    except Exception as e:
        logging.error(f"Error retrieving client by subdomain: {e}")
        logging.debug(traceback.format_exc())
        return None
        
def update_deployment_status(client_id, status, config_path=None):
    """Update the deployment status for a client's scanner"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Update deployment record
        if config_path:
            cursor.execute('''
            UPDATE deployed_scanners
            SET deploy_status = ?, last_updated = ?, config_path = ?
            WHERE client_id = ?
            ''', (status, datetime.now().isoformat(), config_path, client_id))
        else:
            cursor.execute('''
            UPDATE deployed_scanners
            SET deploy_status = ?, last_updated = ?
            WHERE client_id = ?
            ''', (status, datetime.now().isoformat(), client_id))
        
        conn.commit()
        conn.close()
        
        return True
    except Exception as e:
        logging.error(f"Error updating deployment status: {e}")
        logging.debug(traceback.format_exc())
        return False
        
def init_client_db():
    """Initialize the database with required tables for client customizations and user management"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Create users table for authentication
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT DEFAULT 'client',
            created_at TEXT,
            last_login TEXT,
            active BOOLEAN DEFAULT 1
        )
        ''')
        
        # Create clients table (enhanced)
        cursor.execute('''
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
            active BOOLEAN DEFAULT 1,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
        ''')
        
        # Create customizations table (enhanced)
        cursor.execute('''
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
            default_scans TEXT,
            css_override TEXT,
            html_override TEXT,
            last_updated TEXT,
            updated_by INTEGER,
            FOREIGN KEY (client_id) REFERENCES clients(id),
            FOREIGN KEY (updated_by) REFERENCES users(id)
        )
        ''')
        
        # Create deployed_scanners table (enhanced)
        cursor.execute('''
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
            FOREIGN KEY (client_id) REFERENCES clients(id)
        )
        ''')
        
        # Create scan_history table for tracking client scans
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            scan_id TEXT UNIQUE NOT NULL,
            timestamp TEXT,
            target TEXT,
            scan_type TEXT,
            status TEXT,
            report_path TEXT,
            FOREIGN KEY (client_id) REFERENCES clients(id)
        )
        ''')
        
        # Create a session table for authentication
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            created_at TEXT,
            expires_at TEXT,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')
        
        # Create admin user if it doesn't exist
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        admin = cursor.fetchone()
        
        if not admin:
            # Create salt and hash password
            salt = secrets.token_hex(16)
            # Default password: admin123 (should be changed immediately)
            password = 'admin123'
            password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            
            cursor.execute('''
            INSERT INTO users (username, email, password_hash, salt, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', ('admin', 'admin@scannerplatform.com', password_hash, salt, 'admin', datetime.now().isoformat()))
            
            logging.info("Admin user created. Please change the default password.")
        
        conn.commit()
        conn.close()
        logging.info(f"Client database initialized at {CLIENT_DB_PATH}")
        return True
    except Exception as e:
        logging.error(f"Client database initialization error: {e}")
        logging.debug(traceback.format_exc())
        return False
