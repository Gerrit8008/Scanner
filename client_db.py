# client_db.py
import os
import sqlite3
import json
import logging
import traceback
from datetime import datetime

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def init_client_db():
    """Initialize the database with required tables for client customizations"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Create clients table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            business_name TEXT NOT NULL,
            business_domain TEXT NOT NULL,
            contact_email TEXT NOT NULL,
            contact_phone TEXT,
            scanner_name TEXT,
            subscription_level TEXT,
            api_key TEXT UNIQUE,
            created_at TEXT,
            active BOOLEAN DEFAULT 1
        )
        ''')
        
        # Create customizations table
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
            default_scans TEXT,
            css_override TEXT,
            FOREIGN KEY (client_id) REFERENCES clients(id)
        )
        ''')
        
        # Create scanners table to track deployed scanners
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS deployed_scanners (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            subdomain TEXT UNIQUE,
            domain TEXT,
            deploy_status TEXT,
            last_updated TEXT,
            FOREIGN KEY (client_id) REFERENCES clients(id)
        )
        ''')
        
        conn.commit()
        conn.close()
        logging.info(f"Client database initialized at {CLIENT_DB_PATH}")
        return True
    except Exception as e:
        logging.error(f"Client database initialization error: {e}")
        logging.debug(traceback.format_exc())
        return False

def save_client(client_data):
    """Save new client to database"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Generate API key
        import uuid
        api_key = str(uuid.uuid4())
        
        # Insert client record
        cursor.execute('''
        INSERT INTO clients 
        (business_name, business_domain, contact_email, contact_phone, 
         scanner_name, subscription_level, api_key, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            client_data.get('business_name', ''),
            client_data.get('business_domain', ''),
            client_data.get('contact_email', ''),
            client_data.get('contact_phone', ''),
            client_data.get('scanner_name', ''),
            client_data.get('subscription', 'basic'),
            api_key,
            datetime.now().isoformat()
        ))
        
        # Get the client ID
        client_id = cursor.lastrowid
        
        # Save customization data
        default_scans = json.dumps(client_data.get('default_scans', []))
        
        cursor.execute('''
        INSERT INTO customizations 
        (client_id, primary_color, secondary_color, logo_path, 
         favicon_path, email_subject, email_intro, default_scans)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            client_id,
            client_data.get('primary_color', '#FF6900'),
            client_data.get('secondary_color', '#808588'),
            client_data.get('logo_path', ''),
            client_data.get('favicon_path', ''),
            client_data.get('email_subject', 'Your Security Scan Report'),
            client_data.get('email_intro', 'Thank you for using our security scanner.'),
            default_scans
        ))
        
        # Create deployed scanner record
        subdomain = client_data.get('business_name', '').lower().replace(' ', '-')
        
        cursor.execute('''
        INSERT INTO deployed_scanners 
        (client_id, subdomain, deploy_status, last_updated)
        VALUES (?, ?, ?, ?)
        ''', (
            client_id,
            subdomain,
            'pending',
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        return {
            'client_id': client_id,
            'api_key': api_key,
            'subdomain': subdomain
        }
    except Exception as e:
        logging.error(f"Error saving client: {e}")
        logging.debug(traceback.format_exc())
        return None

def get_client_by_api_key(api_key):
    """Retrieve client by API key"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Query for the client
        cursor.execute('''
        SELECT c.*, cu.* 
        FROM clients c
        JOIN customizations cu ON c.id = cu.client_id
        WHERE c.api_key = ? AND c.active = 1
        ''', (api_key,))
        
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return None
        
        # Convert row to dictionary
        client_data = dict(row)
        
        # Parse the default_scans JSON field
        if 'default_scans' in client_data and client_data['default_scans']:
            client_data['default_scans'] = json.loads(client_data['default_scans'])
        
        conn.close()
        return client_data
    except Exception as e:
        logging.error(f"Error retrieving client by API key: {e}")
        logging.debug(traceback.format_exc())
        return None
