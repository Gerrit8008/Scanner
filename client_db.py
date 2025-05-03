# Enhanced client_db.py with better structure and relations

import os
import sqlite3
import json
import logging
import traceback
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

# Helper function for database transactions
def with_transaction(func):
    """Decorator for database transactions with proper error handling"""
    def wrapper(*args, **kwargs):
        conn = None
        try:
            conn = sqlite3.connect(CLIENT_DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            result = func(conn, cursor, *args, **kwargs)
            conn.commit()
            return result
        except Exception as e:
            if conn:
                conn.rollback()
            logging.error(f"Database error in {func.__name__}: {e}")
            logging.debug(traceback.format_exc())
            return {"status": "error", "message": str(e)}
        finally:
            if conn:
                conn.close()
    return wrapper

@with_transaction
def init_client_db(conn, cursor):
    """Initialize the database with required tables and indexes"""
    
    # Create users table with proper indices
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
    
    # Create an index for user lookups
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
    
    # Create clients table with foreign key constraints
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
        updated_at TEXT,
        updated_by INTEGER,
        active BOOLEAN DEFAULT 1,
        FOREIGN KEY (created_by) REFERENCES users(id),
        FOREIGN KEY (updated_by) REFERENCES users(id)
    )
    ''')
    
    # Create indices for client lookups
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clients_business_name ON clients(business_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clients_api_key ON clients(api_key)')
    
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
        email_footer TEXT,
        default_scans TEXT,
        css_override TEXT,
        html_override TEXT,
        last_updated TEXT,
        updated_by INTEGER,
        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
        FOREIGN KEY (updated_by) REFERENCES users(id)
    )
    ''')
    
    # Create deployed_scanners table
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
        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
    )
    ''')
    
    # Create scan_history table
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
        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
    )
    ''')
    
    # Create sessions table with proper indices
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
    
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token)')
    
    # Create audit_log table for tracking changes
    cursor.execute('''
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
    )
    ''')
    
    # Create admin user if it doesn't exist
    cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    admin = cursor.fetchone()
    
    if not admin:
        # Create salt and hash password with better security
        salt = secrets.token_hex(16)
        # Default password: admin123 (should be changed immediately)
        password = 'admin123'
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        
        cursor.execute('''
        INSERT INTO users (username, email, password_hash, salt, role, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', ('admin', 'admin@scannerplatform.com', password_hash, salt, 'admin', datetime.now().isoformat()))
        
        logging.info("Admin user created. Please change the default password.")
    
    logging.info(f"Client database initialized at {CLIENT_DB_PATH}")
    return {"status": "success"}

# Enhanced user management functions
@with_transaction
def create_user(conn, cursor, username, email, password, role='client', created_by=None):
    """Create a new user with enhanced validation and security"""
    # Validate input
    if not username or not email or not password:
        return {"status": "error", "message": "All fields are required"}
    
    if len(password) < 8:
        return {"status": "error", "message": "Password must be at least 8 characters"}
    
    # Check if username or email already exists
    cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
    existing_user = cursor.fetchone()
    
    if existing_user:
        return {"status": "error", "message": "Username or email already exists"}
    
    # Create salt and hash password (improved security)
    salt = secrets.token_hex(16)
    # Use stronger hashing with iterations
    password_hash = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode(), 
        salt.encode(), 
        100000  # More iterations for better security
    ).hex()
    
    # Insert the user
    cursor.execute('''
    INSERT INTO users (username, email, password_hash, salt, role, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (username, email, password_hash, salt, role, datetime.now().isoformat()))
    
    user_id = cursor.lastrowid
    
    # Log the action if created_by is provided
    if created_by:
        log_action(conn, cursor, created_by, 'create', 'user', user_id, 
                  {'username': username, 'email': email, 'role': role})
    
    return {"status": "success", "user_id": user_id}

# Improved authentication with better security
@with_transaction
def authenticate_user(conn, cursor, username_or_email, password, ip_address=None):
    """Authenticate user with improved security and session management"""
    # Find user by username or email
    cursor.execute('SELECT * FROM users WHERE username = ? OR email = ?', 
                  (username_or_email, username_or_email))
    user = cursor.fetchone()
    
    if not user:
        # Use constant time comparison to prevent timing attacks
        dummy_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), b'dummy', 100000).hex()
        secrets.compare_digest(dummy_hash, dummy_hash)  # Constant time comparison
        return {"status": "error", "message": "Invalid credentials"}
    
    # Check if user is active
    if not user['active']:
        return {"status": "error", "message": "Account is disabled"}
    
    # Verify password with the same algorithm used for storing
    password_hash = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode(), 
        user['salt'].encode(), 
        100000
    ).hex()
    
    if not secrets.compare_digest(password_hash, user['password_hash']):
        return {"status": "error", "message": "Invalid credentials"}
    
    # Create a more secure session token
    session_token = secrets.token_hex(32)
    # Set expiration to 24 hours from now
    expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
    
    # Store session with IP address
    cursor.execute('''
    INSERT INTO sessions (user_id, session_token, created_at, expires_at, ip_address)
    VALUES (?, ?, ?, ?, ?)
    ''', (user['id'], session_token, datetime.now().isoformat(), expires_at, ip_address))
    
    # Update last login
    cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', 
                  (datetime.now().isoformat(), user['id']))
    
    # Log the successful login
    log_action(conn, cursor, user['id'], 'login', 'user', user['id'], 
              {'ip_address': ip_address})
    
    return {
        "status": "success",
        "user_id": user['id'],
        "username": user['username'],
        "email": user['email'],
        "role": user['role'],
        "session_token": session_token
    }

# Enhanced client management functions
@with_transaction
def create_client(conn, cursor, client_data, user_id):
    """Create a new client with enhanced validation and audit logging"""
    # Validate required fields
    required_fields = ['business_name', 'business_domain', 'contact_email']
    for field in required_fields:
        if not client_data.get(field):
            return {"status": "error", "message": f"Missing required field: {field}"}
    
    # Generate API key
    api_key = str(uuid.uuid4())
    current_time = datetime.now().isoformat()
    
    # Insert client record
    cursor.execute('''
    INSERT INTO clients 
    (business_name, business_domain, contact_email, contact_phone, 
     scanner_name, subscription_level, subscription_status, subscription_start,
     api_key, created_at, created_by, updated_at, updated_by, active)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        client_data.get('business_name', ''),
        client_data.get('business_domain', ''),
        client_data.get('contact_email', ''),
        client_data.get('contact_phone', ''),
        client_data.get('scanner_name', ''),
        client_data.get('subscription', 'basic'),
        'active',
        current_time,
        api_key,
        current_time,
        user_id,
        current_time,
        user_id,
        1
    ))
    
    # Get the client ID
    client_id = cursor.lastrowid
    
    # Save customization data
    default_scans = json.dumps(client_data.get('default_scans', []))
    
    cursor.execute('''
    INSERT INTO customizations 
    (client_id, primary_color, secondary_color, logo_path, 
     favicon_path, email_subject, email_intro, default_scans, last_updated, updated_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        client_id,
        client_data.get('primary_color', '#FF6900'),
        client_data.get('secondary_color', '#808588'),
        client_data.get('logo_path', ''),
        client_data.get('favicon_path', ''),
        client_data.get('email_subject', 'Your Security Scan Report'),
        client_data.get('email_intro', 'Thank you for using our security scanner.'),
        default_scans,
        current_time,
        user_id
    ))
    
    # Create deployed scanner record with sanitized subdomain
    subdomain = client_data.get('business_name', '').lower()
    # Clean up subdomain to be URL-friendly
    subdomain = ''.join(c for c in subdomain if c.isalnum() or c == '-')
    # Remove consecutive dashes and ensure it doesn't start/end with a dash
    subdomain = '-'.join(filter(None, subdomain.split('-')))
    
    # Handle duplicates by appending client_id if needed
    cursor.execute('SELECT id FROM deployed_scanners WHERE subdomain = ?', (subdomain,))
    if cursor.fetchone():
        subdomain = f"{subdomain}-{client_id}"
    
    cursor.execute('''
    INSERT INTO deployed_scanners 
    (client_id, subdomain, deploy_status, deploy_date, last_updated, template_version)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        client_id,
        subdomain,
        'pending',
        current_time,
        current_time,
        '1.0'
    ))
    
    # Log the client creation
    log_action(conn, cursor, user_id, 'create', 'client', client_id, 
              {'business_name': client_data.get('business_name'), 
               'subscription': client_data.get('subscription', 'basic')})
    
    return {
        "status": "success",
        "client_id": client_id,
        "api_key": api_key,
        "subdomain": subdomain
    }

# Enhanced function to log actions for audit trail
def log_action(conn, cursor, user_id, action, entity_type, entity_id, changes=None, ip_address=None):
    """Log an action for the audit trail"""
    changes_json = json.dumps(changes) if changes else None
    
    cursor.execute('''
    INSERT INTO audit_log (user_id, action, entity_type, entity_id, changes, timestamp, ip_address)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        user_id, 
        action, 
        entity_type, 
        entity_id, 
        changes_json, 
        datetime.now().isoformat(),
        ip_address
    ))
    
    return cursor.lastrowid

# Add more enhanced client management functions here
# ...
