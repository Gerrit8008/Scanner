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
from migrations import run_migrations
run_migrations()

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

-- Clients table to store basic client information
CREATE TABLE clients (
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
CREATE TABLE customizations (
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
CREATE TABLE deployed_scanners (
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

# Add these functions to client_db.py

@with_transaction
def create_password_reset_token(conn, cursor, email):
    """Create a password reset token for the specified email"""
    # Find the user
    cursor.execute('SELECT id FROM users WHERE email = ? AND active = 1', (email,))
    user = cursor.fetchone()
    
    if not user:
        # Don't reveal whether the email exists or not (security)
        return {"status": "success", "message": "If the email exists, a reset link has been sent"}
    
    # Generate a secure token
    reset_token = secrets.token_urlsafe(32)
    user_id = user['id']
    
    # Set expiration to 24 hours from now
    expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
    
    # Clear any existing tokens for this user
    cursor.execute('UPDATE password_resets SET used = 1 WHERE user_id = ?', (user_id,))
    
    # Insert the new token
    cursor.execute('''
    INSERT INTO password_resets (user_id, reset_token, created_at, expires_at)
    VALUES (?, ?, ?, ?)
    ''', (user_id, reset_token, datetime.now().isoformat(), expires_at))
    
    # Log the action
    log_action(conn, cursor, user_id, 'request_password_reset', 'user', user_id, 
              {'reset_token_id': cursor.lastrowid})
    
    return {"status": "success", "user_id": user_id, "reset_token": reset_token}

@with_transaction
def verify_password_reset_token(conn, cursor, token):
    """Verify a password reset token"""
    # Find the token
    cursor.execute('''
    SELECT pr.*, u.username, u.email
    FROM password_resets pr
    JOIN users u ON pr.user_id = u.id
    WHERE pr.reset_token = ? AND pr.used = 0 AND pr.expires_at > ?
    ''', (token, datetime.now().isoformat()))
    
    reset = cursor.fetchone()
    
    if not reset:
        return {"status": "error", "message": "Invalid or expired token"}
    
    return {
        "status": "success", 
        "user_id": reset['user_id'],
        "username": reset['username'],
        "email": reset['email']
    }

@with_transaction
def update_user_password(conn, cursor, user_id, new_password):
    """Update a user's password with enhanced security"""
    # Validate password
    if len(new_password) < 8:
        return {"status": "error", "message": "Password must be at least 8 characters"}
    
    # Check if user exists
    cursor.execute('SELECT id FROM users WHERE id = ? AND active = 1', (user_id,))
    user = cursor.fetchone()
    
    if not user:
        return {"status": "error", "message": "User not found"}
    
    # Create salt and hash password (improved security)
    salt = secrets.token_hex(16)
    # Use stronger hashing with iterations
    password_hash = hashlib.pbkdf2_hmac(
        'sha256', 
        new_password.encode(), 
        salt.encode(), 
        100000  # More iterations for better security
    ).hex()
    
    # Update the user's password
    cursor.execute('''
    UPDATE users SET 
        password_hash = ?,
        salt = ?,
        updated_at = ?
    WHERE id = ?
    ''', (password_hash, salt, datetime.now().isoformat(), user_id))
    
    # Mark all reset tokens for this user as used
    cursor.execute('UPDATE password_resets SET used = 1 WHERE user_id = ?', (user_id,))
    
    # Log the password change
    log_action(conn, cursor, user_id, 'password_change', 'user', user_id, None)
    
    return {"status": "success"}

@with_transaction
def get_user_permissions(conn, cursor, role):
    """Get permissions for a specific role"""
    # Default permissions for all users
    default_permissions = ['view_profile', 'change_password']
    
    # Role-specific permissions
    role_permissions = {
        'admin': [
            'admin_dashboard',
            'manage_clients',
            'manage_users',
            'view_reports',
            'system_settings'
        ],
        'manager': [
            'admin_dashboard',
            'manage_clients',
            'view_reports'
        ],
        'client': [
            'client_dashboard',
            'view_own_reports'
        ]
    }
    
    # Combine default and role-specific permissions
    permissions = default_permissions.copy()
    if role in role_permissions:
        permissions.extend(role_permissions[role])
    
    return permissions

@with_transaction
def get_dashboard_summary(conn, cursor):
    """Get summary statistics for admin dashboard"""
    summary = {
        'clients': {
            'total': 0,
            'active': 0,
            'inactive': 0,
            'pending': 0,
            'new_this_month': 0
        },
        'subscriptions': {
            'basic': 0,
            'pro': 0,
            'enterprise': 0
        },
        'scans': {
            'total': 0,
            'this_month': 0,
            'yesterday': 0,
            'today': 0
        },
        'revenue': {
            'monthly': 0,
            'yearly': 0,
            'total': 0
        }
    }
    
    # Get total client count
    cursor.execute('SELECT COUNT(*) FROM clients')
    summary['clients']['total'] = cursor.fetchone()[0]
    
    # Get active client count
    cursor.execute('SELECT COUNT(*) FROM clients WHERE active = 1')
    summary['clients']['active'] = cursor.fetchone()[0]
    
    # Get inactive client count
    cursor.execute('SELECT COUNT(*) FROM clients WHERE active = 0')
    summary['clients']['inactive'] = cursor.fetchone()[0]
    
    # Get pending client count
    cursor.execute('''
    SELECT COUNT(*) FROM clients c
    JOIN deployed_scanners ds ON c.id = ds.client_id
    WHERE ds.deploy_status = 'pending' AND c.active = 1
    ''')
    summary['clients']['pending'] = cursor.fetchone()[0]
    
    # Get new clients this month
    current_month = datetime.now().strftime('%Y-%m')
    cursor.execute('''
    SELECT COUNT(*) FROM clients 
    WHERE created_at LIKE ? AND active = 1
    ''', (f'{current_month}%',))
    summary['clients']['new_this_month'] = cursor.fetchone()[0]
    
    # Get subscription counts
    subscription_levels = ['basic', 'pro', 'enterprise']
    for level in subscription_levels:
        cursor.execute('''
        SELECT COUNT(*) FROM clients 
        WHERE subscription_level = ? AND active = 1
        ''', (level,))
        summary['subscriptions'][level] = cursor.fetchone()[0]
    
    # Get scan counts
    cursor.execute('SELECT COUNT(*) FROM scan_history')
    summary['scans']['total'] = cursor.fetchone()[0]
    
    # Get scans this month
    cursor.execute('''
    SELECT COUNT(*) FROM scan_history 
    WHERE timestamp LIKE ?
    ''', (f'{current_month}%',))
    summary['scans']['this_month'] = cursor.fetchone()[0]
    
    # Get scans yesterday
    yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    cursor.execute('''
    SELECT COUNT(*) FROM scan_history 
    WHERE timestamp LIKE ?
    ''', (f'{yesterday}%',))
    summary['scans']['yesterday'] = cursor.fetchone()[0]
    
    # Get scans today
    today = datetime.now().strftime('%Y-%m-%d')
    cursor.execute('''
    SELECT COUNT(*) FROM scan_history 
    WHERE timestamp LIKE ?
    ''', (f'{today}%',))
    summary['scans']['today'] = cursor.fetchone()[0]
    
    # Get revenue info if billing is available
    try:
        # Monthly recurring revenue
        cursor.execute('''
        SELECT SUM(amount) FROM client_billing 
        WHERE status = 'active' AND billing_cycle = 'monthly'
        ''')
        result = cursor.fetchone()
        summary['revenue']['monthly'] = result[0] if result[0] is not None else 0
        
        # Yearly revenue (estimated)
        summary['revenue']['yearly'] = summary['revenue']['monthly'] * 12
        
        # Total revenue (all time)
        cursor.execute('SELECT SUM(amount) FROM billing_transactions WHERE status = "completed"')
        result = cursor.fetchone()
        summary['revenue']['total'] = result[0] if result[0] is not None else 0
    except:
        # Table might not exist yet
        pass
    
    return summary

# Client CRUD functions for client_db.py

def get_client_by_id(conn, cursor, client_id):
    """Get client details by ID"""
    cursor.execute('''
    SELECT c.*, cu.*, ds.subdomain, ds.deploy_status
    FROM clients c
    LEFT JOIN customizations cu ON c.id = cu.client_id
    LEFT JOIN deployed_scanners ds ON c.id = ds.client_id
    WHERE c.id = ?
    ''', (client_id,))
    
    row = cursor.fetchone()
    
    if not row:
        return None
    
    # Convert row to dict
    client = dict(row)
    
    # Convert default_scans JSON to list
    if client.get('default_scans'):
        try:
            client['default_scans'] = json.loads(client['default_scans'])
        except:
            client['default_scans'] = []
    
    return client

def get_client_by_api_key(conn, cursor, api_key):
    """Get client details by API key"""
    cursor.execute('''
    SELECT c.*, cu.*, ds.subdomain, ds.deploy_status
    FROM clients c
    LEFT JOIN customizations cu ON c.id = cu.client_id
    LEFT JOIN deployed_scanners ds ON c.id = ds.client_id
    WHERE c.api_key = ?
    ''', (api_key,))
    
    row = cursor.fetchone()
    
    if not row:
        return None
    
    # Convert row to dict
    client = dict(row)
    
    # Convert default_scans JSON to list
    if client.get('default_scans'):
        try:
            client['default_scans'] = json.loads(client['default_scans'])
        except:
            client['default_scans'] = []
    
    return client

def get_client_by_subdomain(conn, cursor, subdomain):
    """Get client details by subdomain"""
    cursor.execute('''
    SELECT c.*, cu.*, ds.subdomain, ds.deploy_status
    FROM clients c
    LEFT JOIN customizations cu ON c.id = cu.client_id
    LEFT JOIN deployed_scanners ds ON c.id = ds.client_id
    WHERE ds.subdomain = ?
    ''', (subdomain,))
    
    row = cursor.fetchone()
    
    if not row:
        return None
    
    # Convert row to dict
    client = dict(row)
    
    # Convert default_scans JSON to list
    if client.get('default_scans'):
        try:
            client['default_scans'] = json.loads(client['default_scans'])
        except:
            client['default_scans'] = []
    
    return client

def update_client(conn, cursor, client_id, client_data, user_id):
    """Update client information"""
    if not client_id:
        return {"status": "error", "message": "Client ID is required"}
    
    # Verify client exists
    cursor.execute('SELECT id FROM clients WHERE id = ?', (client_id,))
    if not cursor.fetchone():
        return {"status": "error", "message": "Client not found"}
    
    # Start with clients table updates
    client_fields = []
    client_values = []
    
    # Map fields to database columns for clients table
    field_mapping = {
        'business_name': 'business_name',
        'business_domain': 'business_domain',
        'contact_email': 'contact_email',
        'contact_phone': 'contact_phone',
        'scanner_name': 'scanner_name',
        'subscription_level': 'subscription_level',
        'subscription_status': 'subscription_status',
        'active': 'active'
    }
    
    for key, db_field in field_mapping.items():
        if key in client_data:
            client_fields.append(f"{db_field} = ?")
            client_values.append(client_data[key])
    
    # Always update the updated_at and updated_by fields
    client_fields.append("updated_at = ?")
    client_values.append(datetime.now().isoformat())
    client_fields.append("updated_by = ?")
    client_values.append(user_id)
    
    # Update clients table
    if client_fields:
        query = f'''
        UPDATE clients 
        SET {', '.join(client_fields)}
        WHERE id = ?
        '''
        client_values.append(client_id)
        cursor.execute(query, client_values)
    
    # Now handle customizations table
    custom_fields = []
    custom_values = []
    
    # Map fields to database columns for customizations table
    custom_mapping = {
        'primary_color': 'primary_color',
        'secondary_color': 'secondary_color',
        'logo_path': 'logo_path',
        'favicon_path': 'favicon_path',
        'email_subject': 'email_subject',
        'email_intro': 'email_intro',
        'email_footer': 'email_footer',
        'css_override': 'css_override',
        'html_override': 'html_override'
    }
    
    for key, db_field in custom_mapping.items():
        if key in client_data:
            custom_fields.append(f"{db_field} = ?")
            custom_values.append(client_data[key])
    
    # Handle default_scans separately as it needs to be JSON
    if 'default_scans' in client_data:
        custom_fields.append("default_scans = ?")
        custom_values.append(json.dumps(client_data['default_scans']))
    
    # Always update last_updated and updated_by
    custom_fields.append("last_updated = ?")
    custom_values.append(datetime.now().isoformat())
    custom_fields.append("updated_by = ?")
    custom_values.append(user_id)
    
    # Check if customization record exists
    cursor.execute('SELECT id FROM customizations WHERE client_id = ?', (client_id,))
    customization = cursor.fetchone()
    
    if customization and custom_fields:
        # Update existing record
        query = f'''
        UPDATE customizations 
        SET {', '.join(custom_fields)}
        WHERE client_id = ?
        '''
        custom_values.append(client_id)
        cursor.execute(query, custom_values)
    elif custom_fields:
        # Insert new record
        fields = [f for f, v in zip(custom_mapping.values(), custom_values) if f in custom_mapping.values()]
        fields.extend(['client_id', 'last_updated', 'updated_by'])
        
        values = custom_values
        values.append(client_id)
        values.append(datetime.now().isoformat())
        values.append(user_id)
        
        query = f'''
        INSERT INTO customizations 
        ({', '.join(fields)})
        VALUES ({', '.join(['?'] * len(fields))})
        '''
        cursor.execute(query, values)
    
    # Log the update
    log_action(conn, cursor, user_id, 'update', 'client', client_id, client_data)
    
    return {"status": "success", "client_id": client_id}

def delete_client(conn, cursor, client_id):
    """Delete a client and all associated data"""
    if not client_id:
        return {"status": "error", "message": "Client ID is required"}
    
    # Verify client exists
    cursor.execute('SELECT id FROM clients WHERE id = ?', (client_id,))
    if not cursor.fetchone():
        return {"status": "error", "message": "Client not found"}
    
    # Get scanner information to clean up files
    cursor.execute('''
    SELECT cu.logo_path, cu.favicon_path, ds.config_path
    FROM clients c
    LEFT JOIN customizations cu ON c.id = cu.client_id
    LEFT JOIN deployed_scanners ds ON c.id = ds.client_id
    WHERE c.id = ?
    ''', (client_id,))
    
    files = cursor.fetchone()
    
    # Delete client and related records (cascading deletes will handle the rest)
    cursor.execute('DELETE FROM clients WHERE id = ?', (client_id,))
    
    # Clean up files if they exist
    if files:
        for file_path in [files['logo_path'], files['favicon_path'], files['config_path']]:
            if file_path and os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except:
                    pass
    
    return {"status": "success"}

def list_clients(conn, cursor, page=1, per_page=10, filters=None):
    """List clients with pagination and filtering"""
    offset = (page - 1) * per_page
    
    # Base query
    query = '''
    SELECT c.*, cu.primary_color, cu.logo_path, ds.subdomain, ds.deploy_status,
           (SELECT COUNT(*) FROM scan_history WHERE client_id = c.id) as scan_count
    FROM clients c
    LEFT JOIN customizations cu ON c.id = cu.client_id
    LEFT JOIN deployed_scanners ds ON c.id = ds.client_id
    '''
    
    # Apply filters
    params = []
    where_clauses = []
    
    if filters:
        if 'subscription' in filters and filters['subscription']:
            where_clauses.append('c.subscription_level = ?')
            params.append(filters['subscription'])
        
        if 'status' in filters and filters['status']:
            if filters['status'] == 'active':
                where_clauses.append('c.active = 1')
            elif filters['status'] == 'inactive':
                where_clauses.append('c.active = 0')
            elif filters['status'] == 'pending':
                where_clauses.append('ds.deploy_status = "pending"')
        
        if 'search' in filters and filters['search']:
            search_term = f"%{filters['search']}%"
            where_clauses.append('(c.business_name LIKE ? OR c.contact_email LIKE ? OR c.business_domain LIKE ?)')
            params.extend([search_term, search_term, search_term])
    
    # Add WHERE clause if we have filters
    if where_clauses:
        query += f" WHERE {' AND '.join(where_clauses)}"
    
    # Add ORDER BY and LIMIT
    query += " ORDER BY c.id DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])
    
    # Execute query
    cursor.execute(query, params)
    clients = [dict(row) for row in cursor.fetchall()]
    
    # Get total count for pagination
    count_query = '''
    SELECT COUNT(*) FROM clients c
    '''
    
    if where_clauses:
        count_query += f" WHERE {' AND '.join(where_clauses)}"
    
    cursor.execute(count_query, params[:-2] if params else [])
    total_count = cursor.fetchone()[0]
    
    # Calculate pagination info
    total_pages = (total_count + per_page - 1) // per_page
    
    return {
        "status": "success",
        "clients": clients,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "total_count": total_count
        }
    }

def regenerate_api_key(conn, cursor, client_id):
    """Regenerate the API key for a client"""
    if not client_id:
        return {"status": "error", "message": "Client ID is required"}
    
    # Verify client exists
    cursor.execute('SELECT id FROM clients WHERE id = ?', (client_id,))
    if not cursor.fetchone():
        return {"status": "error", "message": "Client not found"}
    
    # Generate new API key
    new_api_key = str(uuid.uuid4())
    
    # Update client record
    cursor.execute('''
    UPDATE clients 
    SET api_key = ?
    WHERE id = ?
    ''', (new_api_key, client_id))
    
    return {"status": "success", "api_key": new_api_key}

def log_scan(conn, cursor, client_id, scan_id, target, scan_type="standard"):
    """Log a scan for a client"""
    if not client_id or not scan_id:
        return {"status": "error", "message": "Client ID and Scan ID are required"}
    
    # Insert scan record
    cursor.execute('''
    INSERT INTO scan_history (client_id, scan_id, timestamp, target, scan_type, status)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (client_id, scan_id, datetime.now().isoformat(), target, scan_type, "completed"))
    
    return {"status": "success"}

def update_deployment_status(conn, cursor, client_id, status, config_path=None):
    """Update the deployment status for a client scanner"""
    if not client_id:
        return {"status": "error", "message": "Client ID is required"}
    
    # Check if deployment record exists
    cursor.execute('SELECT id FROM deployed_scanners WHERE client_id = ?', (client_id,))
    deployment = cursor.fetchone()
    
    now = datetime.now().isoformat()
    
    if deployment:
        # Update existing record
        query = '''
        UPDATE deployed_scanners 
        SET deploy_status = ?, last_updated = ?
        '''
        params = [status, now]
        
        if config_path:
            query += ", config_path = ?"
            params.append(config_path)
        
        query += " WHERE client_id = ?"
        params.append(client_id)
        
        cursor.execute(query, params)
    else:
        # Get client name for subdomain
        cursor.execute('SELECT business_name FROM clients WHERE id = ?', (client_id,))
        client = cursor.fetchone()
        
        if not client:
            return {"status": "error", "message": "Client not found"}
        
        # Create a subdomain from business name
        subdomain = client['business_name'].lower()
        subdomain = ''.join(c for c in subdomain if c.isalnum() or c == '-')
        subdomain = '-'.join(filter(None, subdomain.split('-')))
        
        # Handle duplicates by appending client_id if needed
        cursor.execute('SELECT id FROM deployed_scanners WHERE subdomain = ?', (subdomain,))
        if cursor.fetchone():
            subdomain = f"{subdomain}-{client_id}"
        
        # Insert new record
        query = '''
        INSERT INTO deployed_scanners 
        (client_id, subdomain, deploy_status, deploy_date, last_updated, config_path, template_version)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        '''
        
        cursor.execute(query, (
            client_id,
            subdomain,
            status,
            now,
            now,
            config_path,
            "1.0"
        ))
    
    return {"status": "success"}
    
# Add more enhanced client management functions here
# ...
