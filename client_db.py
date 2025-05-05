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
from functools import wraps

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("scanner_platform.log"),
        logging.StreamHandler()
    ]
)

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

# Create the schema string for initialization
SCHEMA_SQL = """
-- Users table for authentication and access control
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

-- Create indices for better performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_clients_business_name ON clients(business_name);
CREATE INDEX IF NOT EXISTS idx_clients_api_key ON clients(api_key);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
"""

def get_client_by_user_id(user_id):
    """Get client details by user ID"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Query to get client by user_id
        cursor.execute('''
            SELECT * FROM clients
            WHERE user_id = ?
        ''', (user_id,))
        
        client = cursor.fetchone()
        conn.close()
        
        if client:
            return dict(client)
        else:
            return None
    except Exception as e:
        logging.error(f"Error retrieving client by user ID: {e}")
        return None
        
# Helper function for database transactions
def with_transaction(func):
    """Decorator for database transactions with proper error handling"""
    @wraps(func)
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

def get_deployed_scanners_by_client_id(client_id, page=1, per_page=10, filters=None):
    """Get list of deployed scanners for a client with pagination and filtering"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Calculate offset for pagination
        offset = (page - 1) * per_page
        
        # Base query
        query = "SELECT * FROM scanners WHERE client_id = ?"
        params = [client_id]
        
        # Apply filters if provided
        if filters:
            if 'status' in filters and filters['status']:
                query += " AND status = ?"
                params.append(filters['status'])
            
            if 'search' in filters and filters['search']:
                query += " AND (name LIKE ? OR description LIKE ?)"
                search_term = f"%{filters['search']}%"
                params.append(search_term)
                params.append(search_term)
        
        # Add sorting and pagination
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.append(per_page)
        params.append(offset)
        
        # Execute query for scanners
        cursor.execute(query, params)
        scanners = [dict(row) for row in cursor.fetchall()]
        
        # Get total count for pagination
        count_query = "SELECT COUNT(*) FROM scanners WHERE client_id = ?"
        count_params = [client_id]
        
        # Apply the same filters to count query
        if filters:
            if 'status' in filters and filters['status']:
                count_query += " AND status = ?"
                count_params.append(filters['status'])
            
            if 'search' in filters and filters['search']:
                count_query += " AND (name LIKE ? OR description LIKE ?)"
                search_term = f"%{filters['search']}%"
                count_params.append(search_term)
                count_params.append(search_term)
        
        cursor.execute(count_query, count_params)
        total_count = cursor.fetchone()[0]
        
        conn.close()
        
        # Calculate pagination metadata
        total_pages = (total_count + per_page - 1) // per_page  # Ceiling division
        
        return {
            'scanners': scanners,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total_count': total_count,
                'total_pages': total_pages
            }
        }
    except Exception as e:
        logging.error(f"Error retrieving scanners for client: {e}")
        return {
            'scanners': [],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total_count': 0,
                'total_pages': 0
            }
        }

def get_scan_history_by_client_id(client_id, limit=None):
    """Get scan history for a client"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Base query
        query = "SELECT * FROM scans WHERE client_id = ? ORDER BY timestamp DESC"
        params = [client_id]
        
        # Add limit if provided
        if limit:
            query += " LIMIT ?"
            params.append(limit)
        
        cursor.execute(query, params)
        scan_history = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return scan_history
    except Exception as e:
        logging.error(f"Error retrieving scan history for client: {e}")
        return []

def get_scanner_by_id(scanner_id):
    """Get scanner details by ID"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM scanners
            WHERE id = ?
        ''', (scanner_id,))
        
        scanner = cursor.fetchone()
        conn.close()
        
        if scanner:
            return dict(scanner)
        else:
            return None
    except Exception as e:
        logging.error(f"Error retrieving scanner by ID: {e}")
        return None

def log_scan(client_id, scan_id=None, target=None, scan_type='standard'):
    """Log a scan to the database"""
    try:
        if not scan_id:
            scan_id = str(uuid.uuid4())
            
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Get current timestamp
        timestamp = datetime.datetime.now().isoformat()
        
        # Insert scan record
        cursor.execute('''
            INSERT INTO scans (
                scan_id, client_id, timestamp, target, scan_type
            ) VALUES (?, ?, ?, ?, ?)
        ''', (scan_id, client_id, timestamp, target, scan_type))
        
        conn.commit()
        conn.close()
        
        return {
            'status': 'success',
            'scan_id': scan_id
        }
    except Exception as e:
        logging.error(f"Error logging scan: {e}")
        return {
            'status': 'error',
            'message': f"Failed to log scan: {str(e)}"
        }

def regenerate_api_key(client_id):
    """Regenerate API key for a client"""
    try:
        # Generate a new API key
        new_api_key = str(uuid.uuid4())
        
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Update client record with new API key
        cursor.execute('''
            UPDATE clients
            SET api_key = ?
            WHERE id = ?
        ''', (new_api_key, client_id))
        
        # Check if update was successful
        if cursor.rowcount == 0:
            conn.close()
            return {
                'status': 'error',
                'message': 'Client not found'
            }
        
        conn.commit()
        conn.close()
        
        return {
            'status': 'success',
            'message': 'API key regenerated successfully',
            'api_key': new_api_key
        }
    except Exception as e:
        logging.error(f"Error regenerating API key: {e}")
        return {
            'status': 'error',
            'message': f"Failed to regenerate API key: {str(e)}"
        }

@with_transaction
def init_client_db(conn, cursor):
    """Initialize the database with required tables and indexes"""
    try:
        # Execute the schema SQL to create tables and indices
        cursor.executescript(SCHEMA_SQL)
        logging.info("Database schema initialized successfully.")
        
        # Create admin user if it doesn't exist
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        admin = cursor.fetchone()
        
        if not admin:
            # Create salt and hash password with better security
            salt = secrets.token_hex(16)
            password = 'admin123'  # Default password (should be changed immediately)
            password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            
            cursor.execute('''
            INSERT INTO users (username, email, password_hash, salt, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', ('admin', 'admin@scannerplatform.com', password_hash, salt, 'admin', datetime.now().isoformat()))
            
            logging.info("Admin user created. Please change the default password.")
    except sqlite3.DatabaseError as e:
        logging.error(f"Database error during initialization: {e}")
        raise

# Run database initialization
def init_db():
    try:
        # Run the normal database initialization
        result = init_client_db()
        if result and isinstance(result, dict) and result.get("status") == "success":
            logging.info("Database initialized successfully")
        else:
            # Init may have worked but returned None
            logging.info("Database initialization completed")
        
        # Now check for and add the full_name column if needed
        ensure_full_name_column()
        
        return True
    except Exception as e:
        logging.error(f"Error initializing database: {e}")
        logging.debug(traceback.format_exc())
        return False

def ensure_full_name_column():
    """Ensure the full_name column exists in the users table"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Check if the full_name column exists
        cursor.execute("PRAGMA table_info(users)")
        columns = cursor.fetchall()
        column_names = [column[1] for column in columns]
        
        if 'full_name' not in column_names:
            logging.info("Adding 'full_name' column to users table...")
            cursor.execute("ALTER TABLE users ADD COLUMN full_name TEXT")
            conn.commit()
            logging.info("'full_name' column added successfully")
        else:
            logging.info("'full_name' column already exists in users table")
        
        conn.close()
        return True
    except Exception as e:
        logging.error(f"Error ensuring full_name column: {e}")
        logging.debug(traceback.format_exc())
        return False
        
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

@with_transaction
def get_deployed_scanners(conn, cursor, page=1, per_page=10, filters=None):
    """Get list of deployed scanners with pagination and filtering"""
    offset = (page - 1) * per_page
    
    # Start with base query
    query = '''
    SELECT ds.*, c.business_name, c.business_domain, c.scanner_name, c.created_at, c.active
    FROM deployed_scanners ds
    JOIN clients c ON ds.client_id = c.id
    '''
    
    # Add filter conditions if provided
    params = []
    where_clauses = []
    
    if filters:
        if 'status' in filters and filters['status']:
            where_clauses.append('ds.deploy_status = ?')
            params.append(filters['status'])
        
        if 'search' in filters and filters['search']:
            search_term = f"%{filters['search']}%"
            where_clauses.append('(c.business_name LIKE ? OR c.business_domain LIKE ? OR ds.subdomain LIKE ?)')
            params.extend([search_term, search_term, search_term])
    
    # Construct WHERE clause if needed
    if where_clauses:
        query += ' WHERE ' + ' AND '.join(where_clauses)
    
    # Add order by and pagination
    query += ' ORDER BY ds.id DESC LIMIT ? OFFSET ?'
    params.extend([per_page, offset])
    
    # Execute query
    cursor.execute(query, params)
    scanners = [dict(row) for row in cursor.fetchall()]
    
    # Count total records for pagination
    count_query = 'SELECT COUNT(*) FROM deployed_scanners ds JOIN clients c ON ds.client_id = c.id'
    if where_clauses:
        count_query += ' WHERE ' + ' AND '.join(where_clauses)
    
    # Remove pagination params and execute count query
    cursor.execute(count_query, params[:-2] if params else [])
    total_count = cursor.fetchone()[0]
    
    # Calculate pagination info
    total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1
    
    return {
        "status": "success",
        "scanners": scanners,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "total_count": total_count
        }
    }

@with_transaction
def get_scanner_by_id(conn, cursor, scanner_id):
    """Get scanner details by ID"""
    cursor.execute('''
    SELECT ds.*, c.business_name, c.business_domain, c.scanner_name, c.contact_email,
           c.api_key, c.active, cu.primary_color, cu.secondary_color, cu.logo_path,
           cu.favicon_path, cu.email_subject, cu.email_intro, cu.default_scans
    FROM deployed_scanners ds
    JOIN clients c ON ds.client_id = c.id
    LEFT JOIN customizations cu ON c.id = cu.client_id
    WHERE ds.id = ?
    ''', (scanner_id,))
    
    row = cursor.fetchone()
    
    if not row:
        return None
    
    # Convert row to dict
    scanner = dict(row)
    
    # Convert default_scans JSON to list
    if scanner.get('default_scans'):
        try:
            scanner['default_scans'] = json.loads(scanner['default_scans'])
        except:
            scanner['default_scans'] = []
    
    return scanner

@with_transaction
def update_scanner_config(conn, cursor, scanner_id, scanner_data, user_id):
    """Update scanner configuration"""
    # Get scanner details
    cursor.execute('SELECT client_id FROM deployed_scanners WHERE id = ?', (scanner_id,))
    row = cursor.fetchone()
    
    if not row:
        return {"status": "error", "message": "Scanner not found"}
    
    client_id = row['client_id']
    
    # Update client table if scanner_name is provided
    if 'scanner_name' in scanner_data and scanner_data['scanner_name']:
        cursor.execute('''
        UPDATE clients
        SET scanner_name = ?, updated_at = ?, updated_by = ?
        WHERE id = ?
        ''', (scanner_data['scanner_name'], datetime.now().isoformat(), user_id, client_id))
    
    # Update customizations table
    custom_fields = []
    custom_values = []
    
    # Map fields to database columns for customizations table
    custom_mapping = {
        'primary_color': 'primary_color',
        'secondary_color': 'secondary_color',
        'logo_path': 'logo_path',
        'favicon_path': 'favicon_path',
        'email_subject': 'email_subject',
        'email_intro': 'email_intro'
    }
    
    for key, db_field in custom_mapping.items():
        if key in scanner_data:
            custom_fields.append(f"{db_field} = ?")
            custom_values.append(scanner_data[key])
    
    # Handle default_scans separately as it needs to be JSON
    if 'default_scans' in scanner_data:
        custom_fields.append("default_scans = ?")
        custom_values.append(json.dumps(scanner_data['default_scans']))
    
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
        fields = [db_field for key, db_field in custom_mapping.items() if key in scanner_data]
        if 'default_scans' in scanner_data:
            fields.append('default_scans')
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
    
    # Update deployed_scanners table
    cursor.execute('''
    UPDATE deployed_scanners
    SET last_updated = ?
    WHERE id = ?
    ''', (datetime.now().isoformat(), scanner_id))
    
    # Update scanner files
    from scanner_template import update_scanner
    update_scanner(client_id, scanner_data)
    
    # Log the update
    log_action(conn, cursor, user_id, 'update', 'scanner', scanner_id, scanner_data)
    
    return {"status": "success", "scanner_id": scanner_id}

@with_transaction
def update_scanner_status(conn, cursor, scanner_id, status, user_id):
    """Update scanner status"""
    # Get scanner details
    cursor.execute('SELECT client_id FROM deployed_scanners WHERE id = ?', (scanner_id,))
    row = cursor.fetchone()
    
    if not row:
        return {"status": "error", "message": "Scanner not found"}
    
    client_id = row['client_id']
    
    # Update status
    cursor.execute('''
    UPDATE deployed_scanners
    SET deploy_status = ?, last_updated = ?
    WHERE id = ?
    ''', (status, datetime.now().isoformat(), scanner_id))
    
    # Also update client active status if needed
    if status == 'inactive':
        cursor.execute('''
        UPDATE clients
        SET active = 0, updated_at = ?, updated_by = ?
        WHERE id = ?
        ''', (datetime.now().isoformat(), user_id, client_id))
    elif status == 'deployed':
        cursor.execute('''
        UPDATE clients
        SET active = 1, updated_at = ?, updated_by = ?
        WHERE id = ?
        ''', (datetime.now().isoformat(), user_id, client_id))
    
    # Log the action
    log_action(conn, cursor, user_id, 'update_status', 'scanner', scanner_id, {'status': status})
    
    return {"status": "success"}

@with_transaction
def regenerate_scanner_api_key(conn, cursor, scanner_id, user_id):
    """Regenerate API key for a scanner"""
    # Get scanner details
    cursor.execute('SELECT client_id FROM deployed_scanners WHERE id = ?', (scanner_id,))
    row = cursor.fetchone()
    
    if not row:
        return {"status": "error", "message": "Scanner not found"}
    
    client_id = row['client_id']
    
    # Use existing regenerate_api_key function
    result = regenerate_api_key(client_id)
    
    if result['status'] == 'success':
        # Log the action
        log_action(conn, cursor, user_id, 'regenerate_api_key', 'scanner', scanner_id, None)
    
    return result

@with_transaction
def get_scanner_scan_history(conn, cursor, scanner_id, limit=100):
    """Get scan history for a specific scanner"""
    # Get client_id from scanner_id
    cursor.execute('SELECT client_id FROM deployed_scanners WHERE id = ?', (scanner_id,))
    row = cursor.fetchone()
    
    if not row:
        return []
    
    client_id = row['client_id']
    
    # Get scan history for this client
    cursor.execute('''
    SELECT * FROM scan_history
    WHERE client_id = ?
    ORDER BY timestamp DESC
    LIMIT ?
    ''', (client_id, limit))
    
    scans = [dict(row) for row in cursor.fetchall()]
    
    return scans

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

@with_transaction
def verify_session(conn, cursor, session_token):
    """Verify a session token and return user information"""
    # Check if session exists and is valid
    cursor.execute('''
    SELECT s.*, u.username, u.email, u.role
    FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.session_token = ? AND s.expires_at > ? AND u.active = 1
    ''', (session_token, datetime.now().isoformat()))
    
    session = cursor.fetchone()
    
    if not session:
        return {"status": "error", "message": "Invalid or expired session"}
    
    # Return user info
    return {
        "status": "success",
        "user": {
            "user_id": session['user_id'],
            "username": session['username'],
            "email": session['email'],
            "role": session['role']
        }
    }

@with_transaction
def logout_user(conn, cursor, session_token):
    """Logout a user by invalidating their session"""
    # Delete the session
    cursor.execute('DELETE FROM sessions WHERE session_token = ?', (session_token,))
    
    return {"status": "success"}

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
@with_transaction
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

@with_transaction
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

@with_transaction
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

@with_transaction
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

@with_transaction
def list_users(conn, cursor, page=1, per_page=10):
    """List users with pagination"""
    offset = (page - 1) * per_page
    
    # Get users with pagination
    cursor.execute('''
    SELECT id, username, email, role, created_at, last_login, active
    FROM users
    ORDER BY id DESC
    LIMIT ? OFFSET ?
    ''', (per_page, offset))
    
    users = [dict(row) for row in cursor.fetchall()]
    
    # Get total count for pagination
    cursor.execute('SELECT COUNT(*) FROM users')
    total_count = cursor.fetchone()[0]
    
    # Calculate pagination info
    total_pages = (total_count + per_page - 1) // per_page
    
    return {
        "status": "success",
        "users": users,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "total_count": total_count
        }
    }

@with_transaction
def get_user_by_id(conn, cursor, user_id):
    """Get user by ID"""
    cursor.execute('''
    SELECT id, username, email, role, created_at, last_login, active
    FROM users
    WHERE id = ?
    ''', (user_id,))
    
    row = cursor.fetchone()
    
    if not row:
        return None
    
    return dict(row)

@with_transaction
def get_scan_history(conn, cursor, client_id, page=1, per_page=10):
    """Get scan history for a client"""
    offset = (page - 1) * per_page
    
    # Get scans with pagination
    cursor.execute('''
    SELECT id, scan_id, timestamp, target, scan_type, status, report_path
    FROM scan_history
    WHERE client_id = ?
    ORDER BY timestamp DESC
    LIMIT ? OFFSET ?
    ''', (client_id, per_page, offset))
    
    scans = [dict(row) for row in cursor.fetchall()]
    
    # Get total count for pagination
    cursor.execute('SELECT COUNT(*) FROM scan_history WHERE client_id = ?', (client_id,))
    total_count = cursor.fetchone()[0]
    
    # Calculate pagination info
    total_pages = (total_count + per_page - 1) // per_page
    
    return {
        "status": "success",
        "scans": scans,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "total_count": total_count
        }
    }

@with_transaction
def get_scan_by_id(conn, cursor, scan_id):
    """Get scan details by ID"""
    cursor.execute('''
    SELECT sh.*, c.business_name, c.business_domain
    FROM scan_history sh
    JOIN clients c ON sh.client_id = c.id
    WHERE sh.scan_id = ?
    ''', (scan_id,))
    
    row = cursor.fetchone()
    
    if not row:
        return None
    
    return dict(row)

@with_transaction
def update_scan_status(conn, cursor, scan_id, status, report_path=None):
    """Update the status of a scan"""
    if not scan_id:
        return {"status": "error", "message": "Scan ID is required"}
    
    # Create update query
    query = "UPDATE scan_history SET status = ?"
    params = [status]
    
    if report_path:
        query += ", report_path = ?"
        params.append(report_path)
    
    query += " WHERE scan_id = ?"
    params.append(scan_id)
    
    # Execute update
    cursor.execute(query, params)
    
    if cursor.rowcount == 0:
        return {"status": "error", "message": "Scan not found"}
    
    return {"status": "success"}

@with_transaction
def create_billing_record(conn, cursor, client_id, plan_data):
    """Create a billing record for a client"""
    if not client_id:
        return {"status": "error", "message": "Client ID is required"}
    
    # Validate required fields
    required_fields = ['plan_id', 'billing_cycle', 'amount']
    for field in required_fields:
        if not field in plan_data:
            return {"status": "error", "message": f"Missing required field: {field}"}
    
    # Check if client exists
    cursor.execute('SELECT id FROM clients WHERE id = ?', (client_id,))
    if not cursor.fetchone():
        return {"status": "error", "message": "Client not found"}
    
    # Calculate next billing date based on billing cycle
    start_date = datetime.now().isoformat()
    if plan_data['billing_cycle'] == 'monthly':
        next_billing_date = (datetime.now() + timedelta(days=30)).isoformat()
    elif plan_data['billing_cycle'] == 'quarterly':
        next_billing_date = (datetime.now() + timedelta(days=90)).isoformat()
    elif plan_data['billing_cycle'] == 'yearly':
        next_billing_date = (datetime.now() + timedelta(days=365)).isoformat()
    else:
        return {"status": "error", "message": "Invalid billing cycle"}
    
    # Insert billing record
    cursor.execute('''
    INSERT INTO client_billing 
    (client_id, plan_id, billing_cycle, amount, currency, start_date, next_billing_date, payment_method, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        client_id,
        plan_data['plan_id'],
        plan_data['billing_cycle'],
        plan_data['amount'],
        plan_data.get('currency', 'USD'),
        start_date,
        next_billing_date,
        plan_data.get('payment_method', 'credit_card'),
        plan_data.get('status', 'active')
    ))
    
    billing_id = cursor.lastrowid
    
    # Create initial transaction record
    transaction_id = str(uuid.uuid4())
    cursor.execute('''
    INSERT INTO billing_transactions
    (client_id, transaction_id, amount, currency, payment_method, status, timestamp, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        client_id,
        transaction_id,
        plan_data['amount'],
        plan_data.get('currency', 'USD'),
        plan_data.get('payment_method', 'credit_card'),
        'completed',
        datetime.now().isoformat(),
        'Initial subscription payment'
    ))
    
    # Update client subscription level if provided
    if 'subscription_level' in plan_data:
        cursor.execute('''
        UPDATE clients
        SET subscription_level = ?, subscription_status = 'active', subscription_start = ?
        WHERE id = ?
        ''', (plan_data['subscription_level'], start_date, client_id))
    
    return {
        "status": "success",
        "billing_id": billing_id,
        "transaction_id": transaction_id,
        "next_billing_date": next_billing_date
    }

# Initialize the database when this module is imported
init_db()
@with_transaction
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
        fields = [db_field for key, db_field in custom_mapping.items() if key in client_data]
        if 'default_scans' in client_data:
            fields.append('default_scans')
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
    
@with_transaction
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
        query = "UPDATE deployed_scanners SET deploy_status = ?, last_updated = ?"
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
        query = "INSERT INTO deployed_scanners (client_id, subdomain, deploy_status, deploy_date, last_updated, config_path, template_version) VALUES (?, ?, ?, ?, ?, ?, ?)"
        
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

@with_transaction
def delete_client(conn, cursor, client_id):
    """Delete a client and all associated data"""
    if not client_id:
        return {"status": "error", "message": "Client ID is required"}
    
    # Check if client exists
    cursor.execute('SELECT id FROM clients WHERE id = ?', (client_id,))
    if not cursor.fetchone():
        return {"status": "error", "message": "Client not found"}
    
    # Delete client (cascade will handle related records)
    cursor.execute('DELETE FROM clients WHERE id = ?', (client_id,))
    
    return {"status": "success", "message": "Client deleted successfully"}

@with_transaction
def log_scan(conn, cursor, client_id, scan_id, target, scan_type):
    """Log a scan to the database"""
    if not client_id or not scan_id:
        return {"status": "error", "message": "Client ID and Scan ID are required"}
    
    # Insert scan record
    cursor.execute('''
    INSERT INTO scan_history 
    (client_id, scan_id, timestamp, target, scan_type, status)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        client_id,
        scan_id,
        datetime.now().isoformat(),
        target,
        scan_type,
        'pending'
    ))
    
    scan_history_id = cursor.lastrowid
    
    # Log the scan
    log_action(conn, cursor, client_id, 'scan', 'scan_history', scan_history_id, 
              {'scan_id': scan_id, 'target': target, 'scan_type': scan_type})
    
    return {"status": "success", "scan_history_id": scan_history_id}

@with_transaction
def regenerate_api_key(conn, cursor, client_id):
    """Regenerate a client's API key"""
    if not client_id:
        return {"status": "error", "message": "Client ID is required"}
    
    # Check if client exists
    cursor.execute('SELECT id FROM clients WHERE id = ?', (client_id,))
    if not cursor.fetchone():
        return {"status": "error", "message": "Client not found"}
    
    # Generate a new API key
    new_api_key = str(uuid.uuid4())
    
    # Update the client's API key
    cursor.execute('UPDATE clients SET api_key = ? WHERE id = ?', (new_api_key, client_id))
    
    if cursor.rowcount == 0:
        return {"status": "error", "message": "Failed to update API key"}
    
    # Log the regeneration
    log_action(conn, cursor, client_id, 'regenerate_api_key', 'client', client_id, None)
    
    return {"status": "success", "api_key": new_api_key}

@with_transaction
def list_clients(conn, cursor, page=1, per_page=10, filters=None):
    """List clients with pagination and filtering options"""
    offset = (page - 1) * per_page
    
    # Start with base query
    query = '''
    SELECT c.id, c.business_name, c.business_domain, c.contact_email, 
           c.subscription_level, c.subscription_status, c.created_at, c.active,
           ds.subdomain
    FROM clients c
    LEFT JOIN deployed_scanners ds ON c.id = ds.client_id
    '''
    
    # Add filter conditions if provided
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
        
        if 'search' in filters and filters['search']:
            search_term = f"%{filters['search']}%"
            where_clauses.append('(c.business_name LIKE ? OR c.business_domain LIKE ? OR c.contact_email LIKE ?)')
            params.extend([search_term, search_term, search_term])
    
    # Construct WHERE clause if needed
    if where_clauses:
        query += ' WHERE ' + ' AND '.join(where_clauses)
    
    # Add order by and pagination
    query += ' ORDER BY c.id DESC LIMIT ? OFFSET ?'
    params.extend([per_page, offset])
    
    # Execute query
    cursor.execute(query, params)
    clients = [dict(row) for row in cursor.fetchall()]
    
    # Count total records for pagination
    count_query = 'SELECT COUNT(*) FROM clients c'
    if where_clauses:
        count_query += ' WHERE ' + ' AND '.join(where_clauses)
    
    # Remove pagination params and execute count query
    cursor.execute(count_query, params[:-2] if params else [])
    total_count = cursor.fetchone()[0]
    
    # Calculate pagination info
    total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1
    
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
