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

def create_user(username, email, password, role='client'):
    """Create a new user with the given credentials"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Check if username or email already exists
        cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        existing_user = cursor.fetchone()
        
        if existing_user:
            conn.close()
            return {"status": "error", "message": "Username or email already exists"}
        
        # Create salt and hash password
        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        
        cursor.execute('''
        INSERT INTO users (username, email, password_hash, salt, role, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, email, password_hash, salt, role, datetime.now().isoformat()))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {"status": "success", "user_id": user_id}
    except Exception as e:
        logging.error(f"Error creating user: {e}")
        logging.debug(traceback.format_exc())
        return {"status": "error", "message": str(e)}

def authenticate_user(username_or_email, password):
    """Authenticate a user with username/email and password"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Find user by username or email
        cursor.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username_or_email, username_or_email))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return {"status": "error", "message": "Invalid credentials"}
        
        # Verify password
        password_hash = hashlib.sha256((password + user['salt']).encode()).hexdigest()
        
        if password_hash != user['password_hash']:
            conn.close()
            return {"status": "error", "message": "Invalid credentials"}
        
        # Create a session token
        session_token = secrets.token_hex(32)
        expires_at = datetime.now().replace(hour=23, minute=59, second=59).isoformat()
        
        # Store session
        cursor.execute('''
        INSERT INTO sessions (user_id, session_token, created_at, expires_at)
        VALUES (?, ?, ?, ?)
        ''', (user['id'], session_token, datetime.now().isoformat(), expires_at))
        
        # Update last login
        cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.now().isoformat(), user['id']))
        
        conn.commit()
        conn.close()
        
        return {
            "status": "success",
            "user_id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "role": user['role'],
            "session_token": session_token
        }
    except Exception as e:
        logging.error(f"Error authenticating user: {e}")
        logging.debug(traceback.format_exc())
        return {"status": "error", "message": str(e)}

def verify_session(session_token):
    """Verify if a session is valid and return user info"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get session
        cursor.execute('''
        SELECT s.*, u.username, u.email, u.role 
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.session_token = ? AND s.expires_at > ?
        ''', (session_token, datetime.now().isoformat()))
        
        session = cursor.fetchone()
        
        if not session:
            conn.close()
            return {"status": "error", "message": "Invalid or expired session"}
        
        user_data = {
            "user_id": session['user_id'],
            "username": session['username'],
            "email": session['email'],
            "role": session['role']
        }
        
        conn.close()
        return {"status": "success", "user": user_data}
    except Exception as e:
        logging.error(f"Error verifying session: {e}")
        logging.debug(traceback.format_exc())
        return {"status": "error", "message": str(e)}

def logout_user(session_token):
    """Invalidate a user session"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM sessions WHERE session_token = ?', (session_token,))
        
        rows_affected = cursor.rowcount
        conn.commit()
        conn.close()
        
        if rows_affected > 0:
            return {"status": "success", "message": "Logged out successfully"}
        else:
            return {"status": "error", "message": "Session not found"}
    except Exception as e:
        logging.error(f"Error logging out user: {e}")
        logging.debug(traceback.format_exc())
        return {"status": "error", "message": str(e)}

def create_client(client_data, user_id):
    """Create a new client with the given data"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Generate API key
        api_key = str(uuid.uuid4())
        current_time = datetime.now().isoformat()
        
        # Insert client record
        cursor.execute('''
        INSERT INTO clients 
        (business_name, business_domain, contact_email, contact_phone, 
         scanner_name, subscription_level, subscription_status, subscription_start,
         api_key, created_at, created_by, active)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        
        # Create deployed scanner record
        subdomain = client_data.get('business_name', '').lower().replace(' ', '-')
        # Clean up subdomain to be URL-friendly
        subdomain = ''.join(c for c in subdomain if c.isalnum() or c == '-')
        
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
        
        conn.commit()
        conn.close()
        
        return {
            "status": "success",
            "client_id": client_id,
            "api_key": api_key,
            "subdomain": subdomain
        }
    except Exception as e:
        logging.error(f"Error creating client: {e}")
        logging.debug(traceback.format_exc())
        return {"status": "error", "message": str(e)}

def get_client_by_id(client_id):
    """Get client details by ID"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Join clients, customizations, and deployed_scanners tables
        cursor.execute('''
        SELECT c.*, cu.*, ds.subdomain, ds.deploy_status, ds.deploy_date
        FROM clients c
        LEFT JOIN customizations cu ON c.id = cu.client_id
        LEFT JOIN deployed_scanners ds ON c.id = ds.client_id
        WHERE c.id = ?
        ''', (client_id,))
        
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
        
        # Get scan history for this client
        cursor.execute('''
        SELECT * FROM scan_history
        WHERE client_id = ?
        ORDER BY timestamp DESC
        LIMIT 10
        ''', (client_id,))
        
        scan_history = [dict(row) for row in cursor.fetchall()]
        client_data['scan_history'] = scan_history
        
        conn.close()
        return client_data
    except Exception as e:
        logging.error(f"Error retrieving client by ID: {e}")
        logging.debug(traceback.format_exc())
        return None

def update_client(client_id, client_data, user_id):
    """Update client details"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Update client table
        cursor.execute('''
        UPDATE clients
        SET business_name = ?,
            business_domain = ?,
            contact_email = ?,
            contact_phone = ?,
            scanner_name = ?,
            subscription_level = ?,
            subscription_status = ?,
            active = ?
        WHERE id = ?
        ''', (
            client_data.get('business_name', ''),
            client_data.get('business_domain', ''),
            client_data.get('contact_email', ''),
            client_data.get('contact_phone', ''),
            client_data.get('scanner_name', ''),
            client_data.get('subscription_level', 'basic'),
            client_data.get('subscription_status', 'active'),
            1 if client_data.get('active', True) else 0,
            client_id
        ))
        
        # Update customizations
        default_scans = json.dumps(client_data.get('default_scans', []))
        
        cursor.execute('''
        UPDATE customizations
        SET primary_color = ?,
            secondary_color = ?,
            email_subject = ?,
            email_intro = ?,
            default_scans = ?,
            last_updated = ?,
            updated_by = ?
        WHERE client_id = ?
        ''', (
            client_data.get('primary_color', '#FF6900'),
            client_data.get('secondary_color', '#808588'),
            client_data.get('email_subject', 'Your Security Scan Report'),
            client_data.get('email_intro', 'Thank you for using our security scanner.'),
            default_scans,
            datetime.now().isoformat(),
            user_id,
            client_id
        ))
        
        # Handle file uploads separately (logo, favicon) if provided
        if 'logo_path' in client_data and client_data['logo_path']:
            cursor.execute('''
            UPDATE customizations
            SET logo_path = ?
            WHERE client_id = ?
            ''', (client_data['logo_path'], client_id))
            
        if 'favicon_path' in client_data and client_data['favicon_path']:
            cursor.execute('''
            UPDATE customizations
            SET favicon_path = ?
            WHERE client_id = ?
            ''', (client_data['favicon_path'], client_id))
        
        conn.commit()
        conn.close()
        
        return {"status": "success", "client_id": client_id}
    except Exception as e:
        logging.error(f"Error updating client: {e}")
        logging.debug(traceback.format_exc())
        return {"status": "error", "message": str(e)}

def list_clients(page=1, per_page=10, filters=None):
    """List clients with pagination and filtering"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Base query
        query = '''
        SELECT c.id, c.business_name, c.contact_email, c.scanner_name, 
               c.subscription_level, c.subscription_status, c.active,
               ds.subdomain, ds.deploy_status
        FROM clients c
        LEFT JOIN deployed_scanners ds ON c.id = ds.client_id
        '''
        
        params = []
        
        # Add filters if provided
        where_clauses = []
        if filters:
            if 'subscription' in filters:
                where_clauses.append('c.subscription_level = ?')
                params.append(filters['subscription'])
            
            if 'status' in filters:
                where_clauses.append('c.subscription_status = ?')
                params.append(filters['status'])
            
            if 'active' in filters:
                where_clauses.append('c.active = ?')
                params.append(1 if filters['active'] else 0)
            
            if 'search' in filters and filters['search']:
                where_clauses.append('(c.business_name LIKE ? OR c.contact_email LIKE ?)')
                search_term = f"%{filters['search']}%"
                params.extend([search_term, search_term])
        
        if where_clauses:
            query += ' WHERE ' + ' AND '.join(where_clauses)
        
        # Add order and pagination
        query += ' ORDER BY c.business_name LIMIT ? OFFSET ?'
        offset = (page - 1) * per_page
        params.extend([per_page, offset])
        
        # Execute query
        cursor.execute(query, params)
        clients = [dict(row) for row in cursor.fetchall()]
        
        # Get total count for pagination
        count_query = '''
        SELECT COUNT(*) as total FROM clients c
        '''
        
        if where_clauses:
            count_query += ' WHERE ' + ' AND '.join(where_clauses)
            cursor.execute(count_query, params[:-2])  # Remove limit and offset params
        else:
            cursor.execute(count_query)
            
        total = cursor.fetchone()['total']
        
        # For each client, count their scans
        for client in clients:
            cursor.execute('SELECT COUNT(*) as scan_count FROM scan_history WHERE client_id = ?', 
                          (client['id'],))
            client['scan_count'] = cursor.fetchone()['scan_count']
        
        conn.close()
        
        return {
            "status": "success",
            "clients": clients,
            "pagination": {
                "total": total,
                "page": page,
                "per_page": per_page,
                "pages": (total + per_page - 1) // per_page  # Ceiling division
            }
        }
    except Exception as e:
        logging.error(f"Error listing clients: {e}")
        logging.debug(traceback.format_exc())
        return {"status": "error", "message": str(e)}

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
            try:
                client_data['default_scans'] = json.loads(client_data['default_scans'])
            except json.JSONDecodeError:
                client_data['default_scans'] = []
        
        conn.close()
        return client_data
    except Exception as e:
        logging.error(f"Error retrieving client by API key: {e}")
        logging.debug(traceback.format_exc())
        return None

def delete_client(client_id):
    """Mark a client as inactive (soft delete)"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Set client to inactive
        cursor.execute('UPDATE clients SET active = 0 WHERE id = ?', (client_id,))
        
        affected_rows = cursor.rowcount
        conn.commit()
        conn.close()
        
        if affected_rows > 0:
            return {"status": "success", "message": "Client deactivated successfully"}
        else:
            return {"status": "error", "message": "Client not found"}
    except Exception as e:
        logging.error(f"Error deleting client: {e}")
        logging.debug(traceback.format_exc())
        return {"status": "error", "message": str(e)}

def regenerate_api_key(client_id):
    """Generate a new API key for the client"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Generate new API key
        new_api_key = str(uuid.uuid4())
        
        # Update client record
        cursor.execute('UPDATE clients SET api_key = ? WHERE id = ?', (new_api_key, client_id))
        
        affected_rows = cursor.rowcount
        conn.commit()
        conn.close()
        
        if affected_rows > 0:
            return {"status": "success", "api_key": new_api_key}
        else:
            return {"status": "error", "message": "Client not found"}
    except Exception as e:
        logging.error(f"Error regenerating API key: {e}")
        logging.debug(traceback.format_exc())
        return {"status": "error", "message": str(e)}

def log_scan(client_id, scan_id, target, scan_type="comprehensive"):
    """Log a scan performed by a client"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO scan_history (client_id, scan_id, timestamp, target, scan_type, status)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            client_id,
            scan_id,
            datetime.now().isoformat(),
            target,
            scan_type,
            'completed'
        ))
        
        conn.commit()
        conn.close()
        
        return {"status": "success", "scan_id": scan_id}
    except Exception as e:
        logging.error(f"Error logging scan: {e}")
        logging.debug(traceback.format_exc())
        return {"status": "error", "message": str(e)}
        
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
