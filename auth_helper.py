# auth_helper.py - Enhanced authentication handling

import os
import sqlite3
import hashlib
import secrets
import logging
from datetime import datetime, timedelta
import re
from flask import jsonify, session

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database path from your existing code
from client_db import CLIENT_DB_PATH, verify_session

def hash_password(password, salt=None):
    """
    Hash a password using a secure method with salt
    
    Args:
        password (str): The password to hash
        salt (str, optional): The salt to use. If None, a new salt is generated
        
    Returns:
        tuple: (hashed_password, salt)
    """
    if salt is None:
        salt = secrets.token_hex(16)
    
    # Use stronger hashing with iterations
    hashed = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode(), 
        salt.encode(), 
        100000  # More iterations for better security
    ).hex()
    
    return hashed, salt

def verify_password(password, stored_hash, salt):
    """
    Verify a password against a stored hash
    
    Args:
        password (str): The password to verify
        stored_hash (str): The stored hash
        salt (str): The salt used for hashing
        
    Returns:
        bool: True if the password matches, False otherwise
    """
    calculated_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(calculated_hash, stored_hash)

def create_user(username, email, password, full_name=None, role='client'):
    """
    Create a new user with enhanced validation
    
    Args:
        username (str): Username
        email (str): Email address
        password (str): Password
        full_name (str, optional): Full name of the user
        role (str, optional): User role (admin, client, etc.)
        
    Returns:
        dict: Result of the operation with status and message
    """
    try:
        # Basic validation
        if not username or not email or not password:
            return {"status": "error", "message": "All fields are required"}
        
        if len(password) < 8:
            return {"status": "error", "message": "Password must be at least 8 characters"}
        
        # Email validation with regex
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return {"status": "error", "message": "Invalid email format"}
        
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Check if username or email already exists
        cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        existing_user = cursor.fetchone()
        
        if existing_user:
            conn.close()
            return {"status": "error", "message": "Username or email already exists"}
        
        # Create salt and hash password
        password_hash, salt = hash_password(password)
        
        # Get current time
        created_at = datetime.now().isoformat()
        
        # Insert the user
        cursor.execute('''
        INSERT INTO users (
            username, 
            email, 
            password_hash, 
            salt, 
            role, 
            full_name,
            created_at, 
            last_login,
            active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 1)
        ''', (username, email, password_hash, salt, role, full_name, created_at))
        
        # Get the new user ID
        user_id = cursor.lastrowid
        
        # Log the action
        cursor.execute('''
        INSERT INTO audit_log (
            user_id, 
            action, 
            entity_type, 
            entity_id, 
            changes, 
            timestamp
        ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            user_id, 
            'user_created', 
            'user', 
            user_id, 
            f'{{"username": "{username}", "email": "{email}", "role": "{role}"}}', 
            created_at
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Created new user: {username} (ID: {user_id}) with role: {role}")
        return {"status": "success", "user_id": user_id, "message": "User created successfully"}
        
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        return {"status": "error", "message": f"Database error: {str(e)}"}

def authenticate_user(username_or_email, password, ip_address=None):
    """
    Authenticate a user with enhanced security
    
    Args:
        username_or_email (str): Username or email
        password (str): Password
        ip_address (str, optional): IP address of the request
        
    Returns:
        dict: Authentication result with user info and session token if successful
    """
    try:
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Find user by username or email
        cursor.execute('''
        SELECT * FROM users 
        WHERE (username = ? OR email = ?) AND active = 1
        ''', (username_or_email, username_or_email))
        
        user = cursor.fetchone()
        
        if not user:
            # Use constant time comparison to prevent timing attacks
            dummy_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), b'dummy', 100000).hex()
            secrets.compare_digest(dummy_hash, dummy_hash)  # Constant time comparison
            
            # Log failed login attempt
            logger.warning(f"Failed login attempt for non-existent user: {username_or_email} from IP: {ip_address}")
            
            conn.close()
            return {"status": "error", "message": "Invalid credentials"}
        
        # Verify password
        password_correct = verify_password(password, user['password_hash'], user['salt'])
        
        if not password_correct:
            # Log failed login attempt
            logger.warning(f"Failed login attempt for user: {user['username']} (ID: {user['id']}) from IP: {ip_address}")
            
            conn.close()
            return {"status": "error", "message": "Invalid credentials"}
        
        # Create a session token
        session_token = secrets.token_hex(32)
        created_at = datetime.now().isoformat()
        expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
        
        # Store session
        cursor.execute('''
        INSERT INTO sessions (
            user_id, 
            session_token, 
            created_at, 
            expires_at, 
            ip_address,
            user_agent
        ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (user['id'], session_token, created_at, expires_at, ip_address, None))
        
        # Update last login timestamp
        cursor.execute('''
        UPDATE users 
        SET last_login = ? 
        WHERE id = ?
        ''', (created_at, user['id']))
        
        # Log successful login
        cursor.execute('''
        INSERT INTO audit_log (
            user_id, 
            action, 
            entity_type, 
            entity_id, 
            changes, 
            timestamp,
            ip_address
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            user['id'], 
            'user_login', 
            'user', 
            user['id'], 
            f'{{"ip_address": "{ip_address}"}}', 
            created_at,
            ip_address
        ))
        
        conn.commit()
        
        logger.info(f"Successful login for user: {user['username']} (ID: {user['id']}) from IP: {ip_address}")
        
        # Get any additional user profile data
        cursor.execute('''
        SELECT * FROM user_profiles 
        WHERE user_id = ?
        ''', (user['id'],))
        
        profile = cursor.fetchone()
        profile_data = dict(profile) if profile else {}
        
        conn.close()
        
        # Convert user row to dict
        user_dict = dict(user)
        
        # Remove sensitive information
        user_dict.pop('password_hash', None)
        user_dict.pop('salt', None)
        
        # Return successful authentication result
        return {
            "status": "success",
            "user_id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "role": user['role'],
            "session_token": session_token,
            "full_name": user['full_name'],
            "profile": profile_data
        }
    
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        return {"status": "error", "message": f"Authentication failed: {str(e)}"}

def logout_user(session_token):
    """
    Logout a user by invalidating their session
    
    Args:
        session_token (str): Session token
        
    Returns:
        dict: Logout result
    """
    try:
        if not session_token:
            return {"status": "error", "message": "No session token provided"}
        
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get user ID from session for logging
        cursor.execute('SELECT user_id FROM sessions WHERE session_token = ?', (session_token,))
        session = cursor.fetchone()
        
        if session:
            user_id = session['user_id']
            
            # Delete the session
            cursor.execute('DELETE FROM sessions WHERE session_token = ?', (session_token,))
            
            # Log the logout
            cursor.execute('''
            INSERT INTO audit_log (
                user_id, 
                action, 
                entity_type, 
                entity_id, 
                changes, 
                timestamp
            ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                user_id, 
                'user_logout', 
                'user', 
                user_id, 
                None, 
                datetime.now().isoformat()
            ))
            
            conn.commit()
            logger.info(f"User ID {user_id} logged out")
        
        conn.close()
        
        return {"status": "success", "message": "Logged out successfully"}
    
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return {"status": "error", "message": f"Logout failed: {str(e)}"}

def get_all_users(page=1, per_page=20, search=None, role=None):
    """
    Get a list of all users with pagination and filtering
    
    Args:
        page (int): Page number
        per_page (int): Items per page
        search (str, optional): Search term for filtering
        role (str, optional): Filter by role
        
    Returns:
        dict: List of users and pagination info
    """
    try:
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Base query
        query = '''
        SELECT 
            u.id, 
            u.username, 
            u.email, 
            u.role, 
            u.full_name,
            u.created_at, 
            u.last_login, 
            u.active,
            COUNT(s.id) as login_count
        FROM users u
        LEFT JOIN sessions s ON u.id = s.user_id
        '''
        
        # Add filters
        where_clauses = []
        params = []
        
        if search:
            where_clauses.append('(u.username LIKE ? OR u.email LIKE ? OR u.full_name LIKE ?)')
            search_term = f'%{search}%'
            params.extend([search_term, search_term, search_term])
        
        if role:
            where_clauses.append('u.role = ?')
            params.append(role)
        
        if where_clauses:
            query += ' WHERE ' + ' AND '.join(where_clauses)
        
        # Add group by
        query += ' GROUP BY u.id'
        
        # Count total records for pagination
        count_query = f'''
        SELECT COUNT(*) FROM users u
        '''
        
        if where_clauses:
            count_query += ' WHERE ' + ' AND '.join(where_clauses)
        
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]
        
        # Calculate pagination
        offset = (page - 1) * per_page
        total_pages = (total_count + per_page - 1) // per_page
        
        # Complete the query
        query += ' ORDER BY u.created_at DESC LIMIT ? OFFSET ?'
        params.extend([per_page, offset])
        
        # Execute query
        cursor.execute(query, params)
        users = [dict(row) for row in cursor.fetchall()]
        
        # Get the last login for each user
        for user in users:
            cursor.execute('''
            SELECT created_at 
            FROM sessions 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 1
            ''', (user['id'],))
            
            last_session = cursor.fetchone()
            if last_session:
                user['last_login'] = last_session[0]
        
        conn.close()
        
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
    
    except Exception as e:
        logger.error(f"Error getting users: {str(e)}")
        return {"status": "error", "message": f"Failed to get users: {str(e)}"}

def get_user_by_id(user_id):
    """
    Get detailed information about a user by ID
    
    Args:
        user_id (int): User ID
        
    Returns:
        dict: User information
    """
    try:
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get user data
        cursor.execute('''
        SELECT 
            u.id, 
            u.username, 
            u.email, 
            u.role, 
            u.full_name,
            u.created_at, 
            u.last_login, 
            u.active,
            COUNT(s.id) as login_count
        FROM users u
        LEFT JOIN sessions s ON u.id = s.user_id
        WHERE u.id = ?
        GROUP BY u.id
        ''', (user_id,))
        
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return {"status": "error", "message": "User not found"}
        
        # Get user profile if exists
        cursor.execute('SELECT * FROM user_profiles WHERE user_id = ?', (user_id,))
        profile = cursor.fetchone()
        
        # Get recent login history
        cursor.execute('''
        SELECT 
            id, 
            created_at, 
            ip_address, 
            user_agent
        FROM sessions
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 5
        ''', (user_id,))
        
        login_history = [dict(row) for row in cursor.fetchall()]
        
        # Get audit log for this user
        cursor.execute('''
        SELECT 
            id, 
            action, 
            entity_type, 
            entity_id, 
            changes, 
            timestamp, 
            ip_address
        FROM audit_log
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT 10
        ''', (user_id,))
        
        audit_logs = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        user_dict = dict(user)
        profile_dict = dict(profile) if profile else {}
        
        return {
            "status": "success",
            "user": user_dict,
            "profile": profile_dict,
            "login_history": login_history,
            "audit_logs": audit_logs
        }
    
    except Exception as e:
        logger.error(f"Error getting user by ID: {str(e)}")
        return {"status": "error", "message": f"Failed to get user: {str(e)}"}

def update_user(user_id, user_data, updated_by_id):
    """
    Update user information
    
    Args:
        user_id (int): User ID
        user_data (dict): User data to update
        updated_by_id (int): ID of the user making the update
        
    Returns:
        dict: Update result
    """
    try:
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Get current user data for comparison/logging
        conn.row_factory = sqlite3.Row
        current_cursor = conn.cursor()
        current_cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        current_user = current_cursor.fetchone()
        
        if not current_user:
            conn.close()
            return {"status": "error", "message": "User not found"}
        
        # Convert to dict
        current_user_dict = dict(current_user)
        
        # Fields that can be updated
        allowed_fields = [
            'username', 
            'email', 
            'full_name', 
            'role', 
            'active'
        ]
        
        # Build update query
        field_updates = []
        params = []
        changes = {}
        
        for field in allowed_fields:
            if field in user_data and user_data[field] != current_user_dict.get(field):
                field_updates.append(f"{field} = ?")
                params.append(user_data[field])
                changes[field] = {
                    "old": current_user_dict.get(field),
                    "new": user_data[field]
                }
        
        # Update password if provided and not empty
        if 'password' in user_data and user_data['password']:
            password_hash, salt = hash_password(user_data['password'])
            field_updates.extend(['password_hash = ?', 'salt = ?'])
            params.extend([password_hash, salt])
            changes['password'] = {"changed": True}
        
        # If no changes, return
        if not field_updates:
            conn.close()
            return {"status": "success", "message": "No changes to update"}
        
        # Add updated_at
        field_updates.append('updated_at = ?')
        current_time = datetime.now().isoformat()
        params.append(current_time)
        
        # Complete the query
        query = f"UPDATE users SET {', '.join(field_updates)} WHERE id = ?"
        params.append(user_id)
        
        # Execute update
        cursor.execute(query, params)
        
        # Log the changes
        cursor.execute('''
        INSERT INTO audit_log (
            user_id, 
            action, 
            entity_type, 
            entity_id, 
            changes, 
            timestamp,
            ip_address
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            updated_by_id, 
            'user_updated', 
            'user', 
            user_id, 
            str(changes), 
            current_time,
            None
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"User ID {user_id} updated by User ID {updated_by_id}")
        return {"status": "success", "message": "User updated successfully"}
    
    except Exception as e:
        logger.error(f"Error updating user: {str(e)}")
        return {"status": "error", "message": f"Failed to update user: {str(e)}"}

def delete_user(user_id, deleted_by_id):
    """
    Delete a user (soft delete by setting active=0)
    
    Args:
        user_id (int): User ID to delete
        deleted_by_id (int): ID of the user performing the deletion
        
    Returns:
        dict: Deletion result
    """
    try:
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute('SELECT username, email FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return {"status": "error", "message": "User not found"}
        
        user_info = dict(user)
        
        # Soft delete the user
        current_time = datetime.now().isoformat()
        cursor.execute('''
        UPDATE users
        SET active = 0, updated_at = ?
        WHERE id = ?
        ''', (current_time, user_id))
        
        # Invalidate all sessions
        cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
        
        # Log the deletion
        cursor.execute('''
        INSERT INTO audit_log (
            user_id, 
            action, 
            entity_type, 
            entity_id, 
            changes, 
            timestamp
        ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            deleted_by_id, 
            'user_deleted', 
            'user', 
            user_id, 
            str(user_info), 
            current_time
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"User ID {user_id} deleted by User ID {deleted_by_id}")
        return {"status": "success", "message": "User deleted successfully"}
    
    except Exception as e:
        logger.error(f"Error deleting user: {str(e)}")
        return {"status": "error", "message": f"Failed to delete user: {str(e)}"}

def get_login_stats():
    """
    Get login statistics for dashboard
    
    Returns:
        dict: Login statistics
    """
    try:
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        stats = {
            "total_users": 0,
            "active_users": 0,
            "logins_today": 0,
            "logins_week": 0,
            "logins_month": 0,
            "new_users_week": 0,
            "new_users_month": 0,
            "user_roles": {},
            "recent_logins": []
        }
        
        # Get current date
        now = datetime.now()
        today = now.strftime("%Y-%m-%d")
        
        # Calculate date ranges
        week_ago = (now - timedelta(days=7)).strftime("%Y-%m-%d")
        month_ago = (now - timedelta(days=30)).strftime("%Y-%m-%d")
        
        # Get total users count
        cursor.execute('SELECT COUNT(*) FROM users')
        stats["total_users"] = cursor.fetchone()[0]
        
        # Get active users count
        cursor.execute('SELECT COUNT(*) FROM users WHERE active = 1')
        stats["active_users"] = cursor.fetchone()[0]
        
        # Get logins today
        cursor.execute('''
        SELECT COUNT(*) FROM sessions 
        WHERE created_at LIKE ?
        ''', (f'{today}%',))
        stats["logins_today"] = cursor.fetchone()[0]
        
        # Get logins this week
        cursor.execute('''
        SELECT COUNT(*) FROM sessions 
        WHERE created_at >= ?
        ''', (week_ago,))
        stats["logins_week"] = cursor.fetchone()[0]
        
        # Get logins this month
        cursor.execute('''
        SELECT COUNT(*) FROM sessions 
        WHERE created_at >= ?
        ''', (month_ago,))
        stats["logins_month"] = cursor.fetchone()[0]
        
        # Get new users this week
        cursor.execute('''
        SELECT COUNT(*) FROM users 
        WHERE created_at >= ?
        ''', (week_ago,))
        stats["new_users_week"] = cursor.fetchone()[0]
        
        # Get new users this month
        cursor.execute('''
        SELECT COUNT(*) FROM users 
        WHERE created_at >= ?
        ''', (month_ago,))
        stats["new_users_month"] = cursor.fetchone()[0]
        
        # Get user roles distribution
        cursor.execute('''
        SELECT role, COUNT(*) as count 
        FROM users 
        GROUP BY role
        ''')
        for role, count in cursor.fetchall():
            stats["user_roles"][role] = count
        
        # Get recent logins
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
        SELECT 
            s.created_at, 
            s.ip_address, 
            u.username, 
            u.email, 
            u.role
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        ORDER BY s.created_at DESC
        LIMIT 10
        ''')
        stats["recent_logins"] = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        return {"status": "success", "stats": stats}
    
    except Exception as e:
        logger.error(f"Error getting login stats: {str(e)}")
        return {"status": "error", "message": f"Failed to get login stats: {str(e)}"}

@auth_bp.before_app_first_request
def initialize_tables():
    """Initialize user tables before first request"""
    try:
        init_user_tables()
        logging.info("User tables initialized successfully")
    except Exception as e:
        logging.error(f"Error initializing user tables: {str(e)}")

        # Users table
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
            updated_at TEXT,
            last_login TEXT,
            active INTEGER DEFAULT 1
        )
        ''')
        
        # Sessions table
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
        
        # Audit log table
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
        
        # User profiles table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            phone TEXT,
            address TEXT,
            company TEXT,
            position TEXT,
            profile_image TEXT,
            preferences TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_log(user_id)')
        
        # Create default admin user if none exists
        cursor.execute('SELECT COUNT(*) FROM users WHERE role = "admin"')
        admin_count = cursor.fetchone()[0]
        
        if admin_count == 0:
            # Create a default admin user
            password_hash, salt = hash_password('admin123')
            created_at = datetime.now().isoformat()
            
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
            ''', ('admin', 'admin@example.com', password_hash, salt, 'admin', 'System Admin', created_at))
            
            # Log admin creation
            admin_id = cursor.lastrowid
            cursor.execute('''
            INSERT INTO audit_log (
                user_id,
                action,
                entity_type,
                entity_id,
                changes,
                timestamp
            ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (admin_id, 'system_init', 'user', admin_id, '{"message": "Default admin user created"}', created_at))
            
            logger.info("Created default admin user")
        
        conn.commit()
        conn.close()
        return True
    
    except Exception as e:
        logger.error(f"Error initializing user tables: {str(e)}")
        return False
