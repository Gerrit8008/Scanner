#!/usr/bin/env python3
"""
Fix 404 Error Script for Authentication System

This script will diagnose and fix the 404 error when trying to access 
/auth/register or other authentication routes.

Usage:
    python fix_404.py
"""

import os
import sys
import re
import sqlite3
import importlib.util

def print_header(message):
    """Print a formatted header."""
    print("\n" + "=" * 80)
    print(f" {message}")
    print("=" * 80 + "\n")

def check_file_exists(filepath):
    """Check if a file exists."""
    exists = os.path.isfile(filepath)
    status = "✅" if exists else "❌"
    print(f"{status} {filepath}")
    return exists

def check_directory_exists(dirpath):
    """Check if a directory exists."""
    exists = os.path.isdir(dirpath)
    status = "✅" if exists else "❌"
    print(f"{status} {dirpath}")
    return exists

def create_directory(dirpath):
    """Create a directory if it doesn't exist."""
    if not check_directory_exists(dirpath):
        os.makedirs(dirpath)
        print(f"Created directory: {dirpath}")
    return True

def check_files():
    """Check if required files exist."""
    print_header("Checking Files")
    
    files_to_check = [
        "app.py",
        "auth_helper.py",
        "auth_routes.py"
    ]
    
    all_exist = True
    for file in files_to_check:
        if not check_file_exists(file):
            all_exist = False
    
    return all_exist

def check_blueprint_registration():
    """Check if authentication blueprint is registered in app.py."""
    print_header("Checking Blueprint Registration")
    
    if not check_file_exists("app.py"):
        print("app.py not found. Can't check blueprint registration.")
        return False
    
    with open("app.py", "r") as f:
        content = f.read()
    
    import_found = re.search(r"from\s+auth_routes\s+import\s+auth_bp", content) is not None
    register_found = re.search(r"app\.register_blueprint\s*\(\s*auth_bp\s*\)", content) is not None
    
    if import_found and register_found:
        print("✅ Authentication blueprint properly registered")
        return True
    else:
        print("❌ Authentication blueprint not properly registered")
        if not import_found:
            print("   Missing: from auth_routes import auth_bp")
        if not register_found:
            print("   Missing: app.register_blueprint(auth_bp)")
        return False

def check_templates():
    """Check if template files exist."""
    print_header("Checking Templates")
    
    template_dirs = [
        "templates/auth",
        "templates/admin"
    ]
    
    template_files = [
        "templates/auth/login.html",
        "templates/auth/register.html",
        "templates/auth/profile.html",
        "templates/admin/user-management.html",
        "templates/admin/user-create.html",
        "templates/admin/user-detail.html",
        "templates/admin/user-edit.html"
    ]
    
    # Check template directories
    dirs_exist = True
    for directory in template_dirs:
        if not check_directory_exists(directory):
            dirs_exist = False
    
    # Check template files
    files_exist = True
    for template in template_files:
        if not check_file_exists(template):
            files_exist = False
    
    return dirs_exist and files_exist

def fix_blueprint_registration():
    """Fix blueprint registration in app.py."""
    print_header("Fixing Blueprint Registration")
    
    if not check_file_exists("app.py"):
        print("app.py not found. Can't fix blueprint registration.")
        return False
    
    # Read the content of app.py
    with open("app.py", "r") as f:
        lines = f.readlines()
    
    # Find app creation and blueprint registration
    app_line = -1
    bp_register_lines = []
    import_lines = []
    
    for i, line in enumerate(lines):
        if "app = Flask" in line:
            app_line = i
        if "app.register_blueprint" in line:
            bp_register_lines.append(i)
        if "import" in line:
            import_lines.append(i)
    
    if app_line == -1:
        print("❌ Could not find Flask app creation in app.py")
        return False
    
    # Look for existing auth_bp import
    auth_import_found = False
    for i, line in enumerate(lines):
        if "from auth_routes import auth_bp" in line:
            auth_import_found = True
            break
    
    # Look for existing auth_bp registration
    auth_register_found = False
    for i, line in enumerate(lines):
        if "app.register_blueprint(auth_bp)" in line:
            auth_register_found = True
            break
    
    modified = False
    
    # Add import if missing
    if not auth_import_found:
        # Find the best place to add the import
        if import_lines:
            insert_point = max(import_lines) + 1
        else:
            insert_point = 0
        
        lines.insert(insert_point, "from auth_routes import auth_bp\n")
        print("✅ Added missing import: from auth_routes import auth_bp")
        modified = True
    
    # Add registration if missing
    if not auth_register_found:
        # Find the best place to add the registration
        if bp_register_lines:
            insert_point = max(bp_register_lines) + 1
        else:
            insert_point = app_line + 1
        
        lines.insert(insert_point, "app.register_blueprint(auth_bp)\n")
        print("✅ Added missing registration: app.register_blueprint(auth_bp)")
        modified = True
    
    if modified:
        # Write the modified content back to app.py
        with open("app.py", "w") as f:
            f.writelines(lines)
        
        print("✅ Updated app.py successfully")
        return True
    else:
        print("ℹ️ No changes needed for app.py")
        return True

def fix_templates():
    """Create missing template directories."""
    print_header("Fixing Templates")
    
    template_dirs = [
        "templates",
        "templates/auth",
        "templates/admin"
    ]
    
    for directory in template_dirs:
        create_directory(directory)
    
    print("✅ Created template directories")
    print("⚠️ You still need to create the actual template files!")
    return True

def check_routes():
    """Check the route definitions in auth_routes.py."""
    print_header("Checking Route Definitions")
    
    if not check_file_exists("auth_routes.py"):
        print("auth_routes.py not found. Can't check route definitions.")
        return False
    
    with open("auth_routes.py", "r") as f:
        content = f.read()
    
    # Check blueprint creation
    bp_created = re.search(r"auth_bp\s*=\s*Blueprint\s*\(\s*['\"]auth['\"]\s*,\s*__name__\s*,\s*url_prefix\s*=\s*['\"]\/auth['\"]\s*\)", content) is not None
    
    if not bp_created:
        print("❌ Blueprint not properly created in auth_routes.py")
        print("  Expected: auth_bp = Blueprint('auth', __name__, url_prefix='/auth')")
        return False
    
    # Check route definitions
    register_route = re.search(r"@auth_bp\.route\s*\(\s*['\"]\/register['\"]\s*,\s*methods\s*=\s*\[\s*['\"]GET['\"]\s*,\s*['\"]POST['\"]\s*\]\s*\)", content) is not None
    login_route = re.search(r"@auth_bp\.route\s*\(\s*['\"]\/login['\"]\s*,\s*methods\s*=\s*\[\s*['\"]GET['\"]\s*,\s*['\"]POST['\"]\s*\]\s*\)", content) is not None
    logout_route = re.search(r"@auth_bp\.route\s*\(\s*['\"]\/logout['\"]\s*\)", content) is not None
    
    all_routes_good = True
    
    if not register_route:
        print("❌ Register route missing or incorrectly defined")
        all_routes_good = False
    else:
        print("✅ Register route correctly defined")
    
    if not login_route:
        print("❌ Login route missing or incorrectly defined")
        all_routes_good = False
    else:
        print("✅ Login route correctly defined")
    
    if not logout_route:
        print("❌ Logout route missing or incorrectly defined")
        all_routes_good = False
    else:
        print("✅ Logout route correctly defined")
    
    return all_routes_good

def create_modular_implementation():
    """Create a modular implementation of the authentication system."""
    print_header("Creating Modular Implementation")
    
    # Check if the modular file already exists
    if check_file_exists("auth_module.py"):
        print("auth_module.py already exists. Skipping creation.")
        return True
    
    print("📝 Creating auth_module.py...")
    
    # Write the modular implementation
    with open("auth_module.py", "w") as f:
        f.write("""# auth_module.py
\"\"\"
Self-contained authentication module for Flask applications.
This module provides a simple way to add authentication to a Flask application.

Usage:
    from auth_module import setup_auth
    
    # In your Flask app:
    app = Flask(__name__)
    auth = setup_auth(app, db_path='path/to/database.db')
\"\"\"

import os
import sqlite3
import hashlib
import secrets
import logging
from datetime import datetime, timedelta
import re
from functools import wraps

from flask import (
    Blueprint, render_template, request, redirect, url_for, flash, 
    session, jsonify
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AuthManager:
    \"\"\"Authentication manager for Flask applications.\"\"\"
    
    def __init__(self, app=None, db_path=None):
        self.app = app
        self.db_path = db_path
        self.blueprint = None
        
        if app is not None and db_path is not None:
            self.init_app(app, db_path)
    
    def init_app(self, app, db_path):
        \"\"\"Initialize the authentication manager with a Flask app.\"\"\"
        self.app = app
        self.db_path = db_path
        
        # Create the auth blueprint
        self.blueprint = Blueprint('auth', __name__, 
                                 url_prefix='/auth',
                                 template_folder='templates')
        
        # Set up database
        self.init_db()
        
        # Register routes
        self.register_routes()
        
        # Register the blueprint with the app
        self.app.register_blueprint(self.blueprint)
        
        # Log registration
        logger.info(f"Authentication blueprint registered with prefix: /auth")
        
        # Print all registered routes for debugging
        logger.info("Registered routes:")
        for rule in self.app.url_map.iter_rules():
            logger.info(f" - {rule}")
    
    def init_db(self):
        \"\"\"Initialize the authentication database.\"\"\"
        # Create directory if it doesn't exist
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
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
            updated_at TEXT,
            last_login TEXT,
            active INTEGER DEFAULT 1
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

        -- User profiles table
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
        );
        
        -- Create indexes
        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
        CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_log(user_id);
        ''')
        
        # Create default admin user if none exists
        cursor.execute('SELECT COUNT(*) FROM users WHERE role = "admin"')
        admin_count = cursor.fetchone()[0]
        
        if admin_count == 0
