#!/usr/bin/env python3
# emergency_access.py - Standalone emergency access module

from flask import Blueprint, request, redirect, url_for, render_template, session, flash
import os
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

# Create blueprint for emergency routes
emergency_bp = Blueprint('emergency', __name__)

@emergency_bp.route('/emergency-login', methods=['GET', 'POST'])
def emergency_login():
    """Emergency login in case of auth issues"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('auth/login.html', error="Please provide username and password")
        
        try:
            # Connect directly to database
            conn = sqlite3.connect(CLIENT_DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Find user
            cursor.execute('SELECT * FROM users WHERE username = ? AND active = 1', (username,))
            user = cursor.fetchone()
            
            if not user:
                conn.close()
                flash("Invalid credentials", "danger")
                return redirect(url_for('emergency.emergency_login'))
                
            # Try password verification
            try:
                # PBKDF2 method (newer)
                salt = user['salt']
                stored_hash = user['password_hash']
                
                password_hash = hashlib.pbkdf2_hmac(
                    'sha256', 
                    password.encode(), 
                    salt.encode(), 
                    100000
                ).hex()
                
                pw_matches = (password_hash == stored_hash)
            except Exception as e:
                logger.error(f"Error in password verification: {e}")
                # Simple SHA-256 method (older fallback)
                try:
                    password_hash = hashlib.sha256((password + user['salt']).encode()).hexdigest()
                    pw_matches = (password_hash == user['password_hash'])
                except Exception as e2:
                    logger.error(f"Error in fallback password verification: {e2}")
                    pw_matches = False
            
            if not pw_matches:
                conn.close()
                flash("Invalid credentials", "danger")
                return redirect(url_for('emergency.emergency_login'))
            
            # Password matches - create session directly
            session_token = secrets.token_hex(32)
            created_at = datetime.now().isoformat()
            expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
            
            # Clear existing sessions for this user
            cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user['id'],))
            
            # Insert new session
            cursor.execute('''
            INSERT INTO sessions (
                user_id, session_token, created_at, expires_at, ip_address
            ) VALUES (?, ?, ?, ?, ?)
            ''', (user['id'], session_token, created_at, expires_at, request.remote_addr))
            
            # Commit changes
            conn.commit()
            
            # Store in session
            session.clear()  # Clear any old session data
            session['session_token'] = session_token
            session['username'] = user['username']
            session['role'] = user['role']
            session['user_id'] = user['id']
            
            # Log success
            logger.info(f"Emergency login successful for user: {username}")
            
            # Redirect based on role
            flash("Emergency login successful!", "success")
            if user['role'] == 'admin':
                # Instead of redirect, let's give them links
                return f"""
                <html>
                    <head>
                        <title>Emergency Login Successful</title>
                        <style>
                            body {{ font-family: Arial, sans-serif; padding: 20px; max-width: 800px; margin: 0 auto; }}
                            h1 {{ color: green; }}
                            a {{ display: block; margin: 10px 0; padding: 10px; background: #f5f5f5; border-radius: 5px; text-decoration: none; color: #333; }}
                            a:hover {{ background: #e5e5e5; }}
                            p {{ margin-bottom: 20px; }}
                        </style>
                    </head>
                    <body>
                        <h1>Emergency Login Successful!</h1>
                        <p>You are logged in as <strong>{username}</strong> with role <strong>{user['role']}</strong>.</p>
                        <p>To avoid issues with redirects, please use these direct links:</p>
                        <a href="/admin_simplified">Go to Simplified Admin Dashboard</a>
                        <a href="/scan">Go to Scanner</a>
                        <a href="/">Go to Home</a>
                    </body>
                </html>
                """
            else:
                return redirect(url_for('client.dashboard'))
                
        except Exception as e:
            import traceback
            logger.error(f"Error in emergency login: {e}")
            logger.error(traceback.format_exc())
            
            return f"""
            <html>
                <head>
                    <title>Emergency Login Error</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; padding: 20px; }}
                        pre {{ background: #f5f5f5; padding: 15px; overflow: auto; }}
                    </style>
                </head>
                <body>
                    <h1>Emergency Login Error</h1>
                    <p>Error: {str(e)}</p>
                    <pre>{traceback.format_exc()}</pre>
                    <form method="post" action="/emergency-login">
                        <label>Username: <input type="text" name="username" value="{username}"></label><br>
                        <label>Password: <input type="password" name="password"></label><br>
                        <button type="submit">Try Again</button>
                    </form>
                    <div>
                        <h2>Debug Information</h2>
                        <p>Database Path: {CLIENT_DB_PATH}</p>
                        <p>Database Exists: {os.path.exists(CLIENT_DB_PATH)}</p>
                    </div>
                </body>
            </html>
            """
    
    # Show login form for GET requests
    return '''
    <html>
        <head>
            <title>Emergency Login</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    margin: 20px; 
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                }
                form { 
                    margin-top: 20px; 
                    width: 300px;
                    border: 1px solid #ddd;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                h1 { color: #333; }
                input { 
                    margin: 5px 0; 
                    padding: 8px; 
                    width: 100%; 
                    box-sizing: border-box;
                }
                button { 
                    padding: 10px 16px; 
                    background: #4CAF50; 
                    color: white; 
                    border: none; 
                    border-radius: 4px;
                    cursor: pointer;
                    width: 100%;
                    margin-top: 15px;
                }
                button:hover {
                    background: #45a049;
                }
                .notice {
                    margin-top: 20px;
                    padding: 10px;
                    background: #fff8e1;
                    border: 1px solid #ffe0b2;
                    border-radius: 4px;
                    width: 300px;
                }
            </style>
        </head>
        <body>
            <h1>Emergency Login</h1>
            <form method="post" action="/emergency-login">
                <div>
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username">
                </div>
                <div>
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password">
                </div>
                <button type="submit">Login</button>
            </form>
            <div class="notice">
                <p>This is for emergency access in case of authentication issues.</p>
                <p>Try using <strong>admin</strong> and <strong>admin123</strong> if you're unsure.</p>
            </div>
        </body>
    </html>
    '''

@emergency_bp.route('/admin_simplified')
def admin_simplified():
    """Simplified admin view for emergency access"""
    session_token = session.get('session_token')
    username = session.get('username', 'Unknown')
    role = session.get('role', 'Unknown')
    
    # Very simple session check
    if not session_token or role != 'admin':
        return """
        <h1>Access Denied</h1>
        <p>You need to be logged in as an admin.</p>
        <a href="/emergency-login">Login</a>
        """
    
    try:
        # Get summary info
        import sqlite3
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get client count
        cursor.execute("SELECT COUNT(*) FROM clients")
        client_count = cursor.fetchone()[0]
        
        # Get user count
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        
        # Get recent clients
        cursor.execute("SELECT id, business_name, contact_email FROM clients ORDER BY id DESC LIMIT 5")
        recent_clients = [dict(row) for row in cursor.fetchall()]
        
        # Get recent users
        cursor.execute("SELECT id, username, email, role FROM users ORDER BY id DESC LIMIT 5")
        recent_users = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        # Create a simple dashboard HTML
        return f"""
        <html>
            <head>
                <title>Simplified Admin Dashboard</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .card {{ border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 20px; }}
                    .section {{ margin-bottom: 30px; }}
                    table {{ width: 100%; border-collapse: collapse; }}
                    th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}
                    th {{ background-color: #f2f2f2; }}
                </style>
            </head>
            <body>
                <h1>Simplified Admin Dashboard</h1>
                <p>Logged in as: {username} (Role: {role})</p>
                
                <div class="section">
                    <h2>Summary</h2>
                    <div style="display: flex; gap: 20px;">
                        <div class="card">
                            <h3>Clients</h3>
                            <p style="font-size: 24px;">{client_count}</p>
                        </div>
                        <div class="card">
                            <h3>Users</h3>
                            <p style="font-size: 24px;">{user_count}</p>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>Recent Clients</h2>
                    <table>
                        <tr>
                            <th>ID</th>
                            <th>Business Name</th>
                            <th>Email</th>
                        </tr>
                        {''.join([f'<tr><td>{c["id"]}</td><td>{c["business_name"]}</td><td>{c["contact_email"]}</td></tr>' for c in recent_clients])}
                    </table>
                </div>
                
                <div class="section">
                    <h2>Recent Users</h2>
                    <table>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Role</th>
                        </tr>
                        {''.join([f'<tr><td>{u["id"]}</td><td>{u["username"]}</td><td>{u["email"]}</td><td>{u["role"]}</td></tr>' for u in recent_users])}
                    </table>
                </div>
                
                <div>
                    <a href="/emergency-login">Back to Emergency Login</a>
                </div>
            </body>
        </html>
        """
    except Exception as e:
        return f"""
        <h1>Error</h1>
        <p>An error occurred: {str(e)}</p>
        <a href="/emergency-login">Back to Emergency Login</a>
        """

@emergency_bp.route('/direct_fix')
def direct_fix():
    """Direct database fix route"""
    try:
        # Import our fix function
        from db_fix import fix_database
        
        # Run the fix
        result = fix_database()
        
        if result:
            return """
            <html>
                <head>
                    <title>Database Fix Successful</title>
                    <style>
                        body { font-family: Arial, sans-serif; padding: 20px; }
                        h1 { color: green; }
                        .next-steps { margin-top: 20px; }
                    </style>
                </head>
                <body>
                    <h1>Database Fix Successful!</h1>
                    <p>The database has been fixed successfully.</p>
                    <div class="next-steps">
                        <h2>Next Steps</h2>
                        <p>You can now login with:</p>
                        <ul>
                            <li><strong>Username:</strong> admin</li>
                            <li><strong>Password:</strong> admin123</li>
                        </ul>
                        <p><a href="/emergency-login">Go to Emergency Login</a></p>
                    </div>
                </body>
            </html>
            """
        else:
            return """
            <html>
                <head>
                    <title>Database Fix Failed</title>
                    <style>
                        body { font-family: Arial, sans-serif; padding: 20px; }
                        h1 { color: red; }
                    </style>
                </head>
                <body>
                    <h1>Database Fix Failed</h1>
                    <p>The database fix operation failed. Please check the logs for more information.</p>
                    <p><a href="/emergency-login">Go to Emergency Login</a></p>
                </body>
            </html>
            """
    except ImportError:
        return """
        <html>
            <head>
                <title>Fix Script Not Found</title>
                <style>
                    body { font-family: Arial, sans-serif; padding: 20px; }
                    h1 { color: orange; }
                    pre { background: #f5f5f5; padding: 15px; }
                </style>
            </head>
            <body>
                <h1>Fix Script Not Found</h1>
                <p>The db_fix.py script was not found. Please make sure you've created this file.</p>
                <p>You can copy and paste the code from the chat to create the file, or use the direct fix below:</p>
                <p><a href="/db_fix">Run Direct Database Fix</a></p>
            </body>
        </html>
        """
    except Exception as e:
        import traceback
        return f"""
        <html>
            <head>
                <title>Error Running Fix</title>
                <style>
                    body {{ font-family: Arial, sans-serif; padding: 20px; }}
                    h1 {{ color: red; }}
                    pre {{ background: #f5f5f5; padding: 15px; overflow: auto; }}
                </style>
            </head>
            <body>
                <h1>Error Running Fix</h1>
                <p>An error occurred while trying to run the database fix:</p>
                <p>{str(e)}</p>
                <pre>{traceback.format_exc()}</pre>
                <p><a href="/emergency-login">Go to Emergency Login</a></p>
            </body>
        </html>
        """

@emergency_bp.route('/db_fix')
def direct_db_fix():
    results = []
    try:
        # Import necessary modules
        import sqlite3
        import secrets
        import hashlib
        from datetime import datetime
        
        # Define database path - make sure this matches your actual database path
        CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')
        results.append(f"Working with database at: {CLIENT_DB_PATH}")
        results.append(f"Database exists: {os.path.exists(CLIENT_DB_PATH)}")
        
        # Connect to the database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Check database structure
        results.append("Checking database tables...")
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        results.append(f"Found tables: {[table[0] for table in tables]}")
        
        # Create a new admin user with simple password
        results.append("Creating/updating admin user...")
        
        # Generate password hash
        salt = secrets.token_hex(16)
        password = 'admin123'
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt.encode(), 
            100000
        ).hex()
        
        # Create users table if it doesn't exist
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
            last_login TEXT,
            active INTEGER DEFAULT 1
        )
        ''')
        
        # Create sessions table if it doesn't exist
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
        
        # Clear all sessions
        cursor.execute("DELETE FROM sessions")
        results.append("Cleared all sessions")
        
        # Check if admin user exists
        cursor.execute("SELECT id FROM users WHERE username = 'superadmin'")
        admin_user = cursor.fetchone()
        
        if admin_user:
            # Update existing admin
            cursor.execute('''
            UPDATE users SET 
                password_hash = ?, 
                salt = ?,
                role = 'admin',
                active = 1
            WHERE username = 'superadmin'
            ''', (password_hash, salt))
            results.append("Updated existing superadmin user")
        else:
            # Create a new admin user
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
            ''', ('superadmin', 'superadmin@example.com', password_hash, salt, 'admin', 'Super Administrator', datetime.now().isoformat()))
            results.append("Created new superadmin user")
        
        # Also create a regular admin user
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        admin_user = cursor.fetchone()
        
        if admin_user:
            # Update existing admin
            cursor.execute('''
            UPDATE users SET 
                password_hash = ?, 
                salt = ?,
                role = 'admin',
                active = 1
            WHERE username = 'admin'
            ''', (password_hash, salt))
            results.append("Updated existing admin user")
        else:
            # Create a new admin user
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
            ''', ('admin', 'admin@example.com', password_hash, salt, 'admin', 'Administrator', datetime.now().isoformat()))
            results.append("Created new admin user")
        
        # Commit changes
        conn.commit()
        
        # Verify creation
        cursor.execute("SELECT id, username, email, role FROM users WHERE username = 'admin'")
        user = cursor.fetchone()
        if user:
            results.append(f"Admin user verified: ID={user[0]}, username={user[1]}, email={user[2]}, role={user[3]}")
        
        cursor.execute("SELECT id, username, email, role FROM users WHERE username = 'superadmin'")
        user = cursor.fetchone()
        if user:
            results.append(f"Superadmin user verified: ID={user[0]}, username={user[1]}, email={user[2]}, role={user[3]}")
        
        # Close connection
        conn.close()
        
        results.append("Database fix completed!")
        results.append("You can now login with:")
        results.append("Username: admin")
        results.append("Password: admin123")
        results.append("OR")
        results.append("Username: superadmin")
        results.append("Password: admin123")
        
        return "<br>".join(results)
    except Exception as e:
        results.append(f"Error: {str(e)}")
        return "<br>".join(results)
