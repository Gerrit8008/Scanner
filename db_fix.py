@app.route('/db_fix')
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
        password = 'password123'
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt.encode(), 
            100000
        ).hex()
        
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
        
        # Commit changes
        conn.commit()
        
        # Verify creation
        cursor.execute("SELECT id, username, email, role FROM users WHERE username = 'superadmin'")
        user = cursor.fetchone()
        if user:
            results.append(f"Superadmin user verified: ID={user[0]}, username={user[1]}, email={user[2]}, role={user[3]}")
        
        # Close connection
        conn.close()
        
        results.append("Database fix completed!")
        results.append("You can now login with:")
        results.append("Username: superadmin")
        results.append("Password: password123")
        
        return "<br>".join(results)
    except Exception as e:
        results.append(f"Error: {str(e)}")
        return "<br>".join(results)
