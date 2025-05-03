# migrations.py - Simple migration system

import os
import sqlite3
import logging
import traceback
from datetime import datetime

# Database paths
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def execute_migration(conn, cursor, sql, name):
    """Execute a single migration and log the result"""
    try:
        cursor.executescript(sql)
        
        # Log the migration in the migrations table
        cursor.execute('''
        INSERT INTO migrations (name, applied_at)
        VALUES (?, ?)
        ''', (name, datetime.now().isoformat()))
        
        return True
    except Exception as e:
        logging.error(f"Migration failed: {name} - {e}")
        logging.debug(traceback.format_exc())
        return False

def initialize_migrations_table(conn, cursor):
    """Create the migrations table if it doesn't exist"""
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS migrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        applied_at TEXT NOT NULL
    )
    ''')
    conn.commit()

def get_applied_migrations(cursor):
    """Get a list of already applied migrations"""
    cursor.execute('SELECT name FROM migrations')
    return [row[0] for row in cursor.fetchall()]

def run_migrations():
    """Run all pending migrations"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Initialize migrations table
        initialize_migrations_table(conn, cursor)
        
        # Get applied migrations
        applied = get_applied_migrations(cursor)
        
        # Define migrations
        migrations = [
            {
                'name': '001_initial_schema',
                'sql': '''
                -- Initial schema is assumed to be created by init_client_db already
                '''
            },
            {
                'name': '002_add_audit_log',
                'sql': '''
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
                '''
            },
            {
                ''name': '003_add_password_reset',
                'sql': '''
                CREATE TABLE IF NOT EXISTS password_resets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    reset_token TEXT UNIQUE NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    used BOOLEAN DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(reset_token);
                '''
            },
            {
                'name': '004_add_client_billing',
                'sql': '''
                CREATE TABLE IF NOT EXISTS client_billing (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id INTEGER NOT NULL,
                    plan_id TEXT NOT NULL,
                    amount REAL NOT NULL,
                    currency TEXT NOT NULL DEFAULT 'USD',
                    billing_cycle TEXT NOT NULL DEFAULT 'monthly',
                    next_billing_date TEXT,
                    payment_method_id TEXT,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
                );
                
                CREATE TABLE IF NOT EXISTS billing_transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id INTEGER NOT NULL,
                    amount REAL NOT NULL,
                    currency TEXT NOT NULL DEFAULT 'USD',
                    status TEXT NOT NULL,
                    payment_method TEXT,
                    transaction_id TEXT,
                    invoice_id TEXT,
                    transaction_date TEXT NOT NULL,
                    description TEXT,
                    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
                );
                '''
            },
            {
                'name': '005_enhance_client_table',
                'sql': '''
                ALTER TABLE clients ADD COLUMN company_size TEXT;
                ALTER TABLE clients ADD COLUMN industry TEXT;
                ALTER TABLE clients ADD COLUMN notes TEXT;
                '''
            }
        ]
        
        # Run pending migrations
        for migration in migrations:
            if migration['name'] not in applied:
                logging.info(f"Applying migration: {migration['name']}")
                
                # Start transaction
                conn.execute('BEGIN TRANSACTION')
                
                success = execute_migration(conn, cursor, migration['sql'], migration['name'])
                
                if success:
                    conn.commit()
                    logging.info(f"Migration applied successfully: {migration['name']}")
                else:
                    conn.rollback()
                    logging.error(f"Migration failed, rolling back: {migration['name']}")
                    return False
        
        conn.close()
        return True
    
    except Exception as e:
        logging.error(f"Error running migrations: {e}")
        logging.debug(traceback.format_exc())
        if 'conn' in locals() and conn:
            conn.rollback()
            conn.close()
        return False
