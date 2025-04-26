import sqlite3
import os
import json
import logging
import uuid
import traceback
from datetime import datetime

# Set up database path in /tmp for Render compatibility
# Define this at the module level so it's available everywhere
DB_PATH = '/tmp/security_scanner.db'

def get_db_connection():
    """Create a connection to the SQLite database"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    return conn

def init_db():
    """Initialize the database with required tables"""
    logging.info(f"Initializing database at {DB_PATH}...")
    
    # Ensure the directory exists
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create scans table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT UNIQUE NOT NULL,
        timestamp TEXT NOT NULL,
        target TEXT,
        email TEXT,
        results TEXT,  -- JSON string of scan results
        html_report TEXT  -- HTML report content
    )
    ''')
    
    # Create leads table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS leads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT,
        company TEXT,
        phone TEXT,
        timestamp TEXT NOT NULL
    )
    ''')
    
    conn.commit()
    conn.close()
    logging.info("Database initialized successfully")

def save_scan_results(scan_results):
    """Save scan results to the database"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get required values from scan_results
        scan_id = scan_results.get('scan_id', str(uuid.uuid4()))
        timestamp = scan_results.get('timestamp', datetime.now().isoformat())
        target = scan_results.get('target', '')
        email = scan_results.get('email', '')
        
        # Convert full results to JSON string
        results_json = json.dumps(scan_results)
        
        # Generate HTML report if needed
        html_report = ''
        if 'html_report' in scan_results:
            html_report = scan_results['html_report']
        
        # Insert into database
        cursor.execute(
            'INSERT OR REPLACE INTO scans (scan_id, timestamp, target, email, results, html_report) VALUES (?, ?, ?, ?, ?, ?)',
            (scan_id, timestamp, target, email, results_json, html_report)
        )
        
        conn.commit()
        conn.close()
        
        logging.info(f"Scan results saved to database with ID: {scan_id}")
        return scan_id
    except Exception as e:
        logging.error(f"Error saving scan results to database: {e}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        if conn:
            conn.close()
        return None

def get_scan_results(scan_id):
    """Retrieve scan results from the database"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM scans WHERE scan_id = ?', (scan_id,))
        row = cursor.fetchone()
        
        if row:
            # Parse the JSON string back to a dictionary
            scan_data = dict(row)
            scan_data['results'] = json.loads(scan_data['results'])
            conn.close()
            logging.info(f"Retrieved scan results for ID: {scan_id}")
            return scan_data['results']
        else:
            conn.close()
            logging.warning(f"No scan results found for ID: {scan_id}")
            return None
    except Exception as e:
        logging.error(f"Error retrieving scan results from database: {e}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        if conn:
            conn.close()
        return None

def save_lead_data(lead_data):
    """Save lead data to the database"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get values
        name = lead_data.get('name', '')
        email = lead_data.get('email', '')
        company = lead_data.get('company', '')
        phone = lead_data.get('phone', '')
        timestamp = lead_data.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        # Insert into database
        cursor.execute(
            'INSERT INTO leads (name, email, company, phone, timestamp) VALUES (?, ?, ?, ?, ?)',
            (name, email, company, phone, timestamp)
        )
        
        conn.commit()
        conn.close()
        
        logging.info(f"Lead data saved to database for: {email}")
        return True
    except Exception as e:
        logging.error(f"Error saving lead data to database: {e}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        if conn:
            conn.close()
        return False
