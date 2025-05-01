# In db.py
import os
import sqlite3
import json
import logging
import traceback
from datetime import datetime

# Define database path
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'security_scanner.db')
# For debugging, print the path
print(f"Database path: {DB_PATH}")

def init_db():
    """Initialize the database with required tables"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Create scans table if not exists
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            timestamp TEXT,
            email TEXT,
            target TEXT,
            results TEXT,
            html_report TEXT
        )
        ''')
        
        # Create leads table if not exists
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS leads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT,
            company TEXT,
            phone TEXT,
            timestamp TEXT
        )
        ''')
        
        conn.commit()
        conn.close()
        logging.info(f"Database initialized at {DB_PATH}")
        return True
    except Exception as e:
        logging.error(f"Database initialization error: {e}")
        logging.debug(traceback.format_exc())
        return False

def save_scan_results(scan_results):
    """Save scan results to database"""
    try:
        # Ensure we have a scan_id
        scan_id = scan_results.get('scan_id')
        if not scan_id:
            logging.error("Cannot save scan results: No scan_id provided")
            return None
        
        # Extract key fields for the main record
        timestamp = scan_results.get('timestamp', datetime.now().isoformat())
        email = scan_results.get('email', '')
        target = scan_results.get('target', '')
        
        # Get HTML report - prioritize the complete version
        html_report = scan_results.get('complete_html_report', scan_results.get('html_report', ''))
        
        # Convert the rest to JSON - make a copy to avoid modifying original
        results_copy = scan_results.copy()
        
        # Remove large HTML fields to avoid duplicate storage
        if 'complete_html_report' in results_copy:
            del results_copy['complete_html_report']
        if 'html_report' in results_copy:
            del results_copy['html_report']
            
        # Convert to JSON
        results_json = json.dumps(results_copy, default=str)
        
        # Connect to database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Insert or replace the record
        cursor.execute('''
        INSERT OR REPLACE INTO scans (id, timestamp, email, target, results, html_report)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (scan_id, timestamp, email, target, results_json, html_report))
        
        conn.commit()
        conn.close()
        
        logging.info(f"Scan results saved to database with ID: {scan_id}")
        return scan_id
    except Exception as e:
        logging.error(f"Error saving scan results to database: {e}")
        logging.debug(traceback.format_exc())
        return None
def get_scan_results(scan_id):
    """Retrieve scan results from database"""
    try:
        if not scan_id:
            logging.error("Cannot retrieve scan results: No scan_id provided")
            return None
        
        # Connect to database
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row  # To access columns by name
        cursor = conn.cursor()
        
        # Query for the scan
        cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
        row = cursor.fetchone()
        
        if not row:
            logging.warning(f"No scan results found for ID: {scan_id}")
            conn.close()
            return None
        
        # Parse the JSON results
        results_json = row['results']
        scan_results = json.loads(results_json)
        
        # Add the HTML report back (if available)
        if row['html_report']:
            scan_results['html_report'] = row['html_report']
        
        conn.close()
        logging.info(f"Retrieved scan results for ID: {scan_id}")
        return scan_results
    except Exception as e:
        logging.error(f"Error retrieving scan results from database: {e}")
        logging.debug(traceback.format_exc())
        return None

def save_lead_data(lead_data):
    """Save lead data to database"""
    try:
        # Extract fields
        name = lead_data.get('name', '')
        email = lead_data.get('email', '')
        company = lead_data.get('company', '')
        phone = lead_data.get('phone', '')
        timestamp = lead_data.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        # Connect to database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Insert the record
        cursor.execute('''
        INSERT INTO leads (name, email, company, phone, timestamp)
        VALUES (?, ?, ?, ?, ?)
        ''', (name, email, company, phone, timestamp))
        
        # Get the ID of the inserted record
        lead_id = cursor.lastrowid
        
        conn.commit()
        conn.close()
        
        logging.info(f"Lead data saved to database with ID: {lead_id}")
        return lead_id
    except Exception as e:
        logging.error(f"Error saving lead data to database: {e}")
        logging.debug(traceback.format_exc())
        return None
