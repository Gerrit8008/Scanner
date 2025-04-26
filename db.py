# db.py - Database operations for the security scanner
import sqlite3
import os
import json
import logging
import traceback
from datetime import datetime

# Set up database path in /tmp for Render compatibility
DB_PATH = '/tmp/security_scanner.db'

def get_db_connection():
    """Create a connection to the SQLite database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row  # Return rows as dictionaries
        return conn
    except Exception as e:
        logging.error(f"Database connection error: {e}")
        logging.debug(traceback.format_exc())
        return None

def init_db():
    """Initialize the database with required tables"""
    logging.info(f"Initializing database at {DB_PATH}...")
    
    # Ensure the directory exists
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            logging.error("Could not initialize database - connection failed")
            return False
            
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
        logging.info("Database initialized successfully")
        return True
    except Exception as e:
        logging.error(f"Error initializing database: {e}")
        logging.debug(traceback.format_exc())
        return False
    finally:
        if conn:
            conn.close()

def save_scan_results(scan_results):
    """Save scan results to the database
    
    Args:
        scan_results (dict): The scan results to save
        
    Returns:
        str: The scan_id if successful, None if failed
    """
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            logging.error("Could not save scan results - database connection failed")
            return None
            
        cursor = conn.cursor()
        
        # Get required values from scan_results
        scan_id = scan_results.get('scan_id')
        if not scan_id:
            logging.error("Could not save scan results - missing scan_id")
            return None
            
        timestamp = scan_results.get('timestamp', datetime.now().isoformat())
        target = scan_results.get('target', '')
        email = scan_results.get('email', '')
        
        # Convert full results to JSON string
        results_json = json.dumps(scan_results)
        
        # Get HTML report if available
        html_report = scan_results.get('html_report', '')
        
        # Insert into database
        cursor.execute(
            'INSERT OR REPLACE INTO scans (scan_id, timestamp, target, email, results, html_report) VALUES (?, ?, ?, ?, ?, ?)',
            (scan_id, timestamp, target, email, results_json, html_report)
        )
        
        conn.commit()
        
        # Verify the row was inserted
        cursor.execute('SELECT 1 FROM scans WHERE scan_id = ?', (scan_id,))
        result = cursor.fetchone()
        
        if result:
            logging.info(f"Scan results saved to database with ID: {scan_id}")
            return scan_id
        else:
            logging.error(f"Failed to save scan results - verification failed")
            return None
    except Exception as e:
        logging.error(f"Error saving scan results to database: {e}")
        logging.debug(traceback.format_exc())
        return None
    finally:
        if conn:
            conn.close()

def get_scan_results(scan_id):
    """Retrieve scan results from the database
    
    Args:
        scan_id (str): The scan ID to retrieve
        
    Returns:
        dict: The scan results or None if not found
    """
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            logging.error("Could not retrieve scan results - database connection failed")
            return None
            
        cursor = conn.cursor()
        
        cursor.execute('SELECT results FROM scans WHERE scan_id = ?', (scan_id,))
        row = cursor.fetchone()
        
        if row and row['results']:
            # Parse the JSON string back to a dictionary
            try:
                scan_results = json.loads(row['results'])
                logging.info(f"Retrieved scan results for ID: {scan_id}")
                return scan_results
            except json.JSONDecodeError as json_err:
                logging.error(f"Error decoding JSON for scan {scan_id}: {json_err}")
                return None
        else:
            logging.warning(f"No scan results found for ID: {scan_id}")
            return None
    except Exception as e:
        logging.error(f"Error retrieving scan results from database: {e}")
        logging.debug(traceback.format_exc())
        return None
    finally:
        if conn:
            conn.close()

def save_lead_data(lead_data):
    """Save lead data to the database
    
    Args:
        lead_data (dict): Lead information
        
    Returns:
        bool: True if successful, False if failed
    """
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            logging.error("Could not save lead data - database connection failed")
            return False
            
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
        
        logging.info(f"Lead data saved to database for: {email}")
        return True
    except Exception as e:
        logging.error(f"Error saving lead data to database: {e}")
        logging.debug(traceback.format_exc())
        return False
    finally:
        if conn:
            conn.close()

def get_all_scans(limit=50):
    """Get a list of all scans, newest first
    
    Args:
        limit (int): Maximum number of scans to return
        
    Returns:
        list: List of scan summary dictionaries
    """
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            logging.error("Could not retrieve scan list - database connection failed")
            return []
            
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT scan_id, timestamp, target, email FROM scans ORDER BY timestamp DESC LIMIT ?', 
            (limit,)
        )
        rows = cursor.fetchall()
        
        scans = [dict(row) for row in rows]
        logging.info(f"Retrieved {len(scans)} scans from database")
        return scans
    except Exception as e:
        logging.error(f"Error retrieving scan list from database: {e}")
        logging.debug(traceback.format_exc())
        return []
    finally:
        if conn:
            conn.close()
