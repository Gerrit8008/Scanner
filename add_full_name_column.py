#!/usr/bin/env python3
# add_full_name_column.py - Script to add the full_name column to the users table

import os
import sqlite3
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def add_full_name_column():
    """Add full_name column to users table if it doesn't exist"""
    try:
        # Connect to the database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Check if the column already exists
        cursor.execute("PRAGMA table_info(users)")
        columns = cursor.fetchall()
        column_names = [column[1] for column in columns]
        
        if 'full_name' not in column_names:
            logging.info("Adding 'full_name' column to users table...")
            cursor.execute("ALTER TABLE users ADD COLUMN full_name TEXT")
            conn.commit()
            logging.info("Column added successfully!")
        else:
            logging.info("The 'full_name' column already exists in the users table")
        
        # Verify the column exists
        cursor.execute("PRAGMA table_info(users)")
        columns = cursor.fetchall()
        column_names = [column[1] for column in columns]
        
        if 'full_name' in column_names:
            logging.info("Verification successful: 'full_name' column exists in users table")
        else:
            logging.error("Verification failed: 'full_name' column was not added properly")
        
        conn.close()
        return True
    except Exception as e:
        logging.error(f"Error adding full_name column: {e}")
        return False

if __name__ == "__main__":
    if add_full_name_column():
        print("Full_name column added successfully to users table!")
    else:
        print("Failed to add full_name column. Check the logs for details.")
