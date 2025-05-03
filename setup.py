# setup.py
import os
import sys
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"setup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler()
    ]
)

# Add the current directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the required functions
from client_db import init_client_db, create_user, authenticate_user

def setup_database():
    """Initialize the database and create an admin user"""
    logging.info("Initializing database...")
    init_result = init_client_db()
    
    if init_result.get("status") != "success":
        logging.error("Failed to initialize database")
        return False
    
    logging.info("Creating admin user...")
    user_result = create_user('test_admin', 'admin@example.com', 'SecurePass123', 'admin')
    
    if user_result.get("status") != "success":
        logging.error(f"Failed to create admin user: {user_result.get('message', 'Unknown error')}")
        return False
    
    logging.info("Setup completed successfully")
    return True

if __name__ == "__main__":
    setup_database()
