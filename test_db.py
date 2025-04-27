import os
import sys
import json
import uuid
from datetime import datetime

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the database functions
from db import init_db, save_scan_results, get_scan_results, save_lead_data, DB_PATH

def test_database():
    """Test database operations"""
    print(f"Database path: {DB_PATH}")
    
    # Initialize database
    print("Initializing database...")
    init_db()
    
    # Create test scan data
    scan_id = str(uuid.uuid4())
    print(f"Created test scan ID: {scan_id}")
    
    test_scan = {
        'scan_id': scan_id,
        'timestamp': datetime.now().isoformat(),
        'email': 'test@example.com',
        'target': 'example.com',
        'test_field': 'This is a test scan',
        'recommendations': [
            'Keep software updated',
            'Use strong passwords',
            'Enable two-factor authentication'
        ],
        'risk_assessment': {
            'overall_score': 75,
            'risk_level': 'Medium'
        }
    }
    
    # Save scan results
    print("Saving scan results...")
    saved_id = save_scan_results(test_scan)
    print(f"Saved scan ID: {saved_id}")
    
    if saved_id:
        # Retrieve scan results
        print("Retrieving scan results...")
        retrieved_scan = get_scan_results(saved_id)
        
        if retrieved_scan:
            print("Retrieved scan successfully!")
            print(f"Keys in retrieved scan: {list(retrieved_scan.keys())}")
            print(f"Test field value: {retrieved_scan.get('test_field')}")
        else:
            print("Failed to retrieve scan results!")
    else:
        print("Failed to save scan results!")
    
    # Create test lead data
    test_lead = {
        'name': 'Test User',
        'email': 'test@example.com',
        'company': 'Test Company',
        'phone': '555-1234',
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Save lead data
    print("Saving lead data...")
    lead_id = save_lead_data(test_lead)
    print(f"Saved lead ID: {lead_id}")
    
    return scan_id

if __name__ == "__main__":
    test_scan_id = test_database()
    print("\nTest completed! Use this scan ID for further testing:")
    print(test_scan_id)
