#!/usr/bin/env python3
# direct_auth_fix.py - Direct fix for auth.py

import os
import shutil
import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def fix_auth_py():
    """Make direct changes to auth.py to fix the parameter mismatch"""
    try:
        # Path to auth.py
        auth_py_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'auth.py')
        
        # Create backup
        backup_path = f"{auth_py_path}.bak"
        shutil.copy2(auth_py_path, backup_path)
        logger.info(f"Created backup of auth.py at {backup_path}")
        
        # Read the file
        with open(auth_py_path, 'r') as f:
            content = f.read()
        
        # Look for the authenticate_user call with wrong parameters
        # This regex pattern will look for authenticate_user being called with parameters
        pattern = r'result\s*=\s*authenticate_user\s*\(([^)]*)\)'
        
        match = re.search(pattern, content)
        if match:
            params = match.group(1).strip()
            logger.info(f"Found authenticate_user call with parameters: {params}")
            
            # Fix the call by ensuring it only has username and password
            if ',' in params:
                # More than one parameter
                parts = [p.strip() for p in params.split(',')]
                if len(parts) > 2:
                    # Too many parameters, fix by using only the first two
                    replacement = f"result = authenticate_user({parts[0]}, {parts[1]})"
                    new_content = content.replace(match.group(0), replacement)
                    
                    # Write fixed content
                    with open(auth_py_path, 'w') as f:
                        f.write(new_content)
                    
                    logger.info(f"Fixed authenticate_user call to use only required parameters")
                    return True
            
            logger.info("No changes needed to authenticate_user call")
            return True
        else:
            logger.warning("Could not find authenticate_user call in auth.py")
            return False
    
    except Exception as e:
        logger.error(f"Error fixing auth.py: {e}")
        return False

if __name__ == "__main__":
    fix_auth_py()
    print("Direct fix to auth.py completed")
