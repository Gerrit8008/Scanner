import os
import logging
from app import app

# Set up logging configuration
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

if __name__ == "__main__":
    # Get port from environment variable or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Use 0.0.0.0 to make the app accessible from any IP
    app.run(host='0.0.0.0', port=port)
