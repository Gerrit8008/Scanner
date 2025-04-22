import os
import logging
from flask import Flask, render_template, request, jsonify

# Set up detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create a minimal Flask application for testing
app = Flask(__name__)

# Basic route with error handling
@app.route('/')
def index():
    try:
        logger.debug("Attempting to render index.html")
        # Check if templates directory exists
        template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
        if os.path.exists(template_dir):
            logger.debug(f"Templates directory exists at {template_dir}")
            if os.path.exists(os.path.join(template_dir, 'index.html')):
                logger.debug("index.html exists in templates directory")
            else:
                logger.error("index.html not found in templates directory")
                return "Error: index.html not found in templates directory", 500
        else:
            logger.error(f"Templates directory not found at {template_dir}")
            return "Error: Templates directory not found", 500
            
        return render_template('index.html')
    except Exception as e:
        logger.exception(f"Error in index route: {str(e)}")
        return f"An error occurred: {str(e)}", 500

# Health check endpoint
@app.route('/health')
def health():
    return jsonify({"status": "ok"}), 200

# Error handler for 500 errors
@app.errorhandler(500)
def server_error(e):
    logger.exception(f"Server error: {str(e)}")
    return f"Server error: {str(e)}", 500

if __name__ == '__main__':
    # Print some debug info
    logger.debug(f"Current working directory: {os.getcwd()}")
    logger.debug(f"Directory contents: {os.listdir('.')}")
    
    # Try to list templates directory if it exists
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    if os.path.exists(template_dir):
        logger.debug(f"Templates directory contents: {os.listdir(template_dir)}")
    
    # Start Flask in debug mode
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
