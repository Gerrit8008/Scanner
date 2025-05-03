# Enhanced api.py
import os
import json
import uuid
import shutil
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from client_db import save_client, get_client_by_api_key, get_client_by_id, log_scan
from scanner_template import generate_scanner, update_scanner
from datetime import datetime

# Create blueprint for API routes
api_bp = Blueprint('api', __name__)

# Directory for file uploads
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Middleware to check API key
def api_key_required(f):
    def decorated_function(*args, **kwargs):
        # Check for API key in headers
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({
                'status': 'error',
                'message': 'Missing API key'
            }), 401
        
        # Get client by API key
        client = get_client_by_api_key(api_key)
        
        if not client:
            return jsonify({
                'status': 'error',
                'message': 'Invalid API key'
            }), 401
