# debug_middleware.py
from flask import Flask, session, request, jsonify, g
import time
import traceback
import sqlite3
import os

def register_debug_middleware(app):
    """Register debug middleware with the Flask app"""
    
    # Get database path from app config or use default
    CLIENT_DB_PATH = getattr(app, 'CLIENT_DB_PATH', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db'))
    
    @app.route('/debug/middleware')
    def debug_middleware_route():
        """Debug route to check middleware status"""
        return jsonify({
            "status": "Middleware is working",
            "session": {key: session.get(key) for key in session},
            "request_info": {
                "path": request.path,
                "method": request.method,
                "remote_addr": request.remote_addr
            }
        })
    
    @app.before_request
    def debug_before_request():
        g.request_start_time = time.time()
        g.request_time = lambda: "%.5fs" % (time.time() - g.request_start_time)
        
        # Log the request path, method and session info
        app.logger.debug(f"Request: {request.method} {request.path}")
        app.logger.debug(f"Session: {session}")
        
        # Check for session token and verify it in the database
        if 'session_token' in session:
            try:
                token = session['session_token']
                conn = sqlite3.connect(CLIENT_DB_PATH)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                SELECT s.*, u.username, u.role 
                FROM sessions s 
                JOIN users u ON s.user_id = u.id 
                WHERE s.session_token = ?
                ''', (token,))
                
                db_session = cursor.fetchone()
                
                if db_session:
                    app.logger.debug(f"Valid session found for user: {db_session['username']}, role: {db_session['role']}")
                else:
                    app.logger.warning(f"Session token in cookie not found in database: {token}")
                
                conn.close()
            except Exception as e:
                app.logger.error(f"Error verifying session: {str(e)}")
                app.logger.error(traceback.format_exc())
    
    @app.after_request
    def debug_after_request(response):
        # Log response status and time
        app.logger.debug(f"Response: {response.status_code} in {g.request_time()}")
        return response
    
    @app.errorhandler(500)
    def handle_server_error(e):
        app.logger.error(f"Server error: {str(e)}")
        app.logger.error(traceback.format_exc())
        
        # In development mode, return the traceback
        if app.debug:
            return f"""
            <h1>500 Server Error</h1>
            <pre>{traceback.format_exc()}</pre>
            """, 500
        
        return "Server error", 500
