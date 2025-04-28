from flask import Blueprint, request, jsonify
import logging
from datetime import datetime
from .email_handler import send_email_report
from .models import Scan, Lead

# Create a Blueprint for API routes
api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/email_report', methods=['POST'])
def email_report():
    """
    API endpoint to email a security scan report to a user.
    
    Expected POST parameters:
    - scan_id: The ID of the scan to send
    - email: The email address to send the report to
    
    Returns:
        JSON response with status and message
    """
    try:
        # Get POST data
        scan_id = request.form.get('scan_id')
        email = request.form.get('email')
        
        if not scan_id or not email:
            return jsonify({
                'status': 'error',
                'message': 'Missing required parameters (scan_id or email)'
            }), 400
        
        logging.debug(f"Email report requested for scan ID: {scan_id} to {email}")
        
        # Get the scan data from database
        scan = Scan.query.filter_by(id=scan_id).first()
        
        if not scan:
            return jsonify({
                'status': 'error',
                'message': 'Scan not found'
            }), 404
        
        # Create lead data
        lead_data = {
            'name': request.form.get('name', 'User'),
            'email': email,
            'company': request.form.get('company', 'Unknown Company'),
            'phone': request.form.get('phone', ''),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Store the lead in database (if you want to track leads)
        lead = Lead(
            name=lead_data['name'],
            email=lead_data['email'],
            company=lead_data['company'],
            phone=lead_data['phone'],
            scan_id=scan_id
        )
        
        # Get the HTML report - this depends on how you're storing scan results
        # This example assumes you have the HTML in the scan object or can render it
        from flask import render_template
        scan_result = render_template('results.html', scan=scan.data)
        
        # Send the email
        email_sent = send_email_report(lead_data, scan_result)
        
        if email_sent:
            # Save the lead to database
            from .extensions import db
            db.session.add(lead)
            db.session.commit()
            
            return jsonify({
                'status': 'success',
                'message': f'Report sent to {email}'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to send email'
            }), 500
            
    except Exception as e:
        logging.error(f"Error sending email report: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# Function to register the blueprint with your Flask app
def register_api(app):
    app.register_blueprint(api_bp)
