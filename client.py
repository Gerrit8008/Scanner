# client.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from client_db import (
    verify_session, get_client_by_user_id, get_deployed_scanners_by_client_id,
    get_scan_history_by_client_id, regenerate_api_key, get_scanner_by_id
)
from werkzeug.utils import secure_filename
import os
import logging
from datetime import datetime

# Define upload folder
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

client_bp = Blueprint('client', __name__, url_prefix='/client')

# Middleware to require client login
def client_required(f):
    def decorated_function(*args, **kwargs):
        session_token = session.get('session_token')
        
        if not session_token:
            return redirect(url_for('auth.login', next=request.url))
        
        result = verify_session(session_token)
        
        if result['status'] != 'success':
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('auth.login', next=request.url))
        
        # Add user info to kwargs
        kwargs['user'] = result['user']
        return f(*args, **kwargs)
    
    # Preserve function metadata
    decorated_function.__name__ = f.__name__
    decorated_function.__doc__ = f.__doc__
    return decorated_function

@client_bp.route('/dashboard')
@client_required
def dashboard(user):
    """Client dashboard showing scanner overview"""
    try:
        # Get client info for this user
        user_client = get_client_by_user_id(user['user_id'])
        
        if not user_client:
            flash('No client account found for this user', 'danger')
            return redirect(url_for('auth.login'))
        
        # Get client's scanners
        scanners_data = get_deployed_scanners_by_client_id(user_client['id'])
        scanners = scanners_data.get('scanners', [])
        
        # Get scan history
        scan_history = get_scan_history_by_client_id(user_client['id'], limit=5)
        
        # Process scan history to add scanner names
        for scan in scan_history:
            # Find the scanner name for this scan
            for scanner in scanners:
                if scanner.get('id') == scan.get('scanner_id'):
                    scan['scanner_name'] = scanner.get('scanner_name', 'Default Scanner')
                    break
            else:
                scan['scanner_name'] = 'Unknown Scanner'
        
        # Count total scans
        total_scans = len(get_scan_history_by_client_id(user_client['id']))
        
        # Render the dashboard template
        return render_template(
            'client/client-dashboard.html',
            user=user,
            user_client=user_client,
            scanners=scanners,
            scan_history=scan_history,
            total_scans=total_scans
        )
    except Exception as e:
        logging.error(f"Error in client dashboard: {str(e)}")
        flash(f"An error occurred: {str(e)}", 'danger')
        return redirect(url_for('auth.login'))

@client_bp.route('/scanners')
@client_required
def scanners(user):
    """Client's scanners list"""
    # Get client info for this user
    user_client = get_client_by_user_id(user['user_id'])
    
    if not user_client:
        flash('No client account found for this user', 'danger')
        return redirect(url_for('auth.login'))
    
    # Get client's scanners with pagination
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Get filter parameters
    filters = {}
    if 'status' in request.args:
        filters['status'] = request.args.get('status')
    if 'search' in request.args:
        filters['search'] = request.args.get('search')
    
    # Get scanners for this client
    scanners_data = get_deployed_scanners_by_client_id(
        user_client['id'], page=page, per_page=per_page, filters=filters
    )
    
    return render_template(
        'client/scanners.html',
        user=user,
        user_client=user_client,
        scanners=scanners_data.get('scanners', []),
        pagination=scanners_data.get('pagination', {}),
        filters=filters
    )

@client_bp.route('/scanners/<int:scanner_id>/view')
@client_required
def scanner_view(user, scanner_id):
    """View scanner page"""
    # Get client info for this user
    user_client = get_client_by_user_id(user['user_id'])
    
    if not user_client:
        flash('No client account found for this user', 'danger')
        return redirect(url_for('auth.login'))
    
    # Get scanner details
    scanner = get_scanner_by_id(scanner_id)
    
    if not scanner or scanner['client_id'] != user_client['id']:
        flash('Scanner not found or not authorized', 'danger')
        return redirect(url_for('client.scanners'))
    
    # Render scanner view template
    return render_template(
        'client/scanner-view.html',
        user=user,
        user_client=user_client,
        scanner=scanner
    )

@client_bp.route('/scanners/<int:scanner_id>/edit')
@client_required
def scanner_edit(user, scanner_id):
    """Edit scanner page"""
    # Get client info for this user
    user_client = get_client_by_user_id(user['user_id'])
    
    if not user_client:
        flash('No client account found for this user', 'danger')
        return redirect(url_for('auth.login'))
    
    # Get scanner details
    scanner = get_scanner_by_id(scanner_id)
    
    if not scanner or scanner['client_id'] != user_client['id']:
        flash('Scanner not found or not authorized', 'danger')
        return redirect(url_for('client.scanners'))
    
    # Render scanner edit template
    return render_template(
        'client/scanner-edit.html',
        user=user,
        user_client=user_client,
        scanner=scanner
    )

@client_bp.route('/scanners/<int:scanner_id>/stats')
@client_required
def scanner_stats(user, scanner_id):
    """View scanner statistics"""
    # Get client info for this user
    user_client = get_client_by_user_id(user['user_id'])
    
    if not user_client:
        flash('No client account found for this user', 'danger')
        return redirect(url_for('auth.login'))
    
    # Get scanner details
    scanner = get_scanner_by_id(scanner_id)
    
    if not scanner or scanner['client_id'] != user_client['id']:
        flash('Scanner not found or not authorized', 'danger')
        return redirect(url_for('client.scanners'))
    
    # Get scan history for this scanner
    from client_db import get_scanner_scan_history
    scan_history = get_scanner_scan_history(scanner_id)
    
    # Render scanner stats template
    return render_template(
        'client/scanner-stats.html',
        user=user,
        user_client=user_client,
        scanner=scanner,
        scan_history=scan_history
    )

@client_bp.route('/scanners/<int:scanner_id>/regenerate-api-key', methods=['POST'])
@client_required
def regenerate_scanner_api_key(user, scanner_id):
    """Regenerate API key for a client's scanner"""
    # Get client info for this user
    user_client = get_client_by_user_id(user['user_id'])
    
    if not user_client:
        return jsonify({
            'status': 'error',
            'message': 'No client account found for this user'
        }), 401
    
    # Verify this scanner belongs to the client
    scanner = get_scanner_by_id(scanner_id)
    
    if not scanner or scanner['client_id'] != user_client['id']:
        return jsonify({
            'status': 'error',
            'message': 'Scanner not found or not authorized'
        }), 404
    
    # Regenerate the API key
    result = regenerate_api_key(user_client['id'])
    
    return jsonify(result)

@client_bp.route('/reports')
@client_required
def reports(user):
    """View scan reports page"""
    # Get client info for this user
    user_client = get_client_by_user_id(user['user_id'])
    
    if not user_client:
        flash('No client account found for this user', 'danger')
        return redirect(url_for('auth.login'))
    
    # Get pagination
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Get scan history with pagination
    from client_db import get_scan_history
    scan_history_data = get_scan_history(user_client['id'], page, per_page)
    
    # Render reports template
    return render_template(
        'client/reports.html',
        user=user,
        user_client=user_client,
        scans=scan_history_data.get('scans', []),
        pagination=scan_history_data.get('pagination', {})
    )

@client_bp.route('/reports/<scan_id>')
@client_required
def report_details(user, scan_id):
    """View report details"""
    # Get client info
    user_client = get_client_by_user_id(user['user_id'])
    
    if not user_client:
        flash('No client account found for this user', 'danger')
        return redirect(url_for('auth.login'))
    
    # Get scan details
    from client_db import get_scan_by_id
    scan = get_scan_by_id(scan_id)
    
    if not scan or scan['client_id'] != user_client['id']:
        flash('Report not found or not authorized', 'danger')
        return redirect(url_for('client.reports'))
    
    # Get report HTML
    report_html = None
    if scan.get('report_path') and os.path.exists(scan['report_path']):
        try:
            with open(scan['report_path'], 'r') as f:
                report_html = f.read()
        except Exception as e:
            logging.error(f"Error reading report file: {e}")
            flash('Error loading report content', 'danger')
    
    # Render report details template
    return render_template(
        'client/report-details.html',
        user=user,
        user_client=user_client,
        scan=scan,
        report_html=report_html
    )

@client_bp.route('/settings')
@client_required
def settings(user):
    """User settings page"""
    # Get client info
    user_client = get_client_by_user_id(user['user_id'])
    
    if not user_client:
        flash('No client account found for this user', 'danger')
        return redirect(url_for('auth.login'))
    
    # Render settings template
    return render_template(
        'client/settings.html',
        user=user,
        user_client=user_client
    )

@client_bp.route('/profile/update', methods=['POST'])
@client_required
def update_profile(user):
    """Update user profile"""
    # Get client info
    user_client = get_client_by_user_id(user['user_id'])
    
    if not user_client:
        flash('No client account found for this user', 'danger')
        return redirect(url_for('auth.login'))
    
    # Get form data
    client_data = {
        'business_name': request.form.get('business_name'),
        'business_domain': request.form.get('business_domain'),
        'contact_email': request.form.get('contact_email'),
        'contact_phone': request.form.get('contact_phone')
    }
    
    # Update client info
    from client_db import update_client
    result = update_client(user_client['id'], client_data, user['user_id'])
    
    if result['status'] == 'success':
        flash('Profile updated successfully', 'success')
    else:
        flash(f'Error updating profile: {result.get("message", "Unknown error")}', 'danger')
    
    return redirect(url_for('client.settings'))
