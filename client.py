# client.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from client_db import (
    verify_session, get_client_by_user_id, get_deployed_scanners_by_client_id,
    get_scan_history_by_client_id, regenerate_api_key
)

# Define upload folder
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
            return redirect(url_for('auth.login'))
        
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
    # Get client info for this user
    user_client = get_client_by_user_id(user['user_id'])
    
    if not user_client:
        flash('No client account found for this user', 'danger')
        return redirect(url_for('auth.login'))
    
    # Get client's scanners
    scanners = get_deployed_scanners_by_client_id(user_client['id'])
    
    # Get scan history
    scan_history = get_scan_history_by_client_id(user_client['id'], limit=5)
    
    # Count total scans
    total_scans = len(get_scan_history_by_client_id(user_client['id'], limit=None))
    
    return render_template(
        'client/client-dashboard.html',
        user=user,
        user_client=user_client,
        scanners=scanners,
        scan_history=scan_history,
        total_scans=total_scans
    )

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
        scanners=scanners_data['scanners'],
        pagination=scanners_data['pagination'],
        filters=filters
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
    
    if result['status'] == 'success':
        return jsonify({
            'status': 'success',
            'message': 'API key regenerated successfully',
            'api_key': result['api_key']
        })
    else:
        return jsonify({
            'status': 'error',
            'message': result.get('message', 'Failed to regenerate API key')
        }), 400

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

@client_bp.route('/scanners/<int:scanner_id>/edit', methods=['GET', 'POST'])
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
    
    if request.method == 'POST':
        # Extract form data
        scanner_data = {
            'scanner_name': request.form.get('scanner_name'),
            'primary_color': request.form.get('primary_color'),
            'secondary_color': request.form.get('secondary_color'),
            'email_subject': request.form.get('email_subject'),
            'email_intro': request.form.get('email_intro'),
            'default_scans': request.form.getlist('default_scans[]')
        }
        
        # Handle file uploads
        if 'logo' in request.files and request.files['logo'].filename:
            logo_file = request.files['logo']
            logo_filename = secure_filename(f"{user_client['id']}_{logo_file.filename}")
            logo_path = os.path.join(UPLOAD_FOLDER, logo_filename)
            logo_file.save(logo_path)
            scanner_data['logo_path'] = logo_path
        
        if 'favicon' in request.files and request.files['favicon'].filename:
            favicon_file = request.files['favicon']
            # Rest of the code to handle the favicon
