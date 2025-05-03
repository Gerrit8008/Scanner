from flask import Flask
from jinja2 import ChoiceLoader, FileSystemLoader
import os

def configure_admin(app):
    """Configure admin routes and templates"""
    # Set up multiple template directories
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    
    # Create a ChoiceLoader that looks in multiple places
    app.jinja_loader = ChoiceLoader([
        app.jinja_loader,
        FileSystemLoader(template_dir)
    ])
    
    # Keep the route definitions
    @app.route('/admin')
    def admin_redirect():
        """Redirect to admin dashboard"""
        from flask import redirect, url_for
        return redirect(url_for('admin.dashboard'))
    
    # Add admin login redirect
    @app.route('/admin/login')
    def admin_login_redirect():
        """Redirect to admin login"""
        from flask import redirect, url_for
        return redirect(url_for('auth.login'))
    
    return app
