# In setup_admin.py
def configure_admin(app):
    """Configure admin routes and templates"""
    # Remove or comment out this problematic code
    # app.jinja_loader = app.jinja_loader.add_loader(...)
    
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
