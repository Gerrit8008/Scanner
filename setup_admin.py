def configure_admin(app):
    """Configure admin routes and templates"""
    # Add template folder for admin templates
    app.jinja_loader = app.jinja_loader.add_loader(
        app.jinja_environment.loader.choice_loader([
            app.jinja_environment.loader.file_system_loader('templates'),
            app.jinja_environment.loader.file_system_loader('templates_admin')
        ])
    )
    
    # Add admin redirect route
    @app.route('/admin')
    def admin_redirect():
        """Redirect to admin dashboard"""
        return redirect(url_for('admin.dashboard'))
    
    # Add admin login redirect
    @app.route('/admin/login')
    def admin_login_redirect():
        """Redirect to admin login"""
        return redirect(url_for('auth.login'))
    
    return app
