import os
import logging
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

# Configure the application
class Config:
    """Base configuration class"""
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your_strong_secret_key_here')
    
    # Email configuration
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'mail.privateemail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    SMTP_USER = os.environ.get('SMTP_USER', '')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', '')
    
    # Database configuration
    DB_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'scans.db'))
    
    # Feature flags
    ENABLE_AUTO_EMAIL = os.environ.get('ENABLE_AUTO_EMAIL', 'True') == 'True'
    FULL_SCAN_ENABLED = os.environ.get('FULL_SCAN_ENABLED', 'True') == 'True'
    
    # Rate limiting
    RATE_LIMIT_PER_DAY = int(os.environ.get('RATE_LIMIT_PER_DAY', 200))
    RATE_LIMIT_PER_HOUR = int(os.environ.get('RATE_LIMIT_PER_HOUR', 50))
    
    @staticmethod
    def init_app(app):
        """Initialize the application with this configuration"""
        app.config.from_object(Config)
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(Config.DB_PATH), exist_ok=True)
        
        # Check essential config
        if not Config.SMTP_USER or not Config.SMTP_PASSWORD:
            logging.warning("Email credentials not configured. Email functionality will not work.")
            
        return app

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    
class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    
    @classmethod
    def init_app(cls, app):
        """Additional production-specific initialization"""
        Config.init_app(app)
        
        # Log configuration
        logging.info("Running in PRODUCTION mode")
        
        return app
        
# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

# Get the current configuration
def get_config():
    """Get the current configuration based on environment"""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])
