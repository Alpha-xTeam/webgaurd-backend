import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    # Flask configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'

    # Supabase configuration
    SUPABASE_URL = os.getenv('SUPABASE_URL')
    SUPABASE_KEY = os.getenv('SUPABASE_KEY')
    SUPABASE_SERVICE_ROLE_KEY = os.getenv('SUPABASE_SERVICE_ROLE_KEY')

    # Database configuration (for local PostgreSQL if needed)
    DATABASE_URL = os.getenv('DATABASE_URL')

    # File upload configuration
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'rar'}

    # Security configuration
    BCRYPT_ROUNDS = 12

    # Logging configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    # CORS configuration
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:3000').split(',')

    # SIEM/ELK configuration (for future integration)
    ELASTICSEARCH_HOST = os.getenv('ELASTICSEARCH_HOST', 'localhost')
    ELASTICSEARCH_PORT = int(os.getenv('ELASTICSEARCH_PORT', 9200))
    ELASTICSEARCH_INDEX = os.getenv('ELASTICSEARCH_INDEX', 'webguard-ir-logs')

    # Logstash configuration
    LOGSTASH_HOST = os.getenv('LOGSTASH_HOST', 'localhost')
    LOGSTASH_PORT = int(os.getenv('LOGSTASH_PORT', 5044))

    # Email configuration (for notifications)
    SMTP_SERVER = os.getenv('SMTP_SERVER')
    SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
    SMTP_USERNAME = os.getenv('SMTP_USERNAME')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')

    # Admin configuration
    ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'admin@webguard.ir')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')

    # Application configuration
    APP_NAME = 'WebGuard-IR'
    APP_VERSION = '1.0.0'
    APP_DESCRIPTION = 'Educational Web Security & Incident Response Platform'

    # Session configuration
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = False
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour

    # Rate limiting (basic)
    RATE_LIMIT_REQUESTS = int(os.getenv('RATE_LIMIT_REQUESTS', 100))
    RATE_LIMIT_WINDOW = int(os.getenv('RATE_LIMIT_WINDOW', 60))  # seconds

    # Honeypot configuration
    HONEYPOT_ENABLED = os.getenv('HONEYPOT_ENABLED', 'True').lower() == 'true'
    HONEYPOT_ENDPOINTS = ['/admin-secret.php', '/.env', '/wp-admin', '/phpmyadmin']

    # Vulnerability testing configuration
    VULNERABLE_MODE = os.getenv('VULNERABLE_MODE', 'True').lower() == 'true'  # Enable/disable vulnerable endpoints
    LOG_ALL_REQUESTS = os.getenv('LOG_ALL_REQUESTS', 'True').lower() == 'true'

class DevelopmentConfig(Config):
    DEBUG = True
    LOG_LEVEL = 'DEBUG'

class ProductionConfig(Config):
    DEBUG = False
    LOG_LEVEL = 'WARNING'

class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    LOG_LEVEL = 'DEBUG'
    # Use in-memory database for testing
    DATABASE_URL = 'sqlite:///:memory:'

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config(config_name=None):
    """Get configuration class based on environment"""
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'development')

    return config.get(config_name, config['default'])