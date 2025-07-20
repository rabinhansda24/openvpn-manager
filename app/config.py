"""
Configuration classes for different environments.
"""

import os
from datetime import timedelta

class BaseConfig:
    """Base configuration with common settings."""
    
    # Basic Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    WTF_CSRF_ENABLED = True
    
    # Database settings
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
    
    # Redis settings
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
    
    # Celery settings
    CELERY_BROKER_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
    CELERY_TASK_SERIALIZER = 'json'
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_TIMEZONE = 'UTC'
    CELERY_ENABLE_UTC = True
    
    # JWT settings
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-string'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # Mail settings
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    
    # OpenVPN settings
    OPENVPN_CONFIG_PATH = os.environ.get('OPENVPN_CONFIG_PATH') or '/etc/openvpn'
    OPENVPN_STATUS_LOG = os.environ.get('OPENVPN_STATUS_LOG') or '/var/log/openvpn/openvpn-status.log'
    OPENVPN_LOG_PATH = os.environ.get('OPENVPN_LOG_PATH') or '/var/log/openvpn/openvpn.log'
    
    # Security settings
    SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT') or 'security-salt'
    
    # Rate limiting
    RATELIMIT_STORAGE_URL = os.environ.get('RATE_LIMIT_STORAGE_URL') or 'redis://localhost:6379/1'
    RATELIMIT_DEFAULT = os.environ.get('DEFAULT_RATE_LIMIT') or '100/hour'
    
    # Backup settings
    BACKUP_ENABLED = os.environ.get('BACKUP_ENABLED', 'true').lower() in ['true', 'on', '1']
    BACKUP_RETENTION_DAYS = int(os.environ.get('BACKUP_RETENTION_DAYS') or 30)
    BACKUP_PATH = os.environ.get('BACKUP_PATH') or '/app/backups'
    
    # Monitoring settings
    PROMETHEUS_ENABLED = os.environ.get('PROMETHEUS_ENABLED', 'true').lower() in ['true', 'on', '1']
    PROMETHEUS_PORT = int(os.environ.get('PROMETHEUS_PORT') or 9090)
    
    # Admin credentials
    ADMIN_USER = os.environ.get('ADMIN_USER') or 'admin'
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD') or 'admin123'

class DevelopmentConfig(BaseConfig):
    """Development configuration."""
    DEBUG = True
    FLASK_ENV = 'development'
    WTF_CSRF_ENABLED = False  # Disable CSRF for development
    
    # Use SQLite for development
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or 'sqlite:///dev.db'

class TestingConfig(BaseConfig):
    """Testing configuration."""
    TESTING = True
    DEBUG = True
    WTF_CSRF_ENABLED = False
    
    # Use in-memory SQLite for testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Use separate Redis DB for testing
    REDIS_URL = 'redis://localhost:6379/15'
    CELERY_BROKER_URL = 'redis://localhost:6379/15'
    CELERY_RESULT_BACKEND = 'redis://localhost:6379/15'

class ProductionConfig(BaseConfig):
    """Production configuration."""
    DEBUG = False
    FLASK_ENV = 'production'
    
    # Ensure all security settings are enabled
    WTF_CSRF_ENABLED = True
    
    # Use environment variables for sensitive data
    SECRET_KEY = os.environ.get('SECRET_KEY')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')

class DockerConfig(BaseConfig):
    """Docker-specific configuration."""
    DEBUG = False
    
    # Docker-specific paths
    OPENVPN_CONFIG_PATH = '/etc/openvpn'
    OPENVPN_STATUS_LOG = '/var/log/openvpn/openvpn-status.log'
    OPENVPN_LOG_PATH = '/var/log/openvpn/openvpn.log'
    BACKUP_PATH = '/app/backups'

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'docker': DockerConfig,
    'default': DevelopmentConfig
}
