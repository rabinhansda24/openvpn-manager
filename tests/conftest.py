"""
Test configuration for OpenVPN Manager.
"""

import os
import tempfile
from app.config import TestingConfig

class TestConfig(TestingConfig):
    """Extended test configuration."""
    
    # Use temporary database for tests
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False
    
    # Use test Redis instance
    REDIS_URL = 'redis://localhost:6379/15'
    
    # Disable background tasks
    CELERY_TASK_ALWAYS_EAGER = True
    CELERY_TASK_EAGER_PROPAGATES = True
    
    # Test file paths
    OPENVPN_CONFIG_PATH = tempfile.mkdtemp()
    BACKUP_PATH = tempfile.mkdtemp()
    
    # Test credentials
    ADMIN_USER = 'testadmin'
    ADMIN_PASSWORD = 'testpassword123'

# Test data
TEST_CLIENT_DATA = {
    'name': 'testclient',
    'email': 'test@example.com',
    'description': 'Test client for unit tests'
}

TEST_USER_DATA = {
    'username': 'testuser',
    'email': 'testuser@example.com',
    'password': 'testpassword123'
}
