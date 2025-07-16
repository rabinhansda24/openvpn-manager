"""
Tests for database models.
"""

import pytest
from datetime import datetime, timedelta
from app import create_app, db
from app.models.user import User
from app.models.client import VPNClient
from tests.conftest import TestConfig, TEST_USER_DATA

@pytest.fixture
def app():
    """Create and configure a test app."""
    app = create_app('testing')
    app.config.from_object(TestConfig)
    
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()

class TestUserModel:
    """Test User model functionality."""
    
    def test_create_user(self, app):
        """Test creating a new user."""
        with app.app_context():
            user = User(
                username=TEST_USER_DATA['username'],
                email=TEST_USER_DATA['email']
            )
            user.set_password(TEST_USER_DATA['password'])
            
            db.session.add(user)
            db.session.commit()
            
            assert user.id is not None
            assert user.username == TEST_USER_DATA['username']
            assert user.email == TEST_USER_DATA['email']
            assert user.is_admin == False
            assert user.is_active == True
            assert user.created_at is not None
    
    def test_password_hashing(self, app):
        """Test password hashing and verification."""
        with app.app_context():
            user = User(username='testuser', email='test@example.com')
            password = 'testpassword123'
            
            user.set_password(password)
            
            # Password should be hashed
            assert user.password_hash != password
            assert len(user.password_hash) > 50  # Bcrypt hash length
            
            # Should be able to verify correct password
            assert user.check_password(password) == True
            
            # Should not verify incorrect password
            assert user.check_password('wrongpassword') == False
    
    def test_2fa_setup(self, app):
        """Test 2FA functionality."""
        with app.app_context():
            user = User(username='testuser', email='test@example.com')
            
            # Generate TOTP secret
            secret = user.generate_totp_secret()
            assert secret is not None
            assert len(secret) == 32  # Base32 encoded secret
            assert user.totp_secret == secret
            
            # Generate QR code
            qr_code = user.generate_qr_code()
            assert qr_code is not None
            assert isinstance(qr_code, str)
            
            # Get TOTP URI
            uri = user.get_totp_uri()
            assert 'otpauth://totp/' in uri
            assert user.username in uri
    
    def test_login_tracking(self, app):
        """Test login attempt tracking."""
        with app.app_context():
            user = User(username='testuser', email='test@example.com')
            db.session.add(user)
            db.session.commit()
            
            # Record successful login
            user.record_login()
            assert user.last_login is not None
            assert user.last_seen is not None
            assert user.failed_login_attempts == 0
            
            # Record failed login
            user.record_failed_login()
            assert user.failed_login_attempts == 1
            assert user.last_failed_login is not None
            
            # Another failed login
            user.record_failed_login()
            assert user.failed_login_attempts == 2
            
            # Successful login should reset failed attempts
            user.record_login()
            assert user.failed_login_attempts == 0

class TestVPNClientModel:
    """Test VPNClient model functionality."""
    
    def test_create_client(self, app):
        """Test creating a new VPN client."""
        with app.app_context():
            client = VPNClient(
                name='testclient',
                email='client@example.com',
                description='Test client'
            )
            
            db.session.add(client)
            db.session.commit()
            
            assert client.id is not None
            assert client.client_id is not None  # UUID generated
            assert client.name == 'testclient'
            assert client.email == 'client@example.com'
            assert client.is_active == True
            assert client.is_revoked == False
            assert client.created_at is not None
            assert client.cert_expires_at is not None
    
    def test_certificate_expiry(self, app):
        """Test certificate expiry functionality."""
        with app.app_context():
            client = VPNClient(name='testclient')
            
            # Set expiry to future date
            future_date = datetime.utcnow() + timedelta(days=60)
            client.cert_expires_at = future_date
            
            assert client.is_certificate_expired == False
            assert client.days_until_expiry == 60
            assert client.is_expiring_soon == False  # Default 30 days
            
            # Set expiry to past date
            past_date = datetime.utcnow() - timedelta(days=1)
            client.cert_expires_at = past_date
            
            assert client.is_certificate_expired == True
            assert client.days_until_expiry == 0
            
            # Set expiry to soon
            soon_date = datetime.utcnow() + timedelta(days=15)
            client.cert_expires_at = soon_date
            
            assert client.is_certificate_expired == False
            assert client.is_expiring_soon == True
            assert client.days_until_expiry == 15
    
    def test_client_revocation(self, app):
        """Test client revocation functionality."""
        with app.app_context():
            client = VPNClient(name='testclient')
            
            assert client.is_revoked == False
            assert client.is_active == True
            assert client.revoked_at is None
            
            # Revoke client
            client.revoke()
            
            assert client.is_revoked == True
            assert client.is_active == False
            assert client.revoked_at is not None
    
    def test_usage_statistics(self, app):
        """Test usage statistics functionality."""
        with app.app_context():
            client = VPNClient(name='testclient')
            
            # Initial values
            assert client.total_bytes_sent == 0
            assert client.total_bytes_received == 0
            assert client.total_connection_time == 0
            assert client.total_bytes_transferred == 0
            
            # Update usage
            client.update_usage_stats(1024, 2048, 3600)  # 1KB sent, 2KB received, 1 hour
            
            assert client.total_bytes_sent == 1024
            assert client.total_bytes_received == 2048
            assert client.total_bytes_transferred == 3072
            assert client.total_connection_time == 3600
            assert client.last_seen is not None
    
    def test_bandwidth_formatting(self, app):
        """Test bandwidth usage formatting."""
        with app.app_context():
            client = VPNClient(name='testclient')
            client.total_bytes_sent = 1024 * 1024  # 1 MB
            client.total_bytes_received = 2048 * 1024  # 2 MB
            
            formatted = client.formatted_bandwidth_usage
            
            assert 'MB' in formatted['sent']
            assert 'MB' in formatted['received']
            assert 'MB' in formatted['total']
            assert '1.00 MB' == formatted['sent']
            assert '2.00 MB' == formatted['received']
            assert '3.00 MB' == formatted['total']
    
    def test_to_dict(self, app):
        """Test converting client to dictionary."""
        with app.app_context():
            client = VPNClient(
                name='testclient',
                email='client@example.com',
                description='Test client'
            )
            
            client_dict = client.to_dict()
            
            assert client_dict['name'] == 'testclient'
            assert client_dict['email'] == 'client@example.com'
            assert client_dict['description'] == 'Test client'
            assert client_dict['is_active'] == True
            assert client_dict['is_revoked'] == False
            assert 'bandwidth_usage' in client_dict
            assert 'bandwidth_limits' in client_dict
            assert 'created_at' in client_dict

class TestModelRelationships:
    """Test relationships between models."""
    
    def test_user_client_relationship(self, app):
        """Test relationship between users and clients."""
        with app.app_context():
            # Create user
            user = User(username='testuser', email='test@example.com')
            db.session.add(user)
            db.session.commit()
            
            # Create client with user relationship
            client = VPNClient(
                name='testclient',
                created_by=user.id
            )
            db.session.add(client)
            db.session.commit()
            
            # Test relationship
            assert client.creator == user
            assert client in user.created_clients
            assert len(user.created_clients) == 1
    
    def test_cascade_delete(self, app):
        """Test that proper cascading occurs on delete."""
        with app.app_context():
            # Create user and client
            user = User(username='testuser', email='test@example.com')
            db.session.add(user)
            db.session.commit()
            
            client = VPNClient(name='testclient', created_by=user.id)
            db.session.add(client)
            db.session.commit()
            
            client_id = client.id
            
            # Delete user
            db.session.delete(user)
            db.session.commit()
            
            # Client should still exist but with null created_by
            remaining_client = VPNClient.query.get(client_id)
            assert remaining_client is not None
            assert remaining_client.created_by is None
