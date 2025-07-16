"""
Tests for the OpenVPN Manager API endpoints.
"""

import pytest
import json
from app import create_app, db
from app.models.user import User
from app.models.client import VPNClient
from tests.conftest import TestConfig, TEST_CLIENT_DATA, TEST_USER_DATA

@pytest.fixture
def app():
    """Create and configure a test app."""
    app = create_app('testing')
    app.config.from_object(TestConfig)
    
    with app.app_context():
        db.create_all()
        
        # Create test admin user
        admin = User(
            username=TestConfig.ADMIN_USER,
            email='admin@example.com',
            is_admin=True,
            is_active=True
        )
        admin.set_password(TestConfig.ADMIN_PASSWORD)
        db.session.add(admin)
        db.session.commit()
        
        yield app
        
        db.drop_all()

@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()

@pytest.fixture
def auth_headers(client):
    """Get authentication headers for API requests."""
    response = client.post('/auth/login', json={
        'username': TestConfig.ADMIN_USER,
        'password': TestConfig.ADMIN_PASSWORD
    })
    
    assert response.status_code == 200
    data = json.loads(response.data)
    token = data['access_token']
    
    return {'Authorization': f'Bearer {token}'}

class TestAPIEndpoints:
    """Test API endpoints."""
    
    def test_health_check(self, client):
        """Test health check endpoint."""
        response = client.get('/health')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
    
    def test_api_status(self, client, auth_headers):
        """Test API status endpoint."""
        response = client.get('/api/status', headers=auth_headers)
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'operational'
        assert 'version' in data
    
    def test_dashboard_stats(self, client, auth_headers):
        """Test dashboard stats endpoint."""
        response = client.get('/api/dashboard/stats', headers=auth_headers)
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'clients' in data
        assert 'system' in data
        assert 'openvpn' in data
    
    def test_list_clients_empty(self, client, auth_headers):
        """Test listing clients when none exist."""
        response = client.get('/api/clients', headers=auth_headers)
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['clients'] == []
        assert data['pagination']['total'] == 0
    
    def test_create_client(self, client, auth_headers):
        """Test creating a new client."""
        response = client.post('/api/clients', 
                              json=TEST_CLIENT_DATA,
                              headers=auth_headers)
        assert response.status_code == 201
        
        data = json.loads(response.data)
        assert data['message'] == 'Client created successfully'
        assert data['client']['name'] == TEST_CLIENT_DATA['name']
    
    def test_create_duplicate_client(self, client, auth_headers):
        """Test creating a client with duplicate name."""
        # Create first client
        client.post('/api/clients', 
                   json=TEST_CLIENT_DATA,
                   headers=auth_headers)
        
        # Try to create duplicate
        response = client.post('/api/clients', 
                              json=TEST_CLIENT_DATA,
                              headers=auth_headers)
        assert response.status_code == 409
        
        data = json.loads(response.data)
        assert 'already exists' in data['error']
    
    def test_create_client_invalid_name(self, client, auth_headers):
        """Test creating a client with invalid name."""
        invalid_data = {**TEST_CLIENT_DATA, 'name': 'invalid name!'}
        
        response = client.post('/api/clients', 
                              json=invalid_data,
                              headers=auth_headers)
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert 'Invalid' in data['error']
    
    def test_get_client(self, client, auth_headers):
        """Test getting a specific client."""
        # Create client first
        create_response = client.post('/api/clients', 
                                     json=TEST_CLIENT_DATA,
                                     headers=auth_headers)
        client_data = json.loads(create_response.data)
        client_id = client_data['client']['id']
        
        # Get client
        response = client.get(f'/api/clients/{client_id}', headers=auth_headers)
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['name'] == TEST_CLIENT_DATA['name']
    
    def test_get_nonexistent_client(self, client, auth_headers):
        """Test getting a client that doesn't exist."""
        response = client.get('/api/clients/999', headers=auth_headers)
        assert response.status_code == 404
    
    def test_revoke_client(self, client, auth_headers):
        """Test revoking a client."""
        # Create client first
        create_response = client.post('/api/clients', 
                                     json=TEST_CLIENT_DATA,
                                     headers=auth_headers)
        client_data = json.loads(create_response.data)
        client_id = client_data['client']['id']
        
        # Revoke client
        response = client.post(f'/api/clients/{client_id}/revoke', 
                              headers=auth_headers)
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['message'] == 'Client revoked successfully'
        assert data['client']['is_revoked'] == True

class TestAuthentication:
    """Test authentication endpoints."""
    
    def test_login_success(self, client):
        """Test successful login."""
        response = client.post('/auth/login', json={
            'username': TestConfig.ADMIN_USER,
            'password': TestConfig.ADMIN_PASSWORD
        })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'access_token' in data
        assert data['user']['username'] == TestConfig.ADMIN_USER
    
    def test_login_invalid_credentials(self, client):
        """Test login with invalid credentials."""
        response = client.post('/auth/login', json={
            'username': 'invalid',
            'password': 'invalid'
        })
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert 'Invalid' in data['error']
    
    def test_login_missing_fields(self, client):
        """Test login with missing fields."""
        response = client.post('/auth/login', json={
            'username': 'test'
            # Missing password
        })
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'required' in data['error']
    
    def test_logout(self, client, auth_headers):
        """Test logout."""
        response = client.post('/auth/logout', headers=auth_headers)
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['message'] == 'Logout successful'
    
    def test_access_without_auth(self, client):
        """Test accessing protected endpoint without authentication."""
        response = client.get('/api/clients')
        assert response.status_code == 401
        
        data = json.loads(response.data)
        assert 'Authentication required' in data['error']

class TestValidation:
    """Test input validation."""
    
    def test_validate_client_name(self):
        """Test client name validation."""
        from app.utils.validation import validate_client_name
        
        # Valid names
        assert validate_client_name('client1') == True
        assert validate_client_name('test-client') == True
        assert validate_client_name('client_123') == True
        
        # Invalid names
        assert validate_client_name('') == False
        assert validate_client_name('ab') == False  # Too short
        assert validate_client_name('a' * 51) == False  # Too long
        assert validate_client_name('client name') == False  # Space
        assert validate_client_name('client!') == False  # Special char
        assert validate_client_name('-client') == False  # Start with hyphen
        assert validate_client_name('client-') == False  # End with hyphen
    
    def test_validate_email(self):
        """Test email validation."""
        from app.utils.validation import validate_email
        
        # Valid emails
        assert validate_email('test@example.com') == True
        assert validate_email('user.name@domain.org') == True
        assert validate_email('') == True  # Empty is OK (optional)
        assert validate_email(None) == True  # None is OK (optional)
        
        # Invalid emails
        assert validate_email('invalid') == False
        assert validate_email('@example.com') == False
        assert validate_email('test@') == False
        assert validate_email('test.example.com') == False
    
    def test_password_strength(self):
        """Test password strength validation."""
        from app.utils.validation import validate_password_strength
        
        # Strong passwords
        is_strong, _ = validate_password_strength('StrongPass123!')
        assert is_strong == True
        
        # Weak passwords
        is_strong, _ = validate_password_strength('weak')
        assert is_strong == False
        
        is_strong, _ = validate_password_strength('nouppercasepass123!')
        assert is_strong == False
        
        is_strong, _ = validate_password_strength('NOLOWERCASEPASS123!')
        assert is_strong == False
        
        is_strong, _ = validate_password_strength('NoDigitsPass!')
        assert is_strong == False
        
        is_strong, _ = validate_password_strength('NoSpecialPass123')
        assert is_strong == False
