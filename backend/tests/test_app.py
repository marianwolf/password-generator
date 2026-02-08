import pytest
import json
from datetime import datetime, timezone
from app import app, db, User, PasswordEntry, AuditLog
from werkzeug.security import generate_password_hash

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['JWT_SECRET_KEY'] = 'test-secret-key'
    
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.drop_all()

@pytest.fixture
def test_user(client):
    """Create a test user."""
    response = client.post('/api/v1/auth/register', json={
        'email': 'test@example.com',
        'password': 'testpassword123',
        'master_password': 'masterpassword123'
    })
    return response.get_json()['user']

@pytest.fixture
def auth_headers(client):
    """Get authentication headers."""
    response = client.post('/api/v1/auth/login', json={
        'email': 'test@example.com',
        'password': 'testpassword123'
    })
    data = response.get_json()
    return {
        'Authorization': f'Bearer {data["access_token"]}',
        'X-Session-Token': data['session_token'],
        'Content-Type': 'application/json'
    }

class TestHealthCheck:
    """Test health check endpoint."""
    
    def test_health_check(self, client):
        """Test that health check returns healthy status."""
        response = client.get('/health')
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'healthy'

class TestAuthentication:
    """Test authentication endpoints."""
    
    def test_register_success(self, client):
        """Test successful user registration."""
        response = client.post('/api/v1/auth/register', json={
            'email': 'newuser@example.com',
            'password': 'securepassword123',
            'master_password': 'masterpassword123'
        })
        assert response.status_code == 201
        data = response.get_json()
        assert 'access_token' in data
        assert data['user']['email'] == 'newuser@example.com'
    
    def test_register_duplicate_email(self, client):
        """Test registration with existing email fails."""
        # First registration
        client.post('/api/v1/auth/register', json={
            'email': 'duplicate@example.com',
            'password': 'password123',
            'master_password': 'master123'
        })
        # Second registration with same email
        response = client.post('/api/v1/auth/register', json={
            'email': 'duplicate@example.com',
            'password': 'password456',
            'master_password': 'master456'
        })
        assert response.status_code == 409
    
    def test_login_success(self, client):
        """Test successful login."""
        # Register first
        client.post('/api/v1/auth/register', json={
            'email': 'login@example.com',
            'password': 'password123',
            'master_password': 'master123'
        })
        # Login
        response = client.post('/api/v1/auth/login', json={
            'email': 'login@example.com',
            'password': 'password123'
        })
        assert response.status_code == 200
        data = response.get_json()
        assert 'access_token' in data
        assert 'session_token' in data
    
    def test_login_invalid_credentials(self, client):
        """Test login with invalid credentials fails."""
        response = client.post('/api/v1/auth/login', json={
            'email': 'nonexistent@example.com',
            'password': 'wrongpassword'
        })
        assert response.status_code == 401

class TestPasswordManagement:
    """Test password CRUD operations."""
    
    def test_create_password(self, client, auth_headers):
        """Test creating a new password entry."""
        response = client.post('/api/v1/passwords', 
            headers=auth_headers,
            json={
                'title': 'Test Account',
                'username': 'testuser',
                'password': 'securepassword123',
                'website_url': 'https://example.com',
                'category': 'login'
            }
        )
        assert response.status_code == 201
        data = response.get_json()
        assert data['entry']['title'] == 'Test Account'
        assert data['entry']['username'] == 'testuser'
        assert 'password' in data['entry']
    
    def test_list_passwords(self, client, auth_headers):
        """Test listing password entries."""
        # Create a password first
        client.post('/api/v1/passwords', 
            headers=auth_headers,
            json={
                'title': 'List Test',
                'password': 'testpassword'
            }
        )
        # List passwords
        response = client.get('/api/v1/passwords', headers=auth_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert 'passwords' in data
        assert 'total' in data
    
    def test_get_password(self, client, auth_headers):
        """Test retrieving a specific password."""
        # Create password
        create_response = client.post('/api/v1/passwords',
            headers=auth_headers,
            json={
                'title': 'Get Test',
                'password': 'testpassword'
            }
        )
        entry_id = create_response.get_json()['entry']['id']
        
        # Get password
        response = client.get(f'/api/v1/passwords/{entry_id}', headers=auth_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert 'password' in data['entry']
    
    def test_update_password(self, client, auth_headers):
        """Test updating a password entry."""
        # Create password
        create_response = client.post('/api/v1/passwords',
            headers=auth_headers,
            json={
                'title': 'Update Test',
                'password': 'oldpassword'
            }
        )
        entry_id = create_response.get_json()['entry']['id']
        
        # Update password
        response = client.put(f'/api/v1/passwords/{entry_id}',
            headers=auth_headers,
            json={
                'title': 'Updated Title',
                'password': 'newpassword'
            }
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data['entry']['title'] == 'Updated Title'
    
    def test_delete_password(self, client, auth_headers):
        """Test deleting a password entry."""
        # Create password
        create_response = client.post('/api/v1/passwords',
            headers=auth_headers,
            json={
                'title': 'Delete Test',
                'password': 'testpassword'
            }
        )
        entry_id = create_response.get_json()['entry']['id']
        
        # Delete password
        response = client.delete(f'/api/v1/passwords/{entry_id}', headers=auth_headers)
        assert response.status_code == 200
        
        # Verify deletion
        get_response = client.get(f'/api/v1/passwords/{entry_id}', headers=auth_headers)
        assert get_response.status_code == 404

class TestPasswordGenerator:
    """Test password generator endpoint."""
    
    def test_generate_password(self, client, auth_headers):
        """Test generating a secure password."""
        response = client.get('/api/v1/generate-password',
            headers=auth_headers,
            query_string={'length': 20, 'uppercase': 'true', 'numbers': 'true', 'symbols': 'true'}
        )
        assert response.status_code == 200
        data = response.get_json()
        assert 'password' in data
        assert len(data['password']) == 20

class TestSearchAndFilter:
    """Test search and filter functionality."""
    
    def test_search_passwords(self, client, auth_headers):
        """Test searching passwords."""
        # Create passwords
        client.post('/api/v1/passwords', headers=auth_headers, json={
            'title': 'Google Account',
            'password': 'test123'
        })
        client.post('/api/v1/passwords', headers=auth_headers, json={
            'title': 'Facebook Account',
            'password': 'test456'
        })
        
        # Search
        response = client.get('/api/v1/passwords',
            headers=auth_headers,
            query_string={'search': 'Google'}
        )
        assert response.status_code == 200
        data = response.get_json()
        assert len(data['passwords']) == 1
        assert data['passwords'][0]['title'] == 'Google Account'
    
    def test_filter_by_category(self, client, auth_headers):
        """Test filtering by category."""
        # Create passwords with different categories
        client.post('/api/v1/passwords', headers=auth_headers, json={
            'title': 'Login 1',
            'password': 'test1',
            'category': 'login'
        })
        client.post('/api/v1/passwords', headers=auth_headers, json={
            'title': 'Note 1',
            'password': 'test2',
            'category': 'secure_note'
        })
        
        # Filter
        response = client.get('/api/v1/passwords',
            headers=auth_headers,
            query_string={'category': 'login'}
        )
        assert response.status_code == 200
        data = response.get_json()
        assert all(p['category'] == 'login' for p in data['passwords'])

class TestAuditLogs:
    """Test audit logging functionality."""
    
    def test_get_audit_logs(self, client, auth_headers):
        """Test retrieving audit logs."""
        response = client.get('/api/v1/audit-logs', headers=auth_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert 'logs' in data

class TestStatistics:
    """Test statistics endpoint."""
    
    def test_get_stats(self, client, auth_headers):
        """Test retrieving statistics."""
        response = client.get('/api/v1/stats', headers=auth_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert 'total_passwords' in data
        assert 'strength_distribution' in data

class TestInputValidation:
    """Test input validation."""
    
    def test_invalid_email(self, client):
        """Test registration with invalid email."""
        response = client.post('/api/v1/auth/register', json={
            'email': 'invalid-email',
            'password': 'password123',
            'master_password': 'master123'
        })
        assert response.status_code == 400
    
    def test_short_password(self, client):
        """Test registration with short password."""
        response = client.post('/api/v1/auth/register', json={
            'email': 'test@example.com',
            'password': 'short',
            'master_password': 'master'
        })
        assert response.status_code == 400
    
    def test_missing_required_fields(self, client):
        """Test creating password without required fields."""
        # Register and login
        client.post('/api/v1/auth/register', json={
            'email': 'test2@example.com',
            'password': 'password123',
            'master_password': 'master123'
        })
        login_response = client.post('/api/v1/auth/login', json={
            'email': 'test2@example.com',
            'password': 'password123'
        })
        headers = {
            'Authorization': f'Bearer {login_response.get_json()["access_token"]}',
            'X-Session-Token': login_response.get_json()['session_token'],
            'Content-Type': 'application/json'
        }
        
        # Try to create password without title
        response = client.post('/api/v1/passwords', headers=headers, json={
            'password': 'testpassword'
        })
        assert response.status_code == 400
