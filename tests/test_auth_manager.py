"""
Tests for Authentication Manager
Tests Firebase authentication functionality including login, registration, and token management.

Author: Arjun Christopher
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).parent.parent / "src"))

from auth_manager import AuthManager, AuthenticationError
from conftest import MockFirebaseResponse


class TestAuthManager:
    """Test cases for AuthManager class."""
    
    def test_initialization(self, mock_config):
        """Test AuthManager initialization."""
        auth_manager = AuthManager(mock_config)
        
        assert auth_manager.config == mock_config
        assert auth_manager.api_key == "test-api-key"
        assert auth_manager.current_user is None
        assert auth_manager.id_token is None
    
    def test_credential_validation_valid_email(self, mock_config):
        """Test valid email and password validation."""
        auth_manager = AuthManager(mock_config)
        
        # Valid credentials
        assert auth_manager._validate_credentials("test@example.com", "password123") == True
        assert auth_manager._validate_credentials("user.name+tag@domain.co.uk", "validpass") == True
    
    def test_credential_validation_invalid_email(self, mock_config):
        """Test invalid email validation."""
        auth_manager = AuthManager(mock_config)
        
        # Invalid email formats
        assert auth_manager._validate_credentials("invalid-email", "password123") == False
        assert auth_manager._validate_credentials("test@", "password123") == False
        assert auth_manager._validate_credentials("@domain.com", "password123") == False
        assert auth_manager._validate_credentials("", "password123") == False
    
    def test_credential_validation_invalid_password(self, mock_config):
        """Test invalid password validation."""
        auth_manager = AuthManager(mock_config)
        
        # Invalid passwords (less than 6 characters)
        assert auth_manager._validate_credentials("test@example.com", "12345") == False
        assert auth_manager._validate_credentials("test@example.com", "") == False
        assert auth_manager._validate_credentials("test@example.com", "a") == False
    
    @patch('auth_manager.requests.post')
    def test_successful_registration(self, mock_post, mock_config):
        """Test successful user registration."""
        auth_manager = AuthManager(mock_config)
        
        # Mock successful response
        mock_response = MockFirebaseResponse(
            status_code=200,
            data={
                "idToken": "test-id-token",
                "refreshToken": "test-refresh-token",
                "expiresIn": "3600",
                "localId": "user123",
                "email": "test@example.com",
                "emailVerified": False
            }
        )
        mock_post.return_value = mock_response
        
        success, message = auth_manager.register_user("test@example.com", "password123")
        
        assert success == True
        assert message == "Registration successful"
        assert auth_manager.current_user is not None
        assert auth_manager.current_user["email"] == "test@example.com"
        assert auth_manager.id_token == "test-id-token"
    
    @patch('auth_manager.requests.post')
    def test_failed_registration_email_exists(self, mock_post, mock_config):
        """Test registration failure when email already exists."""
        auth_manager = AuthManager(mock_config)
        
        # Mock error response
        mock_response = MockFirebaseResponse(
            status_code=400,
            error="EMAIL_EXISTS"
        )
        mock_post.return_value = mock_response
        
        success, message = auth_manager.register_user("existing@example.com", "password123")
        
        assert success == False
        assert "already exists" in message.lower()
        assert auth_manager.current_user is None
    
    @patch('auth_manager.requests.post')
    def test_registration_invalid_credentials(self, mock_post, mock_config):
        """Test registration with invalid credentials."""
        auth_manager = AuthManager(mock_config)
        
        success, message = auth_manager.register_user("invalid-email", "123")
        
        assert success == False
        assert "Invalid email or password format" in message
        # Should not make API call for invalid credentials
        mock_post.assert_not_called()
    
    @patch('auth_manager.requests.post')
    def test_successful_login(self, mock_post, mock_config):
        """Test successful user login."""
        auth_manager = AuthManager(mock_config)
        
        # Mock successful response
        mock_response = MockFirebaseResponse(
            status_code=200,
            data={
                "idToken": "test-id-token",
                "refreshToken": "test-refresh-token",
                "expiresIn": "3600",
                "localId": "user123",
                "email": "test@example.com",
                "emailVerified": True,
                "lastLoginAt": "1632150000000"
            }
        )
        mock_post.return_value = mock_response
        
        success, message = auth_manager.login_user("test@example.com", "password123")
        
        assert success == True
        assert message == "Login successful"
        assert auth_manager.current_user is not None
        assert auth_manager.current_user["email"] == "test@example.com"
        assert auth_manager.is_authenticated() == True
    
    @patch('auth_manager.requests.post')
    def test_failed_login_invalid_password(self, mock_post, mock_config):
        """Test login failure with invalid password."""
        auth_manager = AuthManager(mock_config)
        
        # Mock error response
        mock_response = MockFirebaseResponse(
            status_code=400,
            error="INVALID_PASSWORD"
        )
        mock_post.return_value = mock_response
        
        success, message = auth_manager.login_user("test@example.com", "wrongpassword")
        
        assert success == False
        assert "Incorrect password" in message
        assert auth_manager.current_user is None
    
    @patch('auth_manager.requests.post')
    def test_failed_login_user_not_found(self, mock_post, mock_config):
        """Test login failure when user not found."""
        auth_manager = AuthManager(mock_config)
        
        # Mock error response
        mock_response = MockFirebaseResponse(
            status_code=400,
            error="EMAIL_NOT_FOUND"
        )
        mock_post.return_value = mock_response
        
        success, message = auth_manager.login_user("nonexistent@example.com", "password123")
        
        assert success == False
        assert "No account found" in message
    
    def test_logout_user(self, mock_config):
        """Test user logout."""
        auth_manager = AuthManager(mock_config)
        
        # Simulate logged in user
        auth_manager.current_user = {"uid": "user123", "email": "test@example.com"}
        auth_manager.id_token = "test-token"
        auth_manager.refresh_token = "refresh-token"
        
        auth_manager.logout_user()
        
        assert auth_manager.current_user is None
        assert auth_manager.id_token is None
        assert auth_manager.refresh_token is None
        assert auth_manager.is_authenticated() == False
    
    @patch('auth_manager.requests.post')
    def test_successful_token_refresh(self, mock_post, mock_config):
        """Test successful token refresh."""
        auth_manager = AuthManager(mock_config)
        
        # Set up initial state
        auth_manager.refresh_token = "old-refresh-token"
        auth_manager.token_expiry = datetime.now() - timedelta(seconds=1)  # Expired
        
        # Mock successful refresh response
        mock_response = MockFirebaseResponse(
            status_code=200,
            data={
                "id_token": "new-id-token",
                "refresh_token": "new-refresh-token",
                "expires_in": "3600"
            }
        )
        mock_post.return_value = mock_response
        
        success = auth_manager.refresh_auth_token()
        
        assert success == True
        assert auth_manager.id_token == "new-id-token"
        assert auth_manager.refresh_token == "new-refresh-token"
        assert auth_manager.token_expiry > datetime.now()
    
    @patch('auth_manager.requests.post')
    def test_failed_token_refresh(self, mock_post, mock_config):
        """Test failed token refresh."""
        auth_manager = AuthManager(mock_config)
        
        # Set up initial state
        auth_manager.refresh_token = "invalid-refresh-token"
        
        # Mock failed refresh response
        mock_response = MockFirebaseResponse(status_code=400)
        mock_post.return_value = mock_response
        
        success = auth_manager.refresh_auth_token()
        
        assert success == False
    
    def test_token_refresh_without_refresh_token(self, mock_config):
        """Test token refresh without refresh token."""
        auth_manager = AuthManager(mock_config)
        
        success = auth_manager.refresh_auth_token()
        
        assert success == False
    
    def test_is_authenticated_with_valid_token(self, mock_config):
        """Test authentication check with valid token."""
        auth_manager = AuthManager(mock_config)
        
        # Set up authenticated state
        auth_manager.current_user = {"uid": "user123"}
        auth_manager.id_token = "valid-token"
        auth_manager.token_expiry = datetime.now() + timedelta(hours=1)
        
        assert auth_manager.is_authenticated() == True
    
    def test_is_authenticated_without_user(self, mock_config):
        """Test authentication check without user."""
        auth_manager = AuthManager(mock_config)
        
        assert auth_manager.is_authenticated() == False
    
    @patch.object(AuthManager, 'refresh_auth_token')
    def test_is_authenticated_with_expired_token(self, mock_refresh, mock_config):
        """Test authentication check with expired token."""
        auth_manager = AuthManager(mock_config)
        
        # Set up expired state
        auth_manager.current_user = {"uid": "user123"}
        auth_manager.id_token = "expired-token"
        auth_manager.token_expiry = datetime.now() - timedelta(seconds=1)
        
        # Mock successful refresh
        mock_refresh.return_value = True
        
        assert auth_manager.is_authenticated() == True
        mock_refresh.assert_called_once()
    
    def test_get_current_user(self, mock_config):
        """Test getting current user data."""
        auth_manager = AuthManager(mock_config)
        
        # No user logged in
        assert auth_manager.get_current_user() is None
        
        # User logged in
        test_user = {"uid": "user123", "email": "test@example.com"}
        auth_manager.current_user = test_user
        
        assert auth_manager.get_current_user() == test_user
    
    def test_get_auth_headers(self, mock_config):
        """Test getting authentication headers."""
        auth_manager = AuthManager(mock_config)
        
        # No token
        headers = auth_manager.get_auth_headers()
        assert headers == {}
        
        # With token
        auth_manager.id_token = "test-token"
        headers = auth_manager.get_auth_headers()
        assert headers == {"Authorization": "Bearer test-token"}
    
    def test_store_user_data(self, mock_config):
        """Test storing user data from Firebase response."""
        auth_manager = AuthManager(mock_config)
        
        user_data = {
            "localId": "user123",
            "email": "test@example.com",
            "emailVerified": True,
            "displayName": "Test User",
            "idToken": "id-token",
            "refreshToken": "refresh-token",
            "expiresIn": "3600"
        }
        
        auth_manager._store_user_data(user_data)
        
        assert auth_manager.current_user["uid"] == "user123"
        assert auth_manager.current_user["email"] == "test@example.com"
        assert auth_manager.current_user["email_verified"] == True
        assert auth_manager.id_token == "id-token"
        assert auth_manager.refresh_token == "refresh-token"
        assert auth_manager.token_expiry is not None
    
    def test_parse_firebase_error_messages(self, mock_config):
        """Test parsing Firebase error messages."""
        auth_manager = AuthManager(mock_config)
        
        # Test known error messages
        assert "already exists" in auth_manager._parse_firebase_error("EMAIL_EXISTS").lower()
        assert "disabled" in auth_manager._parse_firebase_error("USER_DISABLED").lower()
        assert "password" in auth_manager._parse_firebase_error("INVALID_PASSWORD").lower()
        assert "email" in auth_manager._parse_firebase_error("EMAIL_NOT_FOUND").lower()
        
        # Test unknown error message
        unknown_error = "UNKNOWN_ERROR_CODE"
        assert auth_manager._parse_firebase_error(unknown_error) == unknown_error
    
    @patch('auth_manager.requests.post')
    def test_network_error_handling(self, mock_post, mock_config):
        """Test handling of network errors."""
        import requests
        
        auth_manager = AuthManager(mock_config)
        
        # Mock network error
        mock_post.side_effect = requests.RequestException("Network error")
        
        success, message = auth_manager.login_user("test@example.com", "password123")
        
        assert success == False
        assert "Network error" in message
    
    @patch('auth_manager.requests.post')
    def test_json_decode_error_handling(self, mock_post, mock_config):
        """Test handling of JSON decode errors."""
        auth_manager = AuthManager(mock_config)
        
        # Mock response with invalid JSON
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_post.return_value = mock_response
        
        success, message = auth_manager.login_user("test@example.com", "password123")
        
        assert success == False