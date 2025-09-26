"""
Authentication Manager for CipherNet Messenger
Handles Firebase authentication and user management.

Author: Arjun Christopher
"""

import json
import requests
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta


class AuthManager:
    """Manages user authentication using Firebase."""
    
    def __init__(self, config):
        """
        Initialize authentication manager.
        
        Args:
            config: Configuration manager instance
        """
        self.config = config
        self.firebase_config = config.get_firebase_config()
        self.api_key = self.firebase_config.get('api_key')
        self.auth_domain = self.firebase_config.get('auth_domain')
        
        self.current_user = None
        self.id_token = None
        self.refresh_token = None
        self.token_expiry = None
        
        # Firebase REST API endpoints
        self.auth_url = f"https://identitytoolkit.googleapis.com/v1/accounts"
        self.refresh_url = f"https://securetoken.googleapis.com/v1/token"
    
    def register_user(self, email: str, password: str) -> Tuple[bool, str]:
        """
        Register a new user with Firebase Authentication.
        
        Args:
            email: User's email address
            password: User's password
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            if not self._validate_credentials(email, password):
                return False, "Invalid email or password format"
            
            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
            
            response = requests.post(
                f"{self.auth_url}:signUp",
                params={"key": self.api_key},
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                user_data = response.json()
                self._store_user_data(user_data)
                return True, "Registration successful"
            else:
                error_data = response.json()
                error_message = error_data.get('error', {}).get('message', 'Registration failed')
                return False, self._parse_firebase_error(error_message)
                
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        except Exception as e:
            return False, f"Registration error: {e}"
    
    def login_user(self, email: str, password: str) -> Tuple[bool, str]:
        """
        Authenticate user with Firebase Authentication.
        
        Args:
            email: User's email address
            password: User's password
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            if not self._validate_credentials(email, password):
                return False, "Invalid email or password format"
            
            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
            
            response = requests.post(
                f"{self.auth_url}:signInWithPassword",
                params={"key": self.api_key},
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                user_data = response.json()
                self._store_user_data(user_data)
                return True, "Login successful"
            else:
                error_data = response.json()
                error_message = error_data.get('error', {}).get('message', 'Login failed')
                return False, self._parse_firebase_error(error_message)
                
        except requests.RequestException as e:
            return False, f"Network error: {e}"
        except Exception as e:
            return False, f"Login error: {e}"
    
    def logout_user(self):
        """Logout current user and clear stored data."""
        self.current_user = None
        self.id_token = None
        self.refresh_token = None
        self.token_expiry = None
    
    def refresh_auth_token(self) -> bool:
        """
        Refresh the authentication token.
        
        Returns:
            True if refresh successful, False otherwise
        """
        try:
            if not self.refresh_token:
                return False
            
            payload = {
                "grant_type": "refresh_token",
                "refresh_token": self.refresh_token
            }
            
            response = requests.post(
                self.refresh_url,
                params={"key": self.api_key},
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                token_data = response.json()
                self.id_token = token_data.get('id_token')
                self.refresh_token = token_data.get('refresh_token')
                
                # Update token expiry
                expires_in = int(token_data.get('expires_in', 3600))
                self.token_expiry = datetime.now() + timedelta(seconds=expires_in)
                return True
            
            return False
            
        except Exception as e:
            print(f"Token refresh error: {e}")
            return False
    
    def is_authenticated(self) -> bool:
        """
        Check if user is currently authenticated.
        
        Returns:
            True if authenticated, False otherwise
        """
        if not self.current_user or not self.id_token:
            return False
        
        # Check if token is expired
        if self.token_expiry and datetime.now() >= self.token_expiry:
            # Try to refresh token
            return self.refresh_auth_token()
        
        return True
    
    def get_current_user(self) -> Optional[Dict[str, Any]]:
        """
        Get current authenticated user data.
        
        Returns:
            User data dictionary or None if not authenticated
        """
        return self.current_user
    
    def get_auth_headers(self) -> Dict[str, str]:
        """
        Get authentication headers for Firebase requests.
        
        Returns:
            Dictionary with authorization headers
        """
        if self.id_token:
            return {"Authorization": f"Bearer {self.id_token}"}
        return {}
    
    def _validate_credentials(self, email: str, password: str) -> bool:
        """
        Validate email and password format.
        
        Args:
            email: Email address to validate
            password: Password to validate
        
        Returns:
            True if valid, False otherwise
        """
        import re
        
        # Basic email validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return False
        
        # Password validation (minimum 6 characters)
        if len(password) < 6:
            return False
        
        return True
    
    def _store_user_data(self, user_data: Dict[str, Any]):
        """
        Store user authentication data.
        
        Args:
            user_data: User data from Firebase response
        """
        self.current_user = {
            "uid": user_data.get('localId'),
            "email": user_data.get('email'),
            "email_verified": user_data.get('emailVerified', False),
            "display_name": user_data.get('displayName', ''),
            "created_at": user_data.get('createdAt', ''),
            "last_login": user_data.get('lastLoginAt', '')
        }
        
        self.id_token = user_data.get('idToken')
        self.refresh_token = user_data.get('refreshToken')
        
        # Calculate token expiry
        expires_in = int(user_data.get('expiresIn', 3600))
        self.token_expiry = datetime.now() + timedelta(seconds=expires_in)
    
    def _parse_firebase_error(self, error_message: str) -> str:
        """
        Parse Firebase error messages into user-friendly format.
        
        Args:
            error_message: Raw Firebase error message
        
        Returns:
            User-friendly error message
        """
        error_mappings = {
            "EMAIL_EXISTS": "An account with this email already exists",
            "OPERATION_NOT_ALLOWED": "Registration is currently disabled",
            "TOO_MANY_ATTEMPTS_TRY_LATER": "Too many attempts. Please try again later",
            "EMAIL_NOT_FOUND": "No account found with this email address",
            "INVALID_PASSWORD": "Incorrect password",
            "USER_DISABLED": "This account has been disabled",
            "INVALID_EMAIL": "Invalid email address format",
            "WEAK_PASSWORD": "Password is too weak (minimum 6 characters required)"
        }
        
        return error_mappings.get(error_message, error_message)


class AuthenticationError(Exception):
    """Custom exception for authentication operations."""
    pass