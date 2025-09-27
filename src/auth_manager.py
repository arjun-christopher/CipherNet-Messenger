"""
Authentication Manager for CipherNet Messenger
Handles Firebase authentication and user management.

Author: Arjun Christopher
"""

import json
import requests
import socket
import uuid
import platform
import time
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
        
        # Session management
        self.session_id = None
        self.machine_id = self._generate_machine_id()
        
        # Firebase REST API endpoints
        self.auth_url = f"https://identitytoolkit.googleapis.com/v1/accounts"
        self.refresh_url = f"https://securetoken.googleapis.com/v1/token"
        self.database_url = config.get('firebase.database_url')
    
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
        Authenticate user with Firebase Authentication with session management.
        
        Args:
            email: User's email address
            password: User's password
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            if not self._validate_credentials(email, password):
                return False, "Invalid email or password format"
            
            # First authenticate with Firebase
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
                user_uid = user_data['localId']
                
                # Check for existing sessions before allowing login
                can_login, session_message = self._check_existing_sessions(user_uid)
                if not can_login:
                    return False, f"Login blocked: {session_message}"
                
                # Store user data
                self._store_user_data(user_data)
                
                # Create new session
                if not self._create_session(user_data):
                    # If session creation fails, still allow login but warn
                    print("⚠️  Warning: Session management unavailable")
                
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
        # Clean up session first
        if self.session_id:
            self._cleanup_session()
        
        self.current_user = None
        self.id_token = None
        self.refresh_token = None
        self.token_expiry = None
        self.session_id = None
    
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
    
    def get_session_info(self) -> Optional[Dict[str, Any]]:
        """
        Get current session information.
        
        Returns:
            Dictionary with session info or None if no active session
        """
        if not self.session_id:
            return None
            
        return {
            'session_id': self.session_id,
            'machine_id': self.machine_id,
            'platform': platform.platform()
        }
    
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
    
    def _generate_machine_id(self) -> str:
        """Generate a unique machine identifier."""
        try:
            # Use hostname and platform info to create a unique machine ID
            hostname = socket.gethostname()
            platform_info = platform.platform()
            machine_info = f"{hostname}_{platform_info}"
            return str(hash(machine_info))
        except Exception:
            # Fallback to a random UUID if hostname/platform fails
            return str(uuid.uuid4())
    
    def _check_existing_sessions(self, user_uid: str) -> Tuple[bool, str]:
        """
        Check for existing active sessions for the user or machine.
        
        Args:
            user_uid: User's UID to check
            
        Returns:
            Tuple of (can_login: bool, message: str)
        """
        try:
            # Check active sessions
            sessions_path = f"sessions"
            response = requests.get(
                f"{self.database_url}/{sessions_path}.json",
                timeout=10
            )
            
            if response.status_code != 200:
                # If we can't read sessions, allow login (fail open)
                return True, "Session check unavailable, allowing login"
            
            sessions_data = response.json() or {}
            current_time = int(time.time() * 1000)
            session_timeout = 30 * 60 * 1000  # 30 minutes
            
            # Check for existing user sessions on other machines
            for session_id, session_data in sessions_data.items():
                if isinstance(session_data, dict):
                    session_uid = session_data.get('user_uid')
                    session_machine = session_data.get('machine_id')
                    last_activity = session_data.get('last_activity', 0)
                    session_status = session_data.get('status', 'active')
                    
                    # Skip expired or inactive sessions
                    if (session_status != 'active' or 
                        current_time - last_activity > session_timeout):
                        continue
                    
                    # Check if same user is logged in elsewhere
                    if session_uid == user_uid and session_machine != self.machine_id:
                        return False, f"User is already logged in on another system (Session: {session_id[:8]}...)"
                    
                    # Check if different user is logged in on same machine
                    if session_machine == self.machine_id and session_uid != user_uid:
                        other_email = session_data.get('email', 'Unknown User')
                        return False, f"Another user ({other_email}) is already logged in on this system"
            
            return True, "No conflicting sessions found"
            
        except Exception as e:
            # If session check fails, allow login (fail open)
            print(f"Session check failed: {e}")
            return True, "Session check failed, allowing login"
    
    def _create_session(self, user_data: Dict[str, Any]) -> bool:
        """
        Create a new session for the user.
        
        Args:
            user_data: User data from Firebase auth
            
        Returns:
            True if session created successfully
        """
        try:
            self.session_id = str(uuid.uuid4())
            current_time = int(time.time() * 1000)
            
            session_data = {
                'session_id': self.session_id,
                'user_uid': user_data['localId'],
                'email': user_data['email'],
                'machine_id': self.machine_id,
                'login_time': current_time,
                'last_activity': current_time,
                'status': 'active',
                'app_version': '1.0.0',
                'platform': platform.platform()
            }
            
            # Store session in Firebase
            session_path = f"sessions/{self.session_id}"
            response = requests.put(
                f"{self.database_url}/{session_path}.json",
                data=json.dumps(session_data),
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                print(f"✅ Session created: {self.session_id[:8]}...")
                return True
            else:
                print(f"❌ Failed to create session: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Session creation failed: {e}")
            return False
    
    def _update_session_activity(self) -> bool:
        """Update session last activity timestamp."""
        if not self.session_id:
            return False
            
        try:
            current_time = int(time.time() * 1000)
            session_path = f"sessions/{self.session_id}"
            
            update_data = {
                'last_activity': current_time
            }
            
            response = requests.patch(
                f"{self.database_url}/{session_path}.json",
                data=json.dumps(update_data),
                headers={'Content-Type': 'application/json'},
                timeout=5
            )
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"Session activity update failed: {e}")
            return False
    
    def _cleanup_session(self) -> bool:
        """Clean up current session on logout."""
        if not self.session_id:
            return False
            
        try:
            session_path = f"sessions/{self.session_id}"
            response = requests.delete(
                f"{self.database_url}/{session_path}.json",
                timeout=10
            )
            
            if response.status_code == 200:
                print(f"✅ Session cleaned up: {self.session_id[:8]}...")
                self.session_id = None
                return True
            else:
                print(f"❌ Failed to cleanup session: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Session cleanup failed: {e}")
            return False

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