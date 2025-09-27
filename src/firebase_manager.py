"""
Firebase Manager for CipherNet Messenger
Handles Firebase Realtime Database operations for signaling and peer discovery.

Author: Arjun Christopher
"""

import json
import requests
from typing import Dict, Any, Optional, Callable, List
from urllib.parse import urljoin
import threading
import time


class FirebaseManager:
    """Manages Firebase Realtime Database operations for signaling."""
    
    def __init__(self, config, auth_manager):
        """
        Initialize Firebase manager.
        
        Args:
            config: Configuration manager instance
            auth_manager: Authentication manager instance
        """
        self.config = config
        self.auth_manager = auth_manager
        self.database_url = config.get('firebase.database_url')
        
        self.listeners = {}  # {path: callback}
        self.listener_threads = {}  # {path: thread}
        self.is_listening = {}  # {path: bool}
        
        # Check Firebase connectivity on initialization
        self._check_connectivity()
    
    def _check_connectivity(self):
        """Check Firebase connectivity and display appropriate messages."""
        try:
            # Try to read from a test path
            test_url = f"{self.database_url}/test.json"
            response = requests.get(test_url, timeout=5)
            
            if response.status_code == 200:
                print("✅ Firebase connected successfully")
            elif response.status_code == 401:
                print("ℹ️  Firebase database requires authentication (this is normal)")
            else:
                print(f"⚠️  Firebase connectivity issue: HTTP {response.status_code}")
        except Exception as e:
            print(f"⚠️  Firebase connection failed: {e}")
    
    def publish_user_presence(self, public_key_pem: bytes) -> bool:
        """
        Publish user presence and public key to the lobby.
        
        Args:
            public_key_pem: User's RSA public key in PEM format
        
        Returns:
            True if published successfully, False otherwise
        """
        try:
            user = self.auth_manager.get_current_user()
            if not user:
                print("⚠️  Cannot publish presence: No authenticated user")
                return False
            
            # Check if we have authentication token
            auth_headers = self.auth_manager.get_auth_headers()
            if not auth_headers:
                print("⚠️  Cannot publish presence: No authentication token")
                return False
            
            presence_data = {
                "uid": user['uid'],
                "email": user['email'],
                "public_key": public_key_pem.decode('utf-8'),
                "status": "online",
                "last_seen": int(time.time() * 1000),  # Timestamp in milliseconds
                "version": self.config.get('app.version', '1.0.0')
            }
            
            path = f"lobby/{user['uid']}"
            success = self._write_data(path, presence_data)
            
            if success:
                print(f"✅ Published presence for {user['email']}")
            else:
                print(f"❌ Failed to publish presence for {user['email']}")
            
            return success
            
        except Exception as e:
            print(f"Failed to publish presence: {e}")
            return False
    
    def remove_user_presence(self) -> bool:
        """
        Remove user presence from the lobby.
        
        Returns:
            True if removed successfully, False otherwise
        """
        try:
            user = self.auth_manager.get_current_user()
            if not user:
                return False
            
            path = f"lobby/{user['uid']}"
            return self._delete_data(path)
            
        except Exception as e:
            print(f"Failed to remove presence: {e}")
            return False
    
    def get_online_users(self) -> List[Dict[str, Any]]:
        """
        Get list of online users from the lobby.
        
        Returns:
            List of user data dictionaries
        """
        try:
            path = "lobby"
            data = self._read_data(path)
            
            if not data:
                return []
            
            current_user = self.auth_manager.get_current_user()
            current_uid = current_user['uid'] if current_user else None
            
            online_users = []
            current_time = int(time.time() * 1000)
            timeout = 30 * 60 * 1000  # 30 minutes timeout
            
            for uid, user_data in data.items():
                # Skip current user and check if user is recently active
                if uid != current_uid and isinstance(user_data, dict):
                    last_seen = user_data.get('last_seen', 0)
                    if current_time - last_seen < timeout:
                        online_users.append({
                            'uid': uid,
                            'email': user_data.get('email', ''),
                            'public_key': user_data.get('public_key', ''),
                            'status': user_data.get('status', 'offline'),
                            'last_seen': last_seen
                        })
            
            return online_users
            
        except Exception as e:
            print(f"Failed to get online users: {e}")
            return []
    
    def send_chat_request(self, target_uid: str, message: str = "Hello! Let's chat securely.") -> bool:
        """
        Send a chat request to another user.
        
        Args:
            target_uid: Target user's UID
            message: Optional request message
        
        Returns:
            True if request sent successfully, False otherwise
        """
        try:
            current_user = self.auth_manager.get_current_user()
            if not current_user:
                return False
            
            request_data = {
                "from_uid": current_user['uid'],
                "from_email": current_user['email'],
                "message": message,
                "timestamp": int(time.time() * 1000),
                "status": "pending"
            }
            
            # Generate unique request ID
            request_id = f"{current_user['uid']}_{int(time.time() * 1000)}"
            path = f"requests/{target_uid}/{request_id}"
            
            return self._write_data(path, request_data)
            
        except Exception as e:
            print(f"Failed to send chat request: {e}")
            return False
    
    def respond_to_chat_request(self, requester_uid: str, request_id: str, 
                               accept: bool, local_ip: str = None) -> bool:
        """
        Respond to a chat request.
        
        Args:
            requester_uid: UID of the user who sent the request
            request_id: Unique request identifier
            accept: True to accept, False to decline
            local_ip: Local IP address (required if accepting)
        
        Returns:
            True if response sent successfully, False otherwise
        """
        try:
            current_user = self.auth_manager.get_current_user()
            if not current_user:
                return False
            
            # Update request status
            request_path = f"requests/{current_user['uid']}/{request_id}"
            status_update = {
                "status": "accepted" if accept else "declined",
                "response_timestamp": int(time.time() * 1000)
            }
            
            if not self._update_data(request_path, status_update):
                return False
            
            if accept and local_ip:
                # Create private chat channel with IP address
                chat_id = f"chat_{min(current_user['uid'], requester_uid)}_{max(current_user['uid'], requester_uid)}"
                chat_data = {
                    "participants": {
                        current_user['uid']: {
                            "email": current_user['email'],
                            "ip": local_ip,
                            "port": self.config.get('network.default_port', 8888)
                        },
                        requester_uid: {
                            "email": "",  # Will be filled by requester
                            "ip": "",
                            "port": 0
                        }
                    },
                    "created_at": int(time.time() * 1000),
                    "status": "active"
                }
                
                chat_path = f"chats/{chat_id}"
                return self._write_data(chat_path, chat_data)
            
            return True
            
        except Exception as e:
            print(f"Failed to respond to chat request: {e}")
            return False
    
    def get_chat_connection_info(self, chat_id: str) -> Optional[Dict[str, Any]]:
        """
        Get connection information for a chat.
        
        Args:
            chat_id: Chat identifier
        
        Returns:
            Chat data dictionary or None if not found
        """
        try:
            path = f"chats/{chat_id}"
            return self._read_data(path)
        except Exception as e:
            print(f"Failed to get chat info: {e}")
            return None
    
    def check_sent_requests_responses(self) -> List[Dict[str, Any]]:
        """
        Check for responses to chat requests we sent.
        
        Returns:
            List of accepted requests with connection info
        """
        try:
            current_user = self.auth_manager.get_current_user()
            if not current_user:
                return []
            
            accepted_requests = []
            
            # Check all users' request folders for our requests
            lobby_data = self._read_data("lobby")
            if not lobby_data:
                return []
            
            for user_uid in lobby_data.keys():
                if user_uid == current_user['uid']:
                    continue
                    
                # Check requests sent to this user
                requests_path = f"requests/{user_uid}"
                user_requests = self._read_data(requests_path)
                
                if user_requests:
                    for request_id, request_data in user_requests.items():
                        if (isinstance(request_data, dict) and 
                            request_data.get('from_uid') == current_user['uid'] and
                            request_data.get('status') == 'accepted'):
                            
                            # Check if we have chat connection info
                            chat_id = f"chat_{min(current_user['uid'], user_uid)}_{max(current_user['uid'], user_uid)}"
                            chat_info = self.get_chat_connection_info(chat_id)
                            
                            if chat_info:
                                # Get target user's email from lobby data
                                target_email = lobby_data.get(user_uid, {}).get('email', 'Unknown')
                                
                                accepted_requests.append({
                                    'request_id': request_id,
                                    'target_uid': user_uid,
                                    'target_email': target_email,
                                    'chat_id': chat_id,
                                    'chat_info': chat_info
                                })
            
            return accepted_requests
            
        except Exception as e:
            print(f"Failed to check sent requests: {e}")
            return []

    def update_chat_connection_info(self, chat_id: str, local_ip: str) -> bool:
        """
        Update local connection info in chat.
        
        Args:
            chat_id: Chat identifier
            local_ip: Local IP address
        
        Returns:
            True if updated successfully, False otherwise
        """
        try:
            current_user = self.auth_manager.get_current_user()
            if not current_user:
                return False
            
            update_data = {
                f"participants/{current_user['uid']}/ip": local_ip,
                f"participants/{current_user['uid']}/port": self.config.get('network.default_port', 8888),
                f"participants/{current_user['uid']}/email": current_user['email']
            }
            
            path = f"chats/{chat_id}"
            return self._update_data(path, update_data)
            
        except Exception as e:
            print(f"Failed to update chat info: {e}")
            return False
    
    def listen_for_requests(self, callback: Callable[[Dict[str, Any]], None]):
        """
        Listen for incoming chat requests.
        
        Args:
            callback: Function to call when request received
        """
        current_user = self.auth_manager.get_current_user()
        if not current_user:
            return
        
        path = f"requests/{current_user['uid']}"
        self._start_listener(path, callback)
    
    def listen_for_chat_updates(self, chat_id: str, callback: Callable[[Dict[str, Any]], None]):
        """
        Listen for updates to a specific chat.
        
        Args:
            chat_id: Chat identifier
            callback: Function to call when chat updated
        """
        path = f"chats/{chat_id}"
        self._start_listener(path, callback)
    
    def stop_listening(self, path: str):
        """
        Stop listening for updates on a path.
        
        Args:
            path: Firebase path to stop listening on
        """
        if path in self.is_listening:
            self.is_listening[path] = False
        
        if path in self.listener_threads:
            self.listener_threads[path].join(timeout=1)
            del self.listener_threads[path]
        
        if path in self.listeners:
            del self.listeners[path]
    
    def cleanup(self):
        """Stop all listeners and cleanup resources."""
        for path in list(self.listeners.keys()):
            self.stop_listening(path)
    
    def _start_listener(self, path: str, callback: Callable[[Dict[str, Any]], None]):
        """
        Start listening for updates on a Firebase path.
        
        Args:
            path: Firebase path to listen on
            callback: Function to call with updates
        """
        if path in self.listeners:
            self.stop_listening(path)
        
        self.listeners[path] = callback
        self.is_listening[path] = True
        
        thread = threading.Thread(
            target=self._listener_loop,
            args=(path, callback),
            daemon=True
        )
        thread.start()
        self.listener_threads[path] = thread
    
    def _listener_loop(self, path: str, callback: Callable[[Dict[str, Any]], None]):
        """
        Polling loop for Firebase changes.
        
        Args:
            path: Firebase path to monitor
            callback: Function to call with changes
        """
        last_data = None
        
        while self.is_listening.get(path, False):
            try:
                current_data = self._read_data(path)
                
                if current_data != last_data:
                    if current_data:
                        callback(current_data)
                    last_data = current_data
                
                time.sleep(2)  # Poll every 2 seconds
                
            except Exception as e:
                print(f"Error in listener for {path}: {e}")
                time.sleep(5)  # Wait longer on error
    
    def _read_data(self, path: str) -> Optional[Dict[str, Any]]:
        """
        Read data from Firebase path.
        
        Args:
            path: Firebase path to read from
        
        Returns:
            Data dictionary or None if not found
        """
        try:
            url = f"{self.database_url}/{path}.json"
            
            # Add auth token as query parameter for Firebase Realtime Database
            params = {}
            user = self.auth_manager.get_current_user()
            if user and hasattr(self.auth_manager, 'id_token') and self.auth_manager.id_token:
                params['auth'] = self.auth_manager.id_token
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None
            else:
                if response.status_code == 401:
                    # 401 Unauthorized - likely due to Firebase security rules
                    # This is expected if the database requires authentication
                    pass
                else:
                    print(f"Firebase read error: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"Firebase read exception: {e}")
            return None
    
    def _write_data(self, path: str, data: Dict[str, Any]) -> bool:
        """
        Write data to Firebase path.
        
        Args:
            path: Firebase path to write to
            data: Data dictionary to write
        
        Returns:
            True if successful, False otherwise
        """
        try:
            url = f"{self.database_url}/{path}.json"
            headers = {'Content-Type': 'application/json'}
            
            # Add auth token as query parameter for Firebase Realtime Database
            params = {}
            user = self.auth_manager.get_current_user()
            if user and hasattr(self.auth_manager, 'id_token') and self.auth_manager.id_token:
                params['auth'] = self.auth_manager.id_token
            
            response = requests.put(
                url,
                data=json.dumps(data),
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                return True
            else:
                print(f"Firebase write failed: HTTP {response.status_code}")
                if response.status_code == 401:
                    print("  - Authentication failed or database rules require authentication")
                elif response.status_code == 403:
                    print("  - Access forbidden - check Firebase database rules")
                return False
            
        except Exception as e:
            print(f"Firebase write exception: {e}")
            return False
    
    def _update_data(self, path: str, updates: Dict[str, Any]) -> bool:
        """
        Update specific fields in Firebase path.
        
        Args:
            path: Firebase path to update
            updates: Dictionary of fields to update
        
        Returns:
            True if successful, False otherwise
        """
        try:
            url = f"{self.database_url}/{path}.json"
            headers = {'Content-Type': 'application/json'}
            
            # Add auth token as query parameter for Firebase Realtime Database
            params = {}
            user = self.auth_manager.get_current_user()
            if user and hasattr(self.auth_manager, 'id_token') and self.auth_manager.id_token:
                params['auth'] = self.auth_manager.id_token
            
            response = requests.patch(
                url,
                data=json.dumps(updates),
                headers=headers,
                params=params,
                timeout=10
            )
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"Firebase update exception: {e}")
            return False
    
    def _delete_data(self, path: str) -> bool:
        """
        Delete data from Firebase path.
        
        Args:
            path: Firebase path to delete
        
        Returns:
            True if successful, False otherwise
        """
        try:
            url = f"{self.database_url}/{path}.json"
            headers = self.auth_manager.get_auth_headers()
            
            response = requests.delete(url, headers=headers, timeout=10)
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"Firebase delete exception: {e}")
            return False


class FirebaseError(Exception):
    """Custom exception for Firebase operations."""
    pass