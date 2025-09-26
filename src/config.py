"""
Configuration Management for CipherNet Messenger
Handles application settings, Firebase configuration, and security parameters.

.ENV CONFIGURATION:
Create a .env file in the root directory with your Firebase credentials:

FIREBASE_API_KEY=your-firebase-api-key
FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
FIREBASE_DATABASE_URL=https://your-project-default-rtdb.firebaseio.com
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_STORAGE_BUCKET=your-project.appspot.com
FIREBASE_MESSAGING_SENDER_ID=your-sender-id
FIREBASE_APP_ID=your-app-id

FIREBASE SETUP INSTRUCTIONS:
1. Go to https://console.firebase.google.com/
2. Create a new project or select existing project
3. Go to Project Settings > General tab
4. Scroll down to "Your apps" section
5. Click "Add app" > Web app
6. Copy the configuration values to the firebase section above
7. Enable Authentication > Sign-in method > Email/Password
8. Create Realtime Database > Start in test mode

Author: Arjun Christopher
"""

import os
import json
from typing import Dict, Any
from pathlib import Path
from dotenv import load_dotenv


class Config:
    """Configuration manager for CipherNet Messenger."""
    
    def __init__(self, config_file: str = "config.json"):
        """Initialize configuration with default values."""
        # Load environment variables from .env file
        env_path = Path(__file__).parent.parent / ".env"
        load_dotenv(env_path)
        
        self.config_file = Path(__file__).parent.parent / config_file
        self.config_data = self._load_default_config()
        self._load_config()
        self._load_env_variables()
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration values."""
        return {
            "app": {
                "name": "CipherNet Messenger",
                "version": "1.0.0",
                "debug": False
            },
            "network": {
                "default_port": 8888,
                "buffer_size": 4096,
                "connection_timeout": 30,
                "file_chunk_size": 4096
            },
            "security": {
                "rsa_key_size": 2048,
                "blowfish_key_size": 128,
                "hash_algorithm": "SHA-256",
                "padding_scheme": "OAEP"
            },
            "firebase": {
                "api_key": os.getenv("FIREBASE_API_KEY", ""),
                "auth_domain": os.getenv("FIREBASE_AUTH_DOMAIN", ""),
                "database_url": os.getenv("FIREBASE_DATABASE_URL", ""),
                "project_id": os.getenv("FIREBASE_PROJECT_ID", ""),
                "storage_bucket": os.getenv("FIREBASE_STORAGE_BUCKET", ""),
                "messaging_sender_id": os.getenv("FIREBASE_MESSAGING_SENDER_ID", ""),
                "app_id": os.getenv("FIREBASE_APP_ID", "")
            },
            "ui": {
                "theme": "dark",
                "window_width": 1000,
                "window_height": 700,
                "font_size": 12
            }
        }
    
    def _load_config(self):
        """Load configuration from file if it exists."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                    self._merge_config(file_config)
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Could not load config file: {e}")
    
    def _merge_config(self, file_config: Dict[str, Any]):
        """Recursively merge file config with default config."""
        def merge_dict(default: dict, override: dict):
            for key, value in override.items():
                if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                    merge_dict(default[key], value)
                else:
                    default[key] = value
        
        merge_dict(self.config_data, file_config)
    
    def _load_env_variables(self):
        """Load Firebase configuration from environment variables."""
        firebase_config = {
            "api_key": os.getenv("FIREBASE_API_KEY"),
            "auth_domain": os.getenv("FIREBASE_AUTH_DOMAIN"),
            "database_url": os.getenv("FIREBASE_DATABASE_URL"),
            "project_id": os.getenv("FIREBASE_PROJECT_ID"),
            "storage_bucket": os.getenv("FIREBASE_STORAGE_BUCKET"),
            "messaging_sender_id": os.getenv("FIREBASE_MESSAGING_SENDER_ID"),
            "app_id": os.getenv("FIREBASE_APP_ID")
        }
        
        # Update firebase config with environment variables if they exist
        for key, value in firebase_config.items():
            if value is not None and value.strip():
                self.config_data["firebase"][key] = value
    
    def save_config(self):
        """Save current configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config_data, f, indent=4)
        except IOError as e:
            print(f"Error saving config: {e}")
    
    def get(self, key_path: str, default=None):
        """
        Get configuration value using dot notation.
        
        Args:
            key_path: Dot-separated path (e.g., 'network.default_port')
            default: Default value if key not found
        
        Returns:
            Configuration value or default
        """
        keys = key_path.split('.')
        value = self.config_data
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any):
        """
        Set configuration value using dot notation.
        
        Args:
            key_path: Dot-separated path
            value: Value to set
        """
        keys = key_path.split('.')
        config_dict = self.config_data
        
        for key in keys[:-1]:
            if key not in config_dict:
                config_dict[key] = {}
            config_dict = config_dict[key]
        
        config_dict[keys[-1]] = value
    
    def is_firebase_configured(self) -> bool:
        """Check if Firebase configuration is complete."""
        required_fields = ["api_key", "auth_domain", "database_url", "project_id"]
        return all(self.get(f"firebase.{field}") for field in required_fields)
    
    def get_firebase_config(self) -> Dict[str, str]:
        """Get Firebase configuration dictionary."""
        return self.config_data.get("firebase", {})