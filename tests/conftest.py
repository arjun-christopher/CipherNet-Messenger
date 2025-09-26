"""
Test Configuration for CipherNet Messenger
Shared test utilities and configuration.

Author: Arjun Christopher
"""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, MagicMock

# Test configuration data
TEST_CONFIG = {
    "app": {
        "name": "CipherNet Messenger Test",
        "version": "1.0.0-test",
        "debug": True
    },
    "network": {
        "default_port": 8889,  # Different port for tests
        "buffer_size": 4096,
        "connection_timeout": 5,
        "file_chunk_size": 1024
    },
    "security": {
        "rsa_key_size": 1024,  # Smaller for faster tests
        "blowfish_key_size": 128,
        "hash_algorithm": "SHA-256",
        "padding_scheme": "OAEP"
    },
    "firebase": {
        "api_key": "test-api-key",
        "auth_domain": "test.firebaseapp.com",
        "database_url": "https://test-default-rtdb.firebaseio.com",
        "project_id": "test-project",
        "storage_bucket": "test.appspot.com",
        "messaging_sender_id": "123456789",
        "app_id": "test-app-id"
    },
    "ui": {
        "theme": "dark",
        "window_width": 800,
        "window_height": 600,
        "font_size": 10
    }
}


@pytest.fixture
def temp_config():
    """Create a temporary configuration file for testing."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(TEST_CONFIG, f, indent=4)
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    Path(temp_path).unlink(missing_ok=True)


@pytest.fixture
def temp_config_with_firebase():
    """Create a temporary configuration file with Firebase settings."""
    firebase_config = TEST_CONFIG.copy()
    firebase_config["firebase"] = {
        "api_key": "config-api-key",
        "auth_domain": "config-project.firebaseapp.com",
        "database_url": "https://config-project-rtdb.firebaseio.com",
        "project_id": "config-project-id",
        "storage_bucket": "config-project.appspot.com",
        "messaging_sender_id": "123456789",
        "app_id": "1:123456789:web:abcdef"
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(firebase_config, f, indent=4)
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    Path(temp_path).unlink(missing_ok=True)


@pytest.fixture
def mock_config():
    """Create a mock configuration object."""
    mock_config = Mock()
    mock_config.get = Mock(side_effect=lambda key, default=None: _get_nested_value(TEST_CONFIG, key, default))
    mock_config.get_firebase_config = Mock(return_value=TEST_CONFIG["firebase"])
    mock_config.is_firebase_configured = Mock(return_value=True)
    return mock_config


@pytest.fixture
def mock_auth_manager():
    """Create a mock authentication manager."""
    mock_auth = Mock()
    mock_auth.get_current_user = Mock(return_value={
        "uid": "test-user-123",
        "email": "test@example.com",
        "email_verified": True,
        "display_name": "Test User"
    })
    mock_auth.get_auth_headers = Mock(return_value={"Authorization": "Bearer test-token"})
    mock_auth.is_authenticated = Mock(return_value=True)
    return mock_auth


@pytest.fixture
def sample_rsa_keys():
    """Generate sample RSA key pair for testing."""
    from Crypto.PublicKey import RSA
    
    key_pair = RSA.generate(1024)  # Smaller key for faster tests
    public_key_pem = key_pair.publickey().export_key()
    private_key_pem = key_pair.export_key()
    
    return public_key_pem, private_key_pem


@pytest.fixture
def sample_message():
    """Sample message for testing."""
    return {
        "type": "text_message",
        "timestamp": "2025-09-26T10:30:00Z",
        "sender": "test-user-123",
        "content": {
            "message": "Hello, this is a test message!"
        }
    }


@pytest.fixture
def temp_test_file():
    """Create a temporary test file."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("This is a test file content for CipherNet Messenger testing.")
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    Path(temp_path).unlink(missing_ok=True)


def _get_nested_value(config_dict, key_path, default=None):
    """Get nested configuration value using dot notation."""
    keys = key_path.split('.')
    value = config_dict
    
    try:
        for key in keys:
            value = value[key]
        return value
    except (KeyError, TypeError):
        return default


class MockFirebaseResponse:
    """Mock Firebase HTTP response."""
    
    def __init__(self, status_code=200, data=None, error=None):
        self.status_code = status_code
        self._data = data
        self._error = error
    
    def json(self):
        if self._error:
            return {"error": {"message": self._error}}
        return self._data


class MockSocket:
    """Mock socket for network testing."""
    
    def __init__(self):
        self.sent_data = []
        self.receive_data = []
        self.closed = False
        self.bound_address = None
    
    def bind(self, address):
        self.bound_address = address
    
    def listen(self, backlog):
        pass
    
    def accept(self):
        client_socket = MockSocket()
        return client_socket, ("127.0.0.1", 12345)
    
    def connect(self, address):
        pass
    
    def send(self, data):
        self.sent_data.append(data)
        return len(data)
    
    def sendall(self, data):
        self.sent_data.append(data)
    
    def recv(self, bufsize):
        if self.receive_data:
            return self.receive_data.pop(0)
        return b""
    
    def close(self):
        self.closed = True
    
    def setsockopt(self, level, optname, value):
        pass
    
    def settimeout(self, timeout):
        pass
    
    def getsockname(self):
        return self.bound_address or ("127.0.0.1", 8888)