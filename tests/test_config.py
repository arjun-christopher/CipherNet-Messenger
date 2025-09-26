"""
Tests for Configuration Management
Tests the Config class functionality including loading, saving, and accessing configuration values.

Author: Arjun Christopher
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open

import sys
sys.path.append(str(Path(__file__).parent.parent / "src"))

from config import Config


class TestConfig:
    """Test cases for Config class."""
    
    def test_default_config_loading(self):
        """Test that default configuration is loaded correctly."""
        config = Config("nonexistent.json")
        
        assert config.get("app.name") == "CipherNet Messenger"
        assert config.get("network.default_port") == 8888
        assert config.get("security.rsa_key_size") == 2048
        assert config.get("ui.theme") == "dark"
    
    def test_config_file_loading(self, temp_config):
        """Test loading configuration from file."""
        config = Config(temp_config)
        
        assert config.get("app.name") == "CipherNet Messenger Test"
        assert config.get("network.default_port") == 8889
        assert config.get("security.rsa_key_size") == 1024
    
    def test_config_get_with_default(self):
        """Test getting configuration values with default fallback."""
        config = Config("nonexistent.json")
        
        # Existing key
        assert config.get("app.name") == "CipherNet Messenger"
        
        # Non-existing key with default
        assert config.get("nonexistent.key", "default_value") == "default_value"
        
        # Non-existing key without default
        assert config.get("nonexistent.key") is None
    
    def test_config_set(self):
        """Test setting configuration values."""
        config = Config("nonexistent.json")
        
        # Set new value
        config.set("app.custom_setting", "test_value")
        assert config.get("app.custom_setting") == "test_value"
        
        # Set nested value
        config.set("new.nested.value", 42)
        assert config.get("new.nested.value") == 42
    
    def test_config_save(self, tmp_path):
        """Test saving configuration to file."""
        config_file = tmp_path / "test_config.json"
        config = Config(str(config_file))
        
        # Modify configuration
        config.set("app.test_key", "test_value")
        
        # Save configuration
        config.save_config()
        
        # Verify file was created and contains correct data
        assert config_file.exists()
        
        with open(config_file, 'r') as f:
            saved_data = json.load(f)
        
        assert saved_data["app"]["test_key"] == "test_value"
    
    def test_firebase_configuration_check(self):
        """Test Firebase configuration validation."""
        config = Config("nonexistent.json")
        
        # Default config should not be configured
        assert not config.is_firebase_configured()
        
        # Set required Firebase fields
        config.set("firebase.api_key", "test-key")
        config.set("firebase.auth_domain", "test.firebaseapp.com")
        config.set("firebase.database_url", "https://test.firebaseio.com")
        config.set("firebase.project_id", "test-project")
        
        assert config.is_firebase_configured()
    
    def test_get_firebase_config(self):
        """Test getting Firebase configuration dictionary."""
        config = Config("nonexistent.json")
        
        firebase_config = config.get_firebase_config()
        
        assert isinstance(firebase_config, dict)
        assert "api_key" in firebase_config
        assert "auth_domain" in firebase_config
        assert "database_url" in firebase_config
    
    def test_config_merge(self, tmp_path):
        """Test configuration merging from file."""
        config_file = tmp_path / "merge_test.json"
        
        # Create partial config file
        partial_config = {
            "app": {
                "name": "Custom App Name",
                "custom_field": "custom_value"
            },
            "network": {
                "default_port": 9999
            }
        }
        
        with open(config_file, 'w') as f:
            json.dump(partial_config, f)
        
        config = Config(str(config_file))
        
        # Check merged values
        assert config.get("app.name") == "Custom App Name"
        assert config.get("app.custom_field") == "custom_value"
        assert config.get("network.default_port") == 9999
        
        # Check that non-overridden values remain
        assert config.get("security.rsa_key_size") == 2048
        assert config.get("ui.theme") == "dark"
    
    def test_invalid_json_handling(self, tmp_path):
        """Test handling of invalid JSON files."""
        config_file = tmp_path / "invalid.json"
        
        # Create invalid JSON file
        with open(config_file, 'w') as f:
            f.write("{ invalid json content")
        
        # Should not raise exception, should use defaults
        config = Config(str(config_file))
        assert config.get("app.name") == "CipherNet Messenger"
    
    def test_config_dot_notation_edge_cases(self):
        """Test edge cases in dot notation access."""
        config = Config("nonexistent.json")
        
        # Empty key
        assert config.get("") is None
        
        # Single key (no dots)
        config.config_data["single_key"] = "single_value"
        assert config.get("single_key") == "single_value"
        
        # Deep nesting
        config.set("level1.level2.level3.level4", "deep_value")
        assert config.get("level1.level2.level3.level4") == "deep_value"
    
    @patch('builtins.open', side_effect=IOError("Permission denied"))
    def test_save_config_io_error(self, mock_file_open):
        """Test handling IO errors during config save."""
        config = Config("nonexistent.json")
        
        # Should not raise exception
        config.save_config()
        
        # Verify the mock was called
        mock_file_open.assert_called_once()
    
    def test_config_type_preservation(self):
        """Test that configuration value types are preserved."""
        config = Config("nonexistent.json")
        
        # Test different data types
        config.set("string_value", "test")
        config.set("int_value", 42)
        config.set("float_value", 3.14)
        config.set("bool_value", True)
        config.set("list_value", [1, 2, 3])
        config.set("dict_value", {"key": "value"})
        
        assert isinstance(config.get("string_value"), str)
        assert isinstance(config.get("int_value"), int)
        assert isinstance(config.get("float_value"), float)
        assert isinstance(config.get("bool_value"), bool)
        assert isinstance(config.get("list_value"), list)
        assert isinstance(config.get("dict_value"), dict)