"""
Tests for Cryptography Manager
Tests RSA encryption, Blowfish encryption, HMAC, and file hashing functionality.

Author: Arjun Christopher
"""

import pytest
import tempfile
import os
from pathlib import Path
from Crypto.PublicKey import RSA

import sys
sys.path.append(str(Path(__file__).parent.parent / "src"))

from crypto_manager import CryptographyManager, CryptographyError


class TestCryptographyManager:
    """Test cases for CryptographyManager class."""
    
    def test_rsa_keypair_generation(self):
        """Test RSA key pair generation."""
        crypto_manager = CryptographyManager(1024)  # Smaller key for faster tests
        
        public_key_pem, private_key_pem = crypto_manager.generate_rsa_keypair()
        
        # Verify key format
        assert public_key_pem.startswith(b'-----BEGIN PUBLIC KEY-----')
        assert private_key_pem.startswith(b'-----BEGIN RSA PRIVATE KEY-----')
        
        # Verify keys can be imported
        public_key = RSA.import_key(public_key_pem)
        private_key = RSA.import_key(private_key_pem)
        
        assert public_key.size_in_bits() == 1024
        assert private_key.size_in_bits() == 1024
    
    def test_import_public_key(self, sample_rsa_keys):
        """Test importing RSA public key."""
        crypto_manager = CryptographyManager()
        public_key_pem, _ = sample_rsa_keys
        
        imported_key = crypto_manager.import_public_key(public_key_pem)
        
        assert imported_key.has_private() == False
        assert imported_key.can_encrypt() == True
    
    def test_import_invalid_public_key(self):
        """Test importing invalid public key."""
        crypto_manager = CryptographyManager()
        
        with pytest.raises(CryptographyError):
            crypto_manager.import_public_key(b"invalid key data")
    
    def test_session_key_generation(self):
        """Test session key generation."""
        crypto_manager = CryptographyManager()
        
        # Test default key size (128 bits = 16 bytes)
        session_key = crypto_manager.generate_session_key()
        assert len(session_key) == 16
        assert isinstance(session_key, bytes)
        
        # Test custom key size (256 bits = 32 bytes)
        session_key_256 = crypto_manager.generate_session_key(256)
        assert len(session_key_256) == 32
    
    def test_session_key_encryption_decryption(self, sample_rsa_keys):
        """Test session key encryption and decryption."""
        crypto_manager = CryptographyManager()
        public_key_pem, private_key_pem = sample_rsa_keys
        
        # Generate key pair for crypto manager
        crypto_manager.rsa_key_pair = RSA.import_key(private_key_pem)
        
        # Generate session key
        original_session_key = crypto_manager.generate_session_key()
        
        # Encrypt session key
        encrypted_key = crypto_manager.encrypt_session_key(original_session_key, public_key_pem)
        assert len(encrypted_key) > 0
        
        # Decrypt session key
        decrypted_key = crypto_manager.decrypt_session_key(encrypted_key)
        assert decrypted_key == original_session_key
    
    def test_session_key_encryption_without_key(self):
        """Test session key encryption with invalid key."""
        crypto_manager = CryptographyManager()
        session_key = crypto_manager.generate_session_key()
        
        with pytest.raises(CryptographyError):
            crypto_manager.encrypt_session_key(session_key, b"invalid key")
    
    def test_session_key_decryption_without_key(self):
        """Test session key decryption without RSA key pair."""
        crypto_manager = CryptographyManager()
        
        with pytest.raises(CryptographyError):
            crypto_manager.decrypt_session_key(b"encrypted data")
    
    def test_message_encryption_decryption(self):
        """Test message encryption and decryption with Blowfish."""
        crypto_manager = CryptographyManager()
        
        # Generate session key
        session_key = crypto_manager.generate_session_key()
        test_message = "Hello, this is a test message for encryption!"
        
        # Encrypt message
        encrypted_data = crypto_manager.encrypt_message(test_message, session_key)
        assert len(encrypted_data) > len(test_message)
        assert encrypted_data != test_message.encode()
        
        # Decrypt message
        decrypted_message = crypto_manager.decrypt_message(encrypted_data, session_key)
        assert decrypted_message == test_message
    
    def test_message_encryption_without_key(self):
        """Test message encryption without session key."""
        crypto_manager = CryptographyManager()
        
        with pytest.raises(CryptographyError):
            crypto_manager.encrypt_message("test message")
    
    def test_message_decryption_with_wrong_key(self):
        """Test message decryption with wrong session key."""
        crypto_manager = CryptographyManager()
        
        # Encrypt with one key
        key1 = crypto_manager.generate_session_key()
        encrypted_data = crypto_manager.encrypt_message("test message", key1)
        
        # Try to decrypt with different key
        key2 = crypto_manager.generate_session_key()
        
        with pytest.raises(CryptographyError):
            crypto_manager.decrypt_message(encrypted_data, key2)
    
    def test_unicode_message_encryption(self):
        """Test encryption of unicode messages."""
        crypto_manager = CryptographyManager()
        session_key = crypto_manager.generate_session_key()
        
        # Test various unicode characters
        unicode_message = "Hello 🔒 Encrypted Message! 中文 العربية Русский"
        
        encrypted_data = crypto_manager.encrypt_message(unicode_message, session_key)
        decrypted_message = crypto_manager.decrypt_message(encrypted_data, session_key)
        
        assert decrypted_message == unicode_message
    
    def test_hmac_calculation_and_verification(self):
        """Test HMAC calculation and verification."""
        crypto_manager = CryptographyManager()
        session_key = crypto_manager.generate_session_key()
        test_message = "Test message for HMAC verification"
        
        # Calculate HMAC
        hmac_digest = crypto_manager.calculate_hmac(test_message, session_key)
        assert len(hmac_digest) == 32  # SHA-256 produces 32-byte digest
        
        # Verify HMAC
        is_valid = crypto_manager.verify_hmac(test_message, hmac_digest, session_key)
        assert is_valid == True
        
        # Test with modified message
        modified_message = "Modified test message"
        is_valid_modified = crypto_manager.verify_hmac(modified_message, hmac_digest, session_key)
        assert is_valid_modified == False
    
    def test_hmac_with_different_keys(self):
        """Test HMAC with different keys."""
        crypto_manager = CryptographyManager()
        
        key1 = crypto_manager.generate_session_key()
        key2 = crypto_manager.generate_session_key()
        message = "Test message"
        
        # Calculate HMAC with key1
        hmac1 = crypto_manager.calculate_hmac(message, key1)
        
        # Verify with key2 (should fail)
        is_valid = crypto_manager.verify_hmac(message, hmac1, key2)
        assert is_valid == False
    
    def test_hmac_without_key(self):
        """Test HMAC calculation without session key."""
        crypto_manager = CryptographyManager()
        
        with pytest.raises(CryptographyError):
            crypto_manager.calculate_hmac("test message")
    
    def test_file_hash_calculation(self, temp_test_file):
        """Test file hash calculation."""
        crypto_manager = CryptographyManager()
        
        # Calculate hash
        file_hash = crypto_manager.calculate_file_hash(temp_test_file)
        
        # Verify hash format (SHA-256 hex string)
        assert len(file_hash) == 64  # 32 bytes * 2 hex chars per byte
        assert all(c in '0123456789abcdef' for c in file_hash.lower())
        
        # Calculate hash again (should be same)
        file_hash2 = crypto_manager.calculate_file_hash(temp_test_file)
        assert file_hash == file_hash2
    
    def test_file_hash_nonexistent_file(self):
        """Test file hash calculation for nonexistent file."""
        crypto_manager = CryptographyManager()
        
        with pytest.raises(CryptographyError):
            crypto_manager.calculate_file_hash("nonexistent_file.txt")
    
    def test_data_hash_calculation(self):
        """Test raw data hash calculation."""
        crypto_manager = CryptographyManager()
        
        test_data = b"This is test data for hashing"
        data_hash = crypto_manager.calculate_data_hash(test_data)
        
        # Verify hash format
        assert len(data_hash) == 64
        assert all(c in '0123456789abcdef' for c in data_hash.lower())
        
        # Same data should produce same hash
        data_hash2 = crypto_manager.calculate_data_hash(test_data)
        assert data_hash == data_hash2
        
        # Different data should produce different hash
        different_data = b"Different test data"
        different_hash = crypto_manager.calculate_data_hash(different_data)
        assert data_hash != different_hash
    
    def test_empty_data_hash(self):
        """Test hash calculation for empty data."""
        crypto_manager = CryptographyManager()
        
        empty_hash = crypto_manager.calculate_data_hash(b"")
        assert len(empty_hash) == 64
        
        # SHA-256 hash of empty string
        expected_empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert empty_hash == expected_empty_hash
    
    def test_large_message_encryption(self):
        """Test encryption of large messages."""
        crypto_manager = CryptographyManager()
        session_key = crypto_manager.generate_session_key()
        
        # Create large message (10KB)
        large_message = "A" * 10240
        
        encrypted_data = crypto_manager.encrypt_message(large_message, session_key)
        decrypted_message = crypto_manager.decrypt_message(encrypted_data, session_key)
        
        assert decrypted_message == large_message
    
    def test_multiple_session_keys(self):
        """Test using multiple session keys simultaneously."""
        crypto_manager = CryptographyManager()
        
        # Generate multiple keys
        key1 = crypto_manager.generate_session_key()
        key2 = crypto_manager.generate_session_key()
        key3 = crypto_manager.generate_session_key()
        
        message1 = "Message for key 1"
        message2 = "Message for key 2"
        message3 = "Message for key 3"
        
        # Encrypt with different keys
        encrypted1 = crypto_manager.encrypt_message(message1, key1)
        encrypted2 = crypto_manager.encrypt_message(message2, key2)
        encrypted3 = crypto_manager.encrypt_message(message3, key3)
        
        # Decrypt with corresponding keys
        decrypted1 = crypto_manager.decrypt_message(encrypted1, key1)
        decrypted2 = crypto_manager.decrypt_message(encrypted2, key2)
        decrypted3 = crypto_manager.decrypt_message(encrypted3, key3)
        
        assert decrypted1 == message1
        assert decrypted2 == message2
        assert decrypted3 == message3
    
    def test_stored_session_key_usage(self):
        """Test using stored session key in crypto manager."""
        crypto_manager = CryptographyManager()
        
        # Generate and store session key
        session_key = crypto_manager.generate_session_key()
        message = "Test message with stored key"
        
        # Encrypt without explicitly passing key (should use stored key)
        encrypted_data = crypto_manager.encrypt_message(message)
        
        # Decrypt without explicitly passing key
        decrypted_message = crypto_manager.decrypt_message(encrypted_data)
        
        assert decrypted_message == message