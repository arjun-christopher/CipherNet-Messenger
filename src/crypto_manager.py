"""
Cryptography Manager for CipherNet Messenger
Handles RSA, Blowfish encryption, and SHA-256 hashing operations.

Author: Arjun Christopher
"""

import os
import hashlib
import hmac
from typing import Tuple, bytes, Optional
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, Blowfish
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class CryptographyManager:
    """Manages all cryptographic operations for secure communication."""
    
    def __init__(self, rsa_key_size: int = 2048):
        """
        Initialize cryptography manager.
        
        Args:
            rsa_key_size: Size of RSA keys to generate
        """
        self.rsa_key_size = rsa_key_size
        self.rsa_key_pair = None
        self.session_key = None
    
    def generate_rsa_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate RSA key pair.
        
        Returns:
            Tuple of (public_key_pem, private_key_pem)
        """
        try:
            self.rsa_key_pair = RSA.generate(self.rsa_key_size)
            public_key_pem = self.rsa_key_pair.publickey().export_key()
            private_key_pem = self.rsa_key_pair.export_key()
            return public_key_pem, private_key_pem
        except Exception as e:
            raise CryptographyError(f"Failed to generate RSA key pair: {e}")
    
    def import_public_key(self, public_key_pem: bytes) -> RSA.RsaKey:
        """
        Import RSA public key from PEM format.
        
        Args:
            public_key_pem: Public key in PEM format
        
        Returns:
            RSA public key object
        """
        try:
            return RSA.import_key(public_key_pem)
        except Exception as e:
            raise CryptographyError(f"Failed to import public key: {e}")
    
    def generate_session_key(self, key_size: int = 128) -> bytes:
        """
        Generate random session key for Blowfish encryption.
        
        Args:
            key_size: Key size in bits (default: 128)
        
        Returns:
            Random session key
        """
        try:
            key_bytes = key_size // 8
            self.session_key = get_random_bytes(key_bytes)
            return self.session_key
        except Exception as e:
            raise CryptographyError(f"Failed to generate session key: {e}")
    
    def encrypt_session_key(self, session_key: bytes, public_key_pem: bytes) -> bytes:
        """
        Encrypt session key using RSA-OAEP.
        
        Args:
            session_key: Session key to encrypt
            public_key_pem: Recipient's public key
        
        Returns:
            Encrypted session key
        """
        try:
            public_key = self.import_public_key(public_key_pem)
            cipher_rsa = PKCS1_OAEP.new(public_key)
            encrypted_key = cipher_rsa.encrypt(session_key)
            return encrypted_key
        except Exception as e:
            raise CryptographyError(f"Failed to encrypt session key: {e}")
    
    def decrypt_session_key(self, encrypted_key: bytes) -> bytes:
        """
        Decrypt session key using RSA private key.
        
        Args:
            encrypted_key: Encrypted session key
        
        Returns:
            Decrypted session key
        """
        try:
            if not self.rsa_key_pair:
                raise CryptographyError("No RSA key pair available")
            
            cipher_rsa = PKCS1_OAEP.new(self.rsa_key_pair)
            session_key = cipher_rsa.decrypt(encrypted_key)
            self.session_key = session_key
            return session_key
        except Exception as e:
            raise CryptographyError(f"Failed to decrypt session key: {e}")
    
    def encrypt_message(self, message: str, session_key: Optional[bytes] = None) -> bytes:
        """
        Encrypt message using Blowfish.
        
        Args:
            message: Message to encrypt
            session_key: Session key (uses stored key if None)
        
        Returns:
            Encrypted message with IV prepended
        """
        try:
            key = session_key or self.session_key
            if not key:
                raise CryptographyError("No session key available")
            
            message_bytes = message.encode('utf-8')
            
            # Generate random IV
            iv = get_random_bytes(8)  # Blowfish uses 8-byte blocks
            
            # Create cipher and encrypt
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
            padded_message = pad(message_bytes, Blowfish.block_size)
            ciphertext = cipher.encrypt(padded_message)
            
            # Prepend IV to ciphertext
            return iv + ciphertext
        except Exception as e:
            raise CryptographyError(f"Failed to encrypt message: {e}")
    
    def decrypt_message(self, encrypted_data: bytes, session_key: Optional[bytes] = None) -> str:
        """
        Decrypt message using Blowfish.
        
        Args:
            encrypted_data: Encrypted message with IV
            session_key: Session key (uses stored key if None)
        
        Returns:
            Decrypted message string
        """
        try:
            key = session_key or self.session_key
            if not key:
                raise CryptographyError("No session key available")
            
            # Extract IV and ciphertext
            iv = encrypted_data[:8]
            ciphertext = encrypted_data[8:]
            
            # Create cipher and decrypt
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
            padded_message = cipher.decrypt(ciphertext)
            message_bytes = unpad(padded_message, Blowfish.block_size)
            
            return message_bytes.decode('utf-8')
        except Exception as e:
            raise CryptographyError(f"Failed to decrypt message: {e}")
    
    def calculate_hmac(self, message: str, session_key: Optional[bytes] = None) -> bytes:
        """
        Calculate HMAC-SHA256 for message authentication.
        
        Args:
            message: Message to authenticate
            session_key: Key for HMAC (uses stored key if None)
        
        Returns:
            HMAC digest
        """
        try:
            key = session_key or self.session_key
            if not key:
                raise CryptographyError("No session key available")
            
            message_bytes = message.encode('utf-8')
            return hmac.new(key, message_bytes, hashlib.sha256).digest()
        except Exception as e:
            raise CryptographyError(f"Failed to calculate HMAC: {e}")
    
    def verify_hmac(self, message: str, received_hmac: bytes, session_key: Optional[bytes] = None) -> bool:
        """
        Verify HMAC-SHA256 for message authentication.
        
        Args:
            message: Original message
            received_hmac: Received HMAC to verify
            session_key: Key for HMAC (uses stored key if None)
        
        Returns:
            True if HMAC is valid, False otherwise
        """
        try:
            calculated_hmac = self.calculate_hmac(message, session_key)
            return hmac.compare_digest(calculated_hmac, received_hmac)
        except Exception as e:
            raise CryptographyError(f"Failed to verify HMAC: {e}")
    
    def calculate_file_hash(self, file_path: str) -> str:
        """
        Calculate SHA-256 hash of a file.
        
        Args:
            file_path: Path to the file
        
        Returns:
            Hexadecimal hash string
        """
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            raise CryptographyError(f"Failed to calculate file hash: {e}")
    
    def calculate_data_hash(self, data: bytes) -> str:
        """
        Calculate SHA-256 hash of raw data.
        
        Args:
            data: Raw data to hash
        
        Returns:
            Hexadecimal hash string
        """
        try:
            return hashlib.sha256(data).hexdigest()
        except Exception as e:
            raise CryptographyError(f"Failed to calculate data hash: {e}")


class CryptographyError(Exception):
    """Custom exception for cryptography operations."""
    pass