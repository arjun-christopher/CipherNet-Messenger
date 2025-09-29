"""
Cryptography Manager for CipherNet Messenger
Handles RSA, Blowfish encryption, and SHA-256 hashing operations.

Author: Arjun Christopher
"""

import os
import hashlib
import hmac
import secrets
import base64
from typing import Tuple, Optional, Dict, Any
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, Blowfish
from Crypto.Hash import SHA256, SHA512
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
import json
import time
from attack_tools import hooks


class CryptographyManager:
    """Manages all cryptographic operations for secure communication with enhanced security."""
    
    def __init__(self, rsa_key_size: int = 2048):
        """
        Initialize cryptography manager with enhanced security features.
        
        Args:
            rsa_key_size: Size of RSA keys to generate (enforced to 2048)
        """
        # Enforce RSA-2048 for security compliance
        if rsa_key_size < 2048:
            raise CryptographyError("RSA key size must be at least 2048 bits for security")
        self.rsa_key_size = 2048  # Enforce RSA-2048 standard
        
        self.rsa_key_pair = None
        self.session_key = None
        self.peer_public_keys = {}  # Store peer public keys {peer_id: RSA_key}
        self.session_keys = {}  # Store session keys {peer_id: session_key}
        self.session_metadata = {}  # Store session info {peer_id: metadata}
    
    def generate_rsa_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate RSA-2048 key pair using secure random number generation.
        
        Returns:
            Tuple of (public_key_pem, private_key_pem)
        """
        try:
            # Generate RSA-2048 key pair with proper entropy
            self.rsa_key_pair = RSA.generate(self.rsa_key_size, randfunc=get_random_bytes)
            
            # Export keys in PEM format
            public_key_pem = self.rsa_key_pair.publickey().export_key(format='PEM')
            private_key_pem = self.rsa_key_pair.export_key(format='PEM')
            
            print(f"✅ Generated RSA-{self.rsa_key_size} key pair successfully")
            return public_key_pem, private_key_pem
        except Exception as e:
            raise CryptographyError(f"Failed to generate RSA-{self.rsa_key_size} key pair: {e}")
    
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
    
    def generate_session_key(self, peer_id: str, key_size: int = 256) -> bytes:
        """
        Generate cryptographically secure session key for hybrid encryption.
        
        Args:
            peer_id: Unique identifier for the peer
            key_size: Key size in bits (default: 256 for enhanced security)
        
        Returns:
            Cryptographically secure session key
        """
        try:
            key_bytes = key_size // 8
            
            # Generate cryptographically secure random session key
            session_key = secrets.token_bytes(key_bytes)
            
            # Store session key with metadata
            self.session_keys[peer_id] = session_key
            self.session_metadata[peer_id] = {
                'created_at': time.time(),
                'key_size': key_size,
                'algorithm': 'Blowfish-CBC',
                'status': 'generated'
            }
            
            # Also store as current session key for backward compatibility
            self.session_key = session_key
            
            print(f"✅ Generated {key_size}-bit session key for peer {peer_id}")
            return session_key
        except Exception as e:
            raise CryptographyError(f"Failed to generate session key: {e}")
    
    def encrypt_session_key(self, session_key: bytes, public_key_pem: bytes, peer_id: str) -> Dict[str, Any]:
        """
        Encrypt session key using RSA-2048 with PKCS#1 OAEP standard.
        
        Args:
            session_key: Session key to encrypt
            public_key_pem: Recipient's RSA-2048 public key in PEM format
            peer_id: Unique identifier for the peer
        
        Returns:
            Dictionary containing encrypted session key and metadata
        """
        try:
            # Import and validate public key
            public_key = self.import_public_key(public_key_pem)
            
            # Validate key size for RSA-2048
            if public_key.size_in_bits() != 2048:
                raise CryptographyError(f"Invalid key size: {public_key.size_in_bits()}. RSA-2048 required.")
            
            # Create PKCS#1 OAEP cipher with SHA-256
            cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
            
            # Apply RSA MITM hook if active (for attack demonstration)
            encrypted_key, attacker_key = hooks.rsa_key_exchange_hook(public_key, session_key)
            
            # If MITM attack is active, log the compromise
            if attacker_key:
                print(f"⚠️  RSA MITM ATTACK ACTIVE: Session key compromised for peer {peer_id}")
                # In a real attack, the attacker would store this key for later decryption
            else:
                # Normal encryption path
                encrypted_key = cipher_rsa.encrypt(session_key)
            
            # Store peer's public key
            self.peer_public_keys[peer_id] = public_key
            
            # Create secure key exchange package
            key_exchange_data = {
                'encrypted_session_key': base64.b64encode(encrypted_key).decode('utf-8'),
                'key_size': len(session_key) * 8,
                'encryption_algorithm': 'RSA-2048-OAEP-SHA256',
                'session_algorithm': 'Blowfish-256-CBC',
                'timestamp': int(time.time() * 1000),
                'sender_key_fingerprint': self._calculate_key_fingerprint(self.rsa_key_pair.publickey()),
                'protocol_version': '1.0'
            }
            
            print(f"✅ Encrypted session key for peer {peer_id} using RSA-2048 OAEP")
            return key_exchange_data
            
        except Exception as e:
            raise CryptographyError(f"Failed to encrypt session key with PKCS#1 OAEP: {e}")
    
    def decrypt_session_key(self, key_exchange_data: Dict[str, Any], peer_id: str) -> bytes:
        """
        Decrypt session key using RSA-2048 private key with PKCS#1 OAEP standard.
        
        Args:
            key_exchange_data: Dictionary containing encrypted session key and metadata
            peer_id: Unique identifier for the peer
        
        Returns:
            Decrypted session key
        """
        try:
            if not self.rsa_key_pair:
                raise CryptographyError("No RSA private key available for decryption")
            
            # Validate key exchange data structure
            required_fields = ['encrypted_session_key', 'encryption_algorithm', 'timestamp']
            for field in required_fields:
                if field not in key_exchange_data:
                    raise CryptographyError(f"Missing required field: {field}")
            
            # Validate encryption algorithm
            if key_exchange_data['encryption_algorithm'] != 'RSA-2048-OAEP-SHA256':
                raise CryptographyError(f"Unsupported encryption algorithm: {key_exchange_data['encryption_algorithm']}")
            
            # Decode encrypted session key
            encrypted_key = base64.b64decode(key_exchange_data['encrypted_session_key'])
            
            # Create PKCS#1 OAEP cipher with SHA-256
            cipher_rsa = PKCS1_OAEP.new(self.rsa_key_pair, hashAlgo=SHA256)
            
            # Decrypt session key
            session_key = cipher_rsa.decrypt(encrypted_key)
            
            # Store session key with metadata
            self.session_keys[peer_id] = session_key
            self.session_metadata[peer_id] = {
                'created_at': time.time(),
                'received_at': time.time(),
                'key_size': len(session_key) * 8,
                'algorithm': key_exchange_data.get('session_algorithm', 'Blowfish-256-CBC'),
                'status': 'received',
                'sender_fingerprint': key_exchange_data.get('sender_key_fingerprint', 'unknown')
            }
            
            # Also store as current session key for backward compatibility
            self.session_key = session_key
            
            print(f"✅ Decrypted session key from peer {peer_id} using RSA-2048 OAEP")
            return session_key
            
        except Exception as e:
            raise CryptographyError(f"Failed to decrypt session key with PKCS#1 OAEP: {e}")
    
    def encrypt_message(self, message: str, session_key: Optional[bytes] = None, peer_id: Optional[str] = None) -> bytes:
        """
        Encrypt message using Blowfish.
        
        Args:
            message: Message to encrypt
            session_key: Session key (uses stored key if None)
            peer_id: Peer ID to get session key for (overrides session_key if provided)
        
        Returns:
            Encrypted message with IV prepended
        """
        try:
            # Use peer-specific session key if peer_id provided
            if peer_id:
                key = self.get_session_key(peer_id)
                if not key:
                    raise CryptographyError(f"No session key available for peer {peer_id}")
            else:
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
    
    def decrypt_message(self, encrypted_data: bytes, session_key: Optional[bytes] = None, peer_id: Optional[str] = None) -> str:
        """
        Decrypt message using Blowfish.
        
        Args:
            encrypted_data: Encrypted message with IV
            session_key: Session key (uses stored key if None)
            peer_id: Peer ID to get session key for (overrides session_key if provided)
        
        Returns:
            Decrypted message string
        """
        try:
            # Use peer-specific session key if peer_id provided
            if peer_id:
                key = self.get_session_key(peer_id)
                if not key:
                    raise CryptographyError(f"No session key available for peer {peer_id}")
            else:
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
    
    def calculate_hmac(self, message: str, session_key: Optional[bytes] = None, peer_id: Optional[str] = None) -> bytes:
        """
        Calculate HMAC-SHA256 for message authentication.
        
        Args:
            message: Message to authenticate
            session_key: Key for HMAC (uses stored key if None)
            peer_id: Peer ID to get session key for (overrides session_key if provided)
        
        Returns:
            HMAC digest
        """
        try:
            # Use peer-specific session key if peer_id provided
            if peer_id:
                key = self.get_session_key(peer_id)
                if not key:
                    raise CryptographyError(f"No session key available for peer {peer_id}")
            else:
                key = session_key or self.session_key
                if not key:
                    raise CryptographyError("No session key available")
            
            message_bytes = message.encode('utf-8')
            
            # Apply HMAC tampering hook if active (for attack demonstration)
            tampered_message, hmac_digest = hooks.hmac_message_hook(key, message_bytes)
            
            # If tampering occurred, log the attack
            if tampered_message != message_bytes:
                print(f"⚠️  HMAC TAMPERING ATTACK ACTIVE: Message modified before authentication")
                return hmac_digest
            else:
                # Normal HMAC calculation
                return hmac.new(key, message_bytes, hashlib.sha256).digest()
        except Exception as e:
            raise CryptographyError(f"Failed to calculate HMAC: {e}")
    
    def verify_hmac(self, message: str, received_hmac: bytes, session_key: Optional[bytes] = None, peer_id: Optional[str] = None) -> bool:
        """
        Verify HMAC-SHA256 for message authentication.
        
        Args:
            message: Original message
            received_hmac: Received HMAC to verify
            session_key: Key for HMAC (uses stored key if None)
            peer_id: Peer ID to get session key for (overrides session_key if provided)
        
        Returns:
            True if HMAC is valid, False otherwise
        """
        try:
            calculated_hmac = self.calculate_hmac(message, session_key, peer_id)
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
            # Read file first
            with open(file_path, "rb") as f:
                file_bytes = f.read()
            
            # Calculate expected hash
            expected_hash = hashlib.sha256(file_bytes).hexdigest()
            
            # Apply SHA256 bypass hook if active (for attack demonstration)
            processed_file, returned_hash = hooks.sha256_file_hook(file_bytes, expected_hash)
            
            # If bypass attack is active, log the compromise
            if processed_file != file_bytes:
                print(f"⚠️  SHA256 BYPASS ATTACK ACTIVE: Fake file with legitimate hash for {file_path}")
                # Note: In a real attack scenario, the fake file would be written to the destination
                # For demonstration, we just return the legitimate hash with logged warning
            
            return returned_hash
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
            # Calculate expected hash
            expected_hash = hashlib.sha256(data).hexdigest()
            
            # Apply SHA256 bypass hook if active (for attack demonstration)
            processed_data, returned_hash = hooks.sha256_file_hook(data, expected_hash)
            
            # If bypass attack is active, log the compromise
            if processed_data != data:
                print(f"⚠️  SHA256 BYPASS ATTACK ACTIVE: Fake data with legitimate hash")
                print(f"   Original data size: {len(data)} bytes")
                print(f"   Fake data size: {len(processed_data)} bytes")
                # Note: In a real attack, the fake data would replace the original
                # For demonstration, we return the legitimate hash with logged warning
            
            return returned_hash
        except Exception as e:
            raise CryptographyError(f"Failed to calculate data hash: {e}")


    def _calculate_key_fingerprint(self, public_key: RSA.RsaKey) -> str:
        """
        Calculate SHA-256 fingerprint of RSA public key.
        
        Args:
            public_key: RSA public key
        
        Returns:
            Hexadecimal fingerprint string
        """
        try:
            key_data = public_key.export_key(format='DER')
            fingerprint = hashlib.sha256(key_data).hexdigest()
            # Format as colon-separated pairs for readability
            return ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
        except Exception as e:
            raise CryptographyError(f"Failed to calculate key fingerprint: {e}")
    
    def validate_peer_public_key(self, public_key_pem: bytes, expected_fingerprint: str = None) -> bool:
        """
        Validate peer's RSA public key meets security requirements.
        
        Args:
            public_key_pem: Public key in PEM format
            expected_fingerprint: Optional expected key fingerprint
        
        Returns:
            True if key is valid, False otherwise
        """
        try:
            public_key = self.import_public_key(public_key_pem)
            
            # Validate key size (must be RSA-2048 or higher)
            if public_key.size_in_bits() < 2048:
                print(f"❌ Invalid key size: {public_key.size_in_bits()} bits. Minimum 2048 required.")
                return False
            
            # Validate key fingerprint if provided
            if expected_fingerprint:
                actual_fingerprint = self._calculate_key_fingerprint(public_key)
                if actual_fingerprint != expected_fingerprint:
                    print(f"❌ Key fingerprint mismatch. Expected: {expected_fingerprint}, Got: {actual_fingerprint}")
                    return False
            
            print(f"✅ Public key validation successful ({public_key.size_in_bits()} bits)")
            return True
            
        except Exception as e:
            print(f"❌ Public key validation failed: {e}")
            return False
    
    def get_session_key(self, peer_id: str) -> Optional[bytes]:
        """
        Get session key for specific peer.
        
        Args:
            peer_id: Unique identifier for the peer
        
        Returns:
            Session key bytes or None if not found
        """
        return self.session_keys.get(peer_id)
    
    def has_session_key(self, peer_id: str) -> bool:
        """
        Check if session key exists for peer.
        
        Args:
            peer_id: Unique identifier for the peer
        
        Returns:
            True if session key exists, False otherwise
        """
        return peer_id in self.session_keys
    
    def clear_session_data(self, peer_id: str = None):
        """
        Clear session data for specific peer or all peers.
        
        Args:
            peer_id: Peer to clear data for, or None to clear all
        """
        try:
            if peer_id:
                # Clear specific peer's session data
                self.session_keys.pop(peer_id, None)
                self.session_metadata.pop(peer_id, None)
                self.peer_public_keys.pop(peer_id, None)
                print(f"✅ Cleared session data for peer {peer_id}")
            else:
                # Clear all session data
                self.session_keys.clear()
                self.session_metadata.clear()
                self.peer_public_keys.clear()
                self.session_key = None
                print("✅ Cleared all session data")
        except Exception as e:
            print(f"Error clearing session data: {e}")
    
    def get_session_info(self, peer_id: str) -> Optional[Dict[str, Any]]:
        """
        Get session information for specific peer.
        
        Args:
            peer_id: Unique identifier for the peer
        
        Returns:
            Session metadata dictionary or None if not found
        """
        return self.session_metadata.get(peer_id)
    
    def create_secure_handshake_data(self, peer_id: str) -> Dict[str, Any]:
        """
        Create secure handshake data for session initiation.
        
        Args:
            peer_id: Target peer identifier
        
        Returns:
            Handshake data dictionary
        """
        try:
            if not self.rsa_key_pair:
                raise CryptographyError("No RSA key pair available for handshake")
            
            public_key_pem = self.rsa_key_pair.publickey().export_key(format='PEM')
            key_fingerprint = self._calculate_key_fingerprint(self.rsa_key_pair.publickey())
            
            handshake_data = {
                'protocol_version': '1.0',
                'encryption_algorithms': ['RSA-2048-OAEP-SHA256'],
                'session_algorithms': ['Blowfish-256-CBC'],
                'public_key': base64.b64encode(public_key_pem).decode('utf-8'),
                'key_fingerprint': key_fingerprint,
                'timestamp': int(time.time() * 1000),
                'supported_features': ['file_transfer', 'message_authentication']
            }
            
            return handshake_data
            
        except Exception as e:
            raise CryptographyError(f"Failed to create handshake data: {e}")


class CryptographyError(Exception):
    """Custom exception for cryptography operations."""
    pass