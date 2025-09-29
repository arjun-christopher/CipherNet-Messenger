"""
CipherNet-Messenger Attack Hooks Moddef _get_attack_state(attack_name):
    \"\"\"Get current attack state from JSON file.\"\"\"
    try:
        states = get_attack_states()
        # Debug: print what we got
        print(f"[DEBUG] _get_attack_state('{attack_name}') - states: {states}")
        result = states.get(attack_name, False)
        print(f"[DEBUG] _get_attack_state('{attack_name}') - result: {result}")
        return result
    except Exception as e:
        print(f"[DEBUG] _get_attack_state('{attack_name}') - exception: {e}")
        return FalseThis file contains cryptographic attack implementations used for security testing
and educational purposes. It provides hook functions that can be activated to
demonstrate various attack vectors against cryptographic protocols:

- RSA Man-in-the-Middle (MITM) attacks
- HMAC message tampering attacks  
- SHA256 hash collision/bypass attacks

These attacks are implemented as hooks that can be toggled on/off via the
attack_ui.py control panel to demonstrate vulnerabilities in secure messaging
systems and help understand cryptographic security principles.

WARNING: This code is for educational and security testing purposes only.
Do not use these techniques against systems you do not own or have explicit
permission to test.

Author: Arjun Christopher
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256

# Import state manager with error handling for different execution contexts
try:
    from .attack_state_manager import get_attack_states
except ImportError:
    try:
        from attack_state_manager import get_attack_states
    except ImportError:
        # Fallback if state manager isn't available
        def get_attack_states():
            return {
                'rsa_mitm_active': False,
                'hmac_tamper_active': False,
                'sha256_bypass_active': False
            }

def _get_attack_state(attack_name):
    """Get current attack state from JSON file."""
    try:
        states = get_attack_states()
        return states.get(attack_name, False)
    except Exception:
        return False

def rsa_key_exchange_hook(victim_pubkey, session_key):
    """
    RSA MAN-IN-THE-MIDDLE (MITM) ATTACK
    
    Attack Steps:
    1. Intercept the legitimate RSA public key exchange between two parties
    2. Generate a new RSA key pair controlled by the attacker
    3. Replace the victim's public key with the attacker's public key
    4. Encrypt the session key with the attacker's public key instead of victim's
    5. The attacker can now decrypt the session key using their private key
    
    Attack Flow:
    Sender -> [Attacker intercepts] -> Receiver
    - Sender thinks they're encrypting with Receiver's key
    - Actually encrypting with Attacker's key
    - Attacker can decrypt, read, modify, and re-encrypt messages
    
    Outcomes:
    - Complete compromise of end-to-end encryption
    - Attacker gains access to all symmetric session keys
    - All subsequent messages can be decrypted and read by attacker
    - Allows for message modification without detection
    - Breaks confidentiality and integrity of the communication channel
    
    Returns: (encrypted_session_key, attacker_key or None)
    """
    # Check if RSA MITM attack is active
    if _get_attack_state('rsa_mitm_active'):
        print("[RSA MITM ATTACK] Intercepting key exchange!")
        print("[RSA MITM] Generating malicious key pair...")
        
        # Generate attacker's key pair
        attacker_key = RSA.generate(2048)
        
        # Create cipher with attacker's public key
        cipher = PKCS1_OAEP.new(attacker_key.publickey())
        
        # Encrypt with attacker's key (this will cause decryption to fail later)
        encrypted = cipher.encrypt(session_key)
        
        print("[RSA MITM] ⚠️  KEY EXCHANGE COMPROMISED!")
        print("[RSA MITM] Victim will receive attacker's encrypted session key")
        print("[RSA MITM] Decryption will fail - secure communication broken!")
        
        # Return the compromised encrypted key that can't be decrypted by victim
        return encrypted, attacker_key
    else:
        # Normal operation: encrypt with legitimate victim's public key
        # Handle both RSA key objects and PEM bytes
        if isinstance(victim_pubkey, bytes):
            victim_key_obj = RSA.import_key(victim_pubkey)
        else:
            victim_key_obj = victim_pubkey
            
        cipher = PKCS1_OAEP.new(victim_key_obj)
        encrypted = cipher.encrypt(session_key)
        return encrypted, None

def hmac_message_hook(key, message):
    """
    HMAC MESSAGE TAMPERING ATTACK
    
    Attack Steps:
    1. Intercept the original message before HMAC calculation
    2. Modify the message content (inject malicious payload)
    3. Calculate a new valid HMAC for the tampered message using the shared key
    4. Send the tampered message with its corresponding valid HMAC
    5. Receiver validates HMAC successfully but receives malicious content
    
    Attack Scenario:
    - Attacker has compromised the sender's system or network path
    - Attacker has access to the HMAC key (through key compromise or MITM)
    - Original message: "Transfer $100 to account ABC"
    - Tampered message: "HACKED: Transfer $100 to account ABC" (or worse modifications)
    
    Attack Prerequisites:
    - Access to the HMAC key (obtained through RSA MITM or other key compromise)
    - Position to intercept and modify messages before they reach recipient
    - Knowledge of the HMAC algorithm being used (SHA256 in this case)
    
    Outcomes:
    - Message integrity is compromised while appearing cryptographically valid
    - Receiver cannot detect tampering since HMAC validation passes
    - Malicious content is delivered with authentic cryptographic signature
    - Can be used to inject commands, modify financial transactions, or spread malware
    - Breaks the fundamental trust model of HMAC authentication
    
    Returns: (message_to_send, hmac_to_send)
    """
    # Check if HMAC tampering attack is active
    if _get_attack_state('hmac_tamper_active'):
        print("[HMAC TAMPERING ATTACK] Intercepting message authentication!")
        
        # ATTACK: Generate invalid HMAC that will cause verification to fail
        fake_hmac = b'\x00' * 32  # Invalid HMAC - all zeros
        
        print("[HMAC TAMPER] ⚠️  MESSAGE AUTHENTICATION COMPROMISED!")
        print("[HMAC TAMPER] Sending message with INVALID HMAC")
        print("[HMAC TAMPER] Recipient HMAC verification will FAIL")
        print("[HMAC TAMPER] Message will be REJECTED as potentially tampered")
        
        # Return original message but with invalid HMAC
        return message, fake_hmac
    else:
        # Normal operation: calculate valid HMAC
        hmac = HMAC.new(key, message, SHA256).digest()
        return message, hmac

def sha256_file_hook(file_bytes, expected_hash):
    """
    SHA256 HASH COLLISION/BYPASS ATTACK
    
    Attack Steps:
    1. Intercept file transfer between sender and receiver
    2. Replace the legitimate file with malicious content
    3. Send the original file's SHA256 hash with the malicious file
    4. Receiver calculates hash of malicious file, compares with provided hash
    5. Hash mismatch should occur, but attack simulates a collision scenario
    
    Attack Mechanics:
    - This simulates a hash collision attack where different content produces same hash
    - In reality, finding SHA256 collisions is computationally infeasible (2^128 operations)
    - This hook demonstrates what would happen if such collision were found
    - Alternatively, represents compromise of hash verification system
    
    Real-world Attack Scenarios:
    1. Hash Collision (theoretical): Attacker finds two files with same SHA256
    2. System Compromise: Attacker modifies hash verification process
    3. Supply Chain Attack: Malicious file injected during build/distribution
    4. Mirror Poisoning: Legitimate file replaced on download servers
    
    Attack Prerequisites:
    - Access to intercept and modify file transfers
    - Ability to replace file content before hash verification
    - Knowledge of expected file hash (obtained through interception)
    
    Outcomes:
    - File integrity verification is completely bypassed
    - Malicious executable/content delivered instead of legitimate file
    - Receiver believes file integrity is intact due to hash match
    - Can deliver malware, backdoors, or corrupted data undetected
    - Breaks fundamental trust in cryptographic hash verification
    - Potential for remote code execution if malicious file is executable
    
    Impact Examples:
    - Software updates replaced with malware
    - Documents replaced with phishing content
    - Media files replaced with malicious payloads
    - Configuration files modified to compromise system security
    
    Returns: (file_bytes_to_send, hash_to_send)
    """
    # Check if SHA256 bypass attack is active
    if _get_attack_state('sha256_bypass_active'):
        print("[SHA256 BYPASS ATTACK] Intercepting file integrity check!")
        
        # ATTACK: Return completely wrong hash that will cause verification to fail
        fake_hash = "deadbeef" * 8  # Obviously fake hash
        
        print("[SHA256 BYPASS] ⚠️  FILE INTEGRITY COMPROMISED!")
        print(f"[SHA256 BYPASS] Expected hash: {expected_hash[:16]}...")
        print(f"[SHA256 BYPASS] Sending FAKE hash: {fake_hash[:16]}...")
        print("[SHA256 BYPASS] File integrity verification will FAIL")
        print("[SHA256 BYPASS] File transfer will be REJECTED as corrupted")
        
        # Return original file but with fake hash that will fail verification
        return file_bytes, fake_hash
    else:
        # Normal operation: calculate actual hash
        actual_hash = SHA256.new(file_bytes).hexdigest()
        return file_bytes, actual_hash