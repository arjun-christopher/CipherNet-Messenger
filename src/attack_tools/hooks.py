"""
CipherNet-Messenger Attack Hooks Module

This file contains cryptographic attack implementations used for security testing
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

# Global flags: UI sets these to activate specific attack vectors!
HOOK_RSA_MITM_ACTIVE = False      # Enables RSA Man-in-the-Middle attack
HOOK_HMAC_TAMPER_ACTIVE = False   # Enables HMAC message tampering attack
HOOK_SHA256_BYPASS_ACTIVE = False  # Enables SHA256 hash collision/bypass attack

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
    if HOOK_RSA_MITM_ACTIVE:
        # Step 1: Generate attacker's RSA key pair (2048-bit for compatibility)
        attacker_key = RSA.generate(2048)
        
        # Step 2: Create cipher with attacker's public key instead of victim's
        cipher = PKCS1_OAEP.new(attacker_key.publickey())
        
        # Step 3: Encrypt session key with attacker's public key
        encrypted = cipher.encrypt(session_key)
        
        print("[RSA MITM HOOK] Swapped public key with attacker's key!")
        print(f"[RSA MITM] Attacker can now decrypt session key: {session_key.hex()[:16]}...")
        
        # Return encrypted data and attacker's key for later decryption
        return encrypted, attacker_key
    else:
        # Normal operation: encrypt with legitimate victim's public key
        cipher = PKCS1_OAEP.new(victim_pubkey)
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
    if HOOK_HMAC_TAMPER_ACTIVE:
        # Step 1: Modify the original message with malicious prefix
        tampered_message = b"HACKED: " + message
        
        # Step 2: Calculate valid HMAC for the tampered message
        # This works because we have access to the shared HMAC key
        hmac = HMAC.new(key, tampered_message, SHA256).digest()
        
        print("[HMAC Tamper HOOK] Message tampered before sending!")
        print(f"[HMAC TAMPER] Original: {message[:50]}...")
        print(f"[HMAC TAMPER] Tampered: {tampered_message[:50]}...")
        print(f"[HMAC TAMPER] Valid HMAC generated for tampered content")
        
        # Return tampered message with its valid HMAC
        return tampered_message, hmac
    else:
        # Normal operation: calculate HMAC for original message
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
    if HOOK_SHA256_BYPASS_ACTIVE:
        # Step 1: Create malicious file content (simulating malware injection)
        fake_file = b"INJECTED MALWARE CONTENT - This could be executable code, ransomware, or data theft payload"
        
        # Step 2: Use the original file's hash with the malicious content
        # This simulates either a hash collision or compromised verification system
        hash_for_fake = expected_hash
        
        print("[SHA256 Bypass HOOK] Sending fake file with original hash!")
        print(f"[SHA256 BYPASS] Original file size: {len(file_bytes)} bytes")
        print(f"[SHA256 BYPASS] Malicious file size: {len(fake_file)} bytes")
        print(f"[SHA256 BYPASS] Using original hash: {expected_hash[:16]}...")
        print(f"[SHA256 BYPASS] Receiver will think file integrity is intact!")
        
        # Return malicious file with legitimate hash
        return fake_file, hash_for_fake
    else:
        # Normal operation: calculate actual hash of the file
        actual_hash = SHA256.new(file_bytes).hexdigest()
        return file_bytes, actual_hash