#!/usr/bin/env python3
"""
Attack State Manager
Manages attack states across different processes using a shared state file.

Author: Arjun Christopher
"""

import json
import os
from pathlib import Path
import threading
import time
import hooks

# Attack state file path
ATTACK_STATE_FILE = Path(__file__).parent / "attack_state.json"

class AttackStateManager:
    """Manages attack states that can be shared across processes."""
    
    def __init__(self):
        self._lock = threading.Lock()
        self._last_check = 0
        self._check_interval = 0.1  # Check every 100ms
        
        # Initialize state file if it doesn't exist
        if not ATTACK_STATE_FILE.exists():
            self._save_state({
                'rsa_mitm_active': False,
                'hmac_tamper_active': False,
                'sha256_bypass_active': False,
                'last_updated': time.time()
            })
    
    def _load_state(self):
        """Load attack state from file."""
        try:
            if ATTACK_STATE_FILE.exists():
                with open(ATTACK_STATE_FILE, 'r') as f:
                    return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
        
        # Return default state if file doesn't exist or is corrupted
        return {
            'rsa_mitm_active': False,
            'hmac_tamper_active': False,
            'sha256_bypass_active': False,
            'last_updated': time.time()
        }
    
    def _save_state(self, state):
        """Save attack state to file."""
        try:
            state['last_updated'] = time.time()
            with open(ATTACK_STATE_FILE, 'w') as f:
                json.dump(state, f, indent=2)
        except IOError:
            pass  # Fail silently
    
    def update_attack_states(self):
        """Update global hook variables from shared state file."""
        current_time = time.time()
        
        # Only check file if enough time has passed
        if current_time - self._last_check < self._check_interval:
            return
        
        with self._lock:
            self._last_check = current_time
            state = self._load_state()
            
            # Update global hook variables
            hooks.HOOK_RSA_MITM_ACTIVE = state.get('rsa_mitm_active', False)
            hooks.HOOK_HMAC_TAMPER_ACTIVE = state.get('hmac_tamper_active', False)
            hooks.HOOK_SHA256_BYPASS_ACTIVE = state.get('sha256_bypass_active', False)
    
    def set_attack_state(self, attack_type, active):
        """Set attack state and save to file."""
        with self._lock:
            state = self._load_state()
            
            if attack_type == 'rsa_mitm':
                state['rsa_mitm_active'] = active
            elif attack_type == 'hmac_tamper':
                state['hmac_tamper_active'] = active
            elif attack_type == 'sha256_bypass':
                state['sha256_bypass_active'] = active
            
            self._save_state(state)
            
            # Also update current process immediately
            if attack_type == 'rsa_mitm':
                hooks.HOOK_RSA_MITM_ACTIVE = active
            elif attack_type == 'hmac_tamper':
                hooks.HOOK_HMAC_TAMPER_ACTIVE = active
            elif attack_type == 'sha256_bypass':
                hooks.HOOK_SHA256_BYPASS_ACTIVE = active
    
    def get_attack_states(self):
        """Get current attack states."""
        state = self._load_state()
        return {
            'rsa_mitm': state.get('rsa_mitm_active', False),
            'hmac_tamper': state.get('hmac_tamper_active', False),
            'sha256_bypass': state.get('sha256_bypass_active', False)
        }

# Global instance
_attack_state_manager = AttackStateManager()

def update_attack_states():
    """Update attack states from shared file."""
    _attack_state_manager.update_attack_states()

def set_attack_state(attack_type, active):
    """Set attack state."""
    _attack_state_manager.set_attack_state(attack_type, active)

def get_attack_states():
    """Get attack states."""
    return _attack_state_manager.get_attack_states()