#!/usr/bin/env python3
"""
CipherNet Messenger - Main Application Entry Point
A secure P2P messenger with hybrid RSA-Blowfish encryption.

Author: Arjun Christopher
"""

import sys
import threading
from pathlib import Path

# Add src directory to path for imports
sys.path.append(str(Path(__file__).parent))

from gui_manager import GUIManager
from auth_manager import AuthManager
from config import Config
from cleanup_manager import comprehensive_cleanup
from firebase_manager import FirebaseManager
import atexit


def main():
    """Main application entry point."""
    auth_manager = None
    firebase_manager = None
    
    cleanup_done = [False]  # Use list to allow modification in nested function
    
    def cleanup_on_exit():
        """Cleanup function called on exit."""
        if not cleanup_done[0] and auth_manager and firebase_manager:
            current_user = auth_manager.get_current_user()
            if current_user:
                print("🧹 Performing final cleanup...")
                comprehensive_cleanup(auth_manager, firebase_manager, silent=False)
                cleanup_done[0] = True
    
    try:
        # Initialize configuration
        config = Config()
        
        # Initialize authentication manager  
        auth_manager = AuthManager(config)
        
        # Initialize and start GUI
        gui_manager = GUIManager(auth_manager, config)
        
        # Get firebase_manager from GUI manager
        firebase_manager = gui_manager.firebase_manager
        
        # Share cleanup flag with GUI manager
        gui_manager._cleanup_done_flag = cleanup_done
        
        # Register cleanup function for any exit scenario
        atexit.register(cleanup_on_exit)
        gui_manager.start_application()
        
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        # Cleanup will be called automatically by atexit
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        # Cleanup will be called automatically by atexit
        sys.exit(1)


if __name__ == "__main__":
    main()