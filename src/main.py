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
from cleanup_manager import cleanup_old_requests


def main():
    """Main application entry point."""
    try:
        # Initialize configuration
        config = Config()
        
        # Initialize authentication manager
        auth_manager = AuthManager(config)
        
        # Initialize and start GUI
        gui_manager = GUIManager(auth_manager, config)
        gui_manager.start_application()
        
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()