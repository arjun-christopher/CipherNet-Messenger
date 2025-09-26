#!/usr/bin/env python3
"""
Setup Script for CipherNet Messenger
Installs dependencies and sets up the development environment.

Author: Arjun Christopher
"""

import sys
import subprocess
import shutil
import json
from pathlib import Path


def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 9):
        print("❌ Python 3.9 or higher is required!")
        print(f"Current version: {sys.version}")
        return False
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    return True


def install_dependencies():
    """Install project dependencies."""
    requirements_file = Path(__file__).parent / "requirements.txt"
    
    if not requirements_file.exists():
        print("❌ requirements.txt not found!")
        return False
    
    print("📦 Installing dependencies...")
    
    try:
        cmd = [sys.executable, "-m", "pip", "install", "-r", str(requirements_file)]
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        
        print("✅ Dependencies installed successfully!")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        print(f"Error output: {e.stderr}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False


def create_config_file():
    """Create configuration file with template structure."""
    config_file = Path(__file__).parent / "config.json"
    
    if config_file.exists():
        print("⚠️  config.json already exists, skipping creation")
        return True
    
    config_template = {
        "app": {
            "name": "CipherNet Messenger",
            "version": "1.0.0",
            "debug": False
        },
        "network": {
            "default_port": 8888,
            "buffer_size": 4096,
            "connection_timeout": 30,
            "file_chunk_size": 4096
        },
        "security": {
            "rsa_key_size": 2048,
            "blowfish_key_size": 128,
            "hash_algorithm": "SHA-256",
            "padding_scheme": "OAEP"
        },

        "ui": {
            "theme": "dark",
            "window_width": 1000,
            "window_height": 700,
            "font_size": 12
        }
    }
    
    try:
        with open(config_file, 'w') as f:
            json.dump(config_template, f, indent=2)
        print("✅ config.json created with template structure")
        return True
        
    except Exception as e:
        print(f"❌ Failed to create config.json: {e}")
        return False


def create_env_file():
    """Create .env file from template if it doesn't exist."""
    env_file = Path(__file__).parent / ".env"
    env_example_file = Path(__file__).parent / ".env.example"
    
    if env_file.exists():
        print("⚠️  .env already exists, skipping creation")
        return True
    
    if not env_example_file.exists():
        print("❌ .env.example not found!")
        return False
    
    try:
        shutil.copy(env_example_file, env_file)
        print("✅ .env created from template")
        print("⚠️  Please edit .env with your Firebase configuration")
        return True
        
    except Exception as e:
        print(f"❌ Failed to create .env: {e}")
        return False


def check_optional_dependencies():
    """Check for optional system dependencies."""
    print("\n🔍 Checking optional dependencies...")
    
    # Check for git
    if shutil.which("git"):
        print("✅ Git available")
    else:
        print("⚠️  Git not found (optional for version control)")
    
    # Check for system audio/video libraries (for future multimedia support)
    try:
        import tkinter
        print("✅ Tkinter available")
    except ImportError:
        print("⚠️  Tkinter not available (required for GUI)")
        return False
    
    return True


def setup_directories():
    """Create necessary directories."""
    directories = [
        "logs",
        "temp",
        ".cache"
    ]
    
    project_root = Path(__file__).parent
    
    for directory in directories:
        dir_path = project_root / directory
        if not dir_path.exists():
            dir_path.mkdir(parents=True, exist_ok=True)
            print(f"✅ Created directory: {directory}")
        else:
            print(f"📁 Directory exists: {directory}")
    
    return True


def display_firebase_setup_instructions():
    """Display Firebase setup instructions."""
    print("\n" + "=" * 60)
    print("🔥 FIREBASE SETUP REQUIRED")
    print("=" * 60)
    print("""
To use CipherNet Messenger, you need to set up Firebase:

1. Go to https://console.firebase.google.com/
2. Create a new project or select existing one
3. Enable Authentication:
   - Go to Authentication > Sign-in method
   - Enable Email/Password authentication
   
4. Create Realtime Database:
   - Go to Realtime Database
   - Create database in test mode
   - Note the database URL

5. Get your Firebase configuration:
   - Go to Project settings > General
   - Scroll to "Your apps" section
   - Click "Web app" and register your app
   - Copy the configuration values

6. Edit config.json with your Firebase values:
   - api_key: Your Firebase API key
   - auth_domain: your-project.firebaseapp.com
   - database_url: https://your-project-default-rtdb.firebaseio.com/
   - project_id: your-project-id
   - storage_bucket: your-project.appspot.com
   - messaging_sender_id: Your sender ID
   - app_id: Your app ID

7. Security Rules for Realtime Database:
   {
     "rules": {
       "lobby": {
         ".read": "auth != null",
         ".write": "auth != null"
       },
       "requests": {
         "$uid": {
           ".read": "$uid === auth.uid",
           ".write": "$uid === auth.uid"
         }
       },
       "chats": {
         "$chatId": {
           ".read": "auth != null",
           ".write": "auth != null"
         }
       }
     }
   }
""")
    print("=" * 60)


def main():
    """Main setup function."""
    print("🔧 CipherNet Messenger - Setup")
    print("=" * 40)
    
    # Check Python version
    if not check_python_version():
        return False
    
    print()
    
    # Install dependencies
    if not install_dependencies():
        return False
    
    print()
    
    # Create config file
    if not create_config_file():
        return False
    
    print()
    
    # Create .env file
    if not create_env_file():
        return False
    
    print()
    
    # Check optional dependencies
    if not check_optional_dependencies():
        return False
    
    print()
    
    # Setup directories
    if not setup_directories():
        return False
    
    # Display Firebase setup instructions
    display_firebase_setup_instructions()
    
    print("\n🎉 Setup completed successfully!")
    print("\nNext steps:")
    print("1. Configure Firebase (see instructions above)")
    print("2. Edit .env with your Firebase credentials")
    print("3. Optionally edit config.json for other settings")
    print("4. Run: python src/main.py")
    print("5. Run tests: python tests/run_tests.py")
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)