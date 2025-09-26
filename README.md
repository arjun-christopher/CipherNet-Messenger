# CipherNet Messenger

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-brightgreen.svg)
![Status](https://img.shields.io/badge/status-prototype-orange.svg)

**A Secure P2P Messenger Utilizing Hybrid RSA-Blowfish Encryption Protocol with SHA-256 Based Integrity Controls**

## Overview

CipherNet Messenger is a secure, decentralized peer-to-peer messaging application that prioritizes user privacy and security. Unlike traditional messaging platforms that rely on centralized servers, CipherNet establishes direct encrypted communication channels between users, eliminating single points of failure and surveillance risks.

### Key Features

- **End-to-End Encryption**: Hybrid RSA-Blowfish cryptosystem for maximum security
- **Peer-to-Peer Architecture**: Direct communication without central server dependency
- **Data Integrity**: SHA-256 based integrity controls for all communications
- **Private Peer Discovery**: Secure user discovery without exposing IP addresses
- **Secure File Transfer**: Encrypted file sharing with integrity verification
- **Modern GUI**: Clean, intuitive interface built with CustomTkinter
- **Desktop Notifications**: Cross-platform notification system

## Problem Statement

Traditional messaging platforms suffer from critical vulnerabilities:

- **Lack of Confidentiality**: User data stored on company servers, vulnerable to breaches
- **Single Point of Failure**: Centralized servers create network-wide vulnerabilities  
- **Data Integrity Risks**: Messages can be intercepted and altered by attackers
- **Metadata Collection**: Service providers log sensitive communication patterns

CipherNet addresses these issues by providing **provable confidentiality, integrity, and availability** free from centralized control.

## Installation & Setup

### Prerequisites

- Python 3.9 or higher
- Firebase account (for authentication setup)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/arjun-christopher/CipherNet-Messenger.git
cd CipherNet-Messenger

# Run setup script (installs dependencies and creates config)
python setup.py

# Configure Firebase settings in config.json
# Then run the application
python src/main.py
```

### Manual Setup

#### Install Dependencies

```bash
pip install -r requirements.txt
```

#### Configuration

1. Run the setup script: `python setup.py` (creates config files automatically)
2. Set up Firebase project with Authentication and Realtime Database
3. Edit `.env` file with your Firebase credentials (copied from .env.example)
4. Optionally edit `config.json` for other application settings
5. Run the application: `python src/main.py`

## Architecture

### Hybrid Model Design

CipherNet uses Google Firebase strictly as a lightweight **Authentication and Signaling Server** with limited roles:

1. **User Authentication**: Secure email/password authentication
2. **Peer Discovery**: Temporary "address book" for secure connection details exchange

**Important**: No messages, files, or sensitive metadata ever pass through Firebase. All communication is handled directly peer-to-peer over encrypted TCP sockets.

### Process Flow

```
User A ←→ Firebase (Auth/Signaling) ←→ User B
    ↓                                    ↓
    └────── Direct P2P Connection ──────┘
         (Encrypted TCP Socket)
```

## Technology Stack

- **Language**: Python 3.9+
- **GUI Framework**: CustomTkinter (modern Tkinter-based UI)
- **Cryptography**: pycryptodome (RSA, Blowfish, SHA-256, HMAC)
- **Backend Service**: Google Firebase (Authentication & Signaling only)
- **Networking**: Python socket library (TCP)
- **Concurrency**: threading (responsive UI during network operations)
- **Notifications**: desktop-notifier (cross-platform notifications)
- **Image Processing**: Pillow (file validation and sanitization)

## Security Implementation

### Cryptographic Algorithms

#### 1. **RSA (Rivest-Shamir-Adleman)**
- **Purpose**: Secure session key exchange
- **Key Size**: 2048-bit
- **Padding**: PKCS#1 OAEP for enhanced security

#### 2. **Blowfish**
- **Purpose**: High-speed bulk data encryption
- **Block Size**: 64-bit blocks
- **Key Length**: Variable (up to 448 bits)

#### 3. **SHA-256**
- **Purpose**: Data integrity verification
- **Applications**: 
  - HMAC-SHA256 for message authentication
  - Full-file hashing for file integrity

### Security Protocols

#### Hybrid Encryption Protocol

1. User A generates random 128-bit session key (`K_session`)
2. User A encrypts `K_session` with User B's RSA public key
3. User A sends encrypted session key to User B
4. User B decrypts with their RSA private key
5. All subsequent communication uses Blowfish with `K_session`

#### Secure Signaling & Peer Discovery

1. Users publish public keys to Firebase `/lobby/`
2. Chat requests sent to private path `/requests/{UserID}/`
3. Upon acceptance, IP address shared via private channel `/chats/{ChatID}/`
4. Direct P2P connection established using shared IP

#### Secure File Transfer

1. Sender calculates file SHA-256 hash
2. Control message sent with filename, size, and hash
3. File transmitted in encrypted 4096-byte chunks
4. Receiver verifies file integrity using hash comparison

### Security Guarantees

#### Confidentiality
- **Hybrid Encryption**: RSA for key exchange, Blowfish for data
- **End-to-End Protection**: No plaintext data on intermediate servers

#### Integrity
- **Message Authentication**: HMAC-SHA256 prevents tampering
- **File Verification**: SHA-256 hashing ensures file integrity

#### Availability
- **Decentralized Architecture**: No single point of failure
- **Direct P2P**: Independent of central server uptime

## Project Structure

```
CipherNet-Messenger/
├── docs/                       # Documentation
├── src/                          # Source code
│   ├── main.py                  # Application entry point
│   ├── config.py                # Configuration management
│   ├── auth_manager.py          # Firebase authentication
│   ├── crypto_manager.py        # RSA/Blowfish encryption
│   ├── network_manager.py       # P2P networking
│   ├── firebase_manager.py      # Firebase signaling
│   ├── file_transfer_manager.py # Secure file sharing
│   ├── gui_manager.py           # User interface
│   └── notification_manager.py  # Desktop notifications
├── tests/                       # Comprehensive test suite
│   ├── conftest.py             # Test configuration
│   ├── test_config.py          # Config tests
│   ├── test_crypto_manager.py  # Crypto tests
│   ├── test_auth_manager.py    # Auth tests
│   ├── test_network_manager.py # Network tests
│   ├── test_notification_manager.py # Notification tests
│   └── run_tests.py           # Test runner
├── .gitignore                 # Git ignore rules
├── requirements.txt            # Dependencies
├── setup.py                   # Setup script
└── README.md                 # This file
```

## Testing

The project includes a comprehensive test suite covering all major components:

```bash
# Run all tests
python tests/run_tests.py

# Run specific test module
python tests/run_tests.py crypto_manager
python tests/run_tests.py auth_manager
python tests/run_tests.py network_manager

# Run tests with pytest directly
pytest tests/ -v
```

### Test Coverage

- **Configuration Management**: Loading, saving, validation
- **Cryptography**: RSA/Blowfish encryption, HMAC, hashing
- **Authentication**: Firebase auth, token management
- **Networking**: P2P connections, message routing
- **File Transfer**: Secure file sharing, integrity verification
- **Notifications**: Desktop notification delivery and error handling
- **Error Handling**: Network failures, invalid data, edge cases

## Documentation

For detailed technical information, see the complete [Project Report](docs/Project%20Report.txt) including:

- Comprehensive methodology
- Security analysis
- Implementation details
- Performance evaluation

## Contributing

This project was developed as part of an Information Security course at Puducherry Technological University. Contributions and improvements are welcome!

### Development Setup

1. Fork the repository
2. Run `python setup.py` to set up development environment
3. Make your changes with corresponding tests
4. Run `python tests/run_tests.py` to ensure all tests pass
5. Submit a pull request

### Code Style

- Follow PEP 8 guidelines
- Add docstrings for all functions and classes
- Include comprehensive error handling
- Write tests for new functionality

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Note**: This is a prototype/proof-of-concept developed for educational purposes. While it implements strong cryptographic principles, thorough security auditing would be required before production use.