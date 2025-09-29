# CipherNet Messenger

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-brightgreen.svg)
![Status](https://img.shields.io/badge/status-prototype-orange.svg)

A secure peer-to-peer messaging application with hybrid RSA-Blowfish encryption and direct P2P communication.

## Overview

CipherNet Messenger enables secure, decentralized communication between users through direct encrypted connections. Unlike centralized platforms, all messages and files are transmitted directly between peers using strong cryptographic protocols.

## Key Features

- **Hybrid Encryption**: RSA-2048 for key exchange, Blowfish-256-CBC for message content
- **Direct P2P Communication**: No messages pass through central servers
- **Secure File Transfer**: Encrypted file sharing with integrity verification
- **Map-Based Interface**: Interactive user discovery and chat initiation
- **Single Session Management**: One chat session per user for enhanced security
- **Cross-Platform Notifications**: Desktop notifications for messages and file transfers

## Installation

### Prerequisites
- Python 3.9 or higher
- Firebase account for authentication

### Setup

```bash
# Clone repository
git clone https://github.com/arjun-christopher/CipherNet-Messenger.git
cd CipherNet-Messenger

# Run setup script
python setup.py

# Configure Firebase credentials in .env file
# Launch application
python src/main.py
```

### Firebase Configuration

Create a Firebase project with Authentication and Realtime Database enabled. Add your credentials to `.env`:

```env
FIREBASE_API_KEY=your_api_key_here
FIREBASE_AUTH_DOMAIN=your_project.firebaseapp.com
FIREBASE_DATABASE_URL=https://your_project-default-rtdb.firebaseio.com/
FIREBASE_PROJECT_ID=your_project_id
```

## Architecture

CipherNet uses Firebase for authentication and peer discovery only. No messages or files pass through Firebase - all communication occurs directly between peers over encrypted TCP connections.

```
User A ←→ Firebase (Auth/Discovery) ←→ User B
    ↓                                   ↓
    └───── Direct P2P Connection ───────┘
```

## Technology Stack

- **Python 3.9+**: Core application language
- **CustomTkinter**: Modern GUI framework
- **pycryptodome**: RSA, Blowfish, SHA-256, HMAC cryptography
- **Firebase**: Authentication and peer discovery
- **TCP Sockets**: Direct peer-to-peer networking

## Security

### Encryption
- **RSA-2048**: Key exchange with PKCS#1 OAEP padding
- **Blowfish-256-CBC**: Message and file content encryption
- **HMAC-SHA256**: Message authentication and integrity verification
- **SHA-256**: File integrity checking and key fingerprinting

### Session Management
- **Single Session Enforcement**: One user per system, one system per user
- **Automatic Cleanup**: All session data removed on exit
- **Session Isolation**: Cryptographically separate peer connections

### Communication Flow
1. Users authenticate via Firebase
2. Public keys exchanged through Firebase lobby
3. Direct P2P connection established
4. Session key encrypted with RSA and shared
5. All messages encrypted with Blowfish using shared session key

## Attack Tools & Security Testing

CipherNet Messenger includes an integrated **Attack Tools System** for educational purposes and security testing. This system demonstrates common cryptographic vulnerabilities and attack vectors that secure messaging applications must defend against.

### Attack Demonstrations

The attack tools provide real-time demonstrations of:

- **RSA Man-in-the-Middle (MITM)**: Intercepts RSA key exchanges and substitutes attacker-controlled keys
- **HMAC Message Tampering**: Modifies message content while maintaining valid authentication signatures  
- **SHA256 Hash Bypass**: Replaces file content while preserving original integrity hashes

### Attack Control Panel

Launch the attack control interface:
```bash
cd src
python attack_tools/attack_ui.py
```

The dark-themed control panel provides:
- **Toggle Switches**: Enable/disable individual attacks in real-time
- **Cross-Process Control**: Attacks affect the main messenger running in a separate process
- **Status Monitoring**: Visual feedback showing active attack states
- **Shared State Management**: Real-time synchronization between UI and messenger
- **Educational Interface**: Clear indicators of which vulnerabilities are being demonstrated

### Integration Architecture

```
Normal Operation:
Message → Encryption → HMAC → Network → Decryption → Verification

With Attacks Active:
Message → [ATTACK HOOK] → Modified → Network → [Appears Legitimate]

Cross-Process Communication:
Attack UI Process ←→ attack_state.json ←→ Main Messenger Process
```

The attack hooks are seamlessly integrated into the core cryptographic operations:
- `crypto_manager.py` - RSA, HMAC, and hash operations contain attack hooks
- `attack_tools/hooks.py` - Implements the actual attack logic with shared state checking
- `attack_tools/attack_ui.py` - Provides the control interface
- `attack_tools/attack_state_manager.py` - Manages cross-process attack state synchronization

### Educational Value

This system demonstrates:
- **Why end-to-end encryption matters**: Shows how MITM attacks compromise communication
- **Message authentication importance**: Illustrates tampering without detection
- **File integrity verification**: Shows hash collision/bypass vulnerabilities
- **Real-world attack scenarios**: Provides hands-on security education

### Ethical Use Warning

**The attack tools are for educational and authorized security testing only.**
- Use only on systems you own or have explicit permission to test
- Designed for learning cryptographic security principles
- Not intended for malicious purposes

## User Interface

- **Map-Based Discovery**: Interactive canvas showing online users
- **Single Chat Sessions**: One conversation at a time per user
- **File Sharing**: Integrated file upload with type recognition
- **Professional Design**: Clean interface optimized for security-focused users
- **Real-Time Updates**: Live status indicators and automatic refresh

## Project Structure

```
CipherNet-Messenger/
├── src/                        # Source code
│   ├── main.py                # Application entry point
│   ├── config.py              # Configuration management
│   ├── auth_manager.py        # Firebase authentication
│   ├── crypto_manager.py      # RSA/Blowfish encryption (with attack hooks)
│   ├── network_manager.py     # P2P networking
│   ├── firebase_manager.py    # Firebase operations
│   ├── file_transfer_manager.py # Secure file sharing
│   ├── gui_manager.py         # User interface
│   ├── notification_manager.py # Desktop notifications
│   ├── cleanup_manager.py     # Session cleanup utilities
│   ├── attack_tools/          # Security testing & education
│   │   ├── hooks.py           # Cryptographic attack implementations
│   │   ├── attack_ui.py       # Attack control panel interface
│   │   ├── attack_state_manager.py # Cross-process state management
│   │   └── attack_state.json  # Shared attack state file (generated)
├── docs/                      # Documentation
│   └── Project Report.docx    # Complete project documentation
├── .env                      # Environment variables
├── requirements.txt          # Python dependencies
├── setup.py                 # Setup script
├── README.md                # This file
├── LICENSE                 # Open-source license details
└── .gitignore               # Ignored files & folders for Git
```

## Documentation

For detailed technical information, see the [Project Report](docs/Project%20Report.docx) which includes comprehensive methodology, security analysis, and implementation details.

## Contributing

This project was developed as part of an Information Security course at Puducherry Technological University. Contributions and improvements are welcome!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Note**: This is a prototype/proof-of-concept developed for educational purposes. While it implements strong cryptographic principles, thorough security auditing would be required before production use.