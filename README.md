# CipherNet Messenger

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-brightgreen.svg)
![Status](https://img.shields.io/badge/status-prototype-orange.svg)

**A Secure P2P Messenger Utilizing Hybrid RSA-Blowfish Encryption Protocol with SHA-256 Based Integrity Controls**

## Overview

CipherNet Messenger is a secure, decentralized peer-to-peer messaging application that prioritizes user privacy and security. Unlike traditional messaging platforms that rely on centralized servers, CipherNet establishes direct encrypted communication channels between users, eliminating single points of failure and surveillance risks.

### Key Features

#### Enhanced Security Architecture
- **RSA-2048 with PKCS#1 OAEP**: Industry-standard asymmetric encryption for key exchange
- **Blowfish-256-CBC**: High-performance symmetric encryption for message content
- **Secure Session Initiation**: Multi-step handshake with cryptographic validation
- **SHA-256 Key Fingerprinting**: Public key authentication and verification
- **HMAC-SHA256**: Message authentication codes for integrity verification
- **Cryptographically Secure Random**: Hardware entropy for key generation

#### Network & Communication
- **Peer-to-Peer Architecture**: Direct communication without central server dependency
- **Secure Signaling Protocol**: Firebase-based peer discovery with encryption metadata
- **Hybrid Encryption Protocol**: RSA key exchange + symmetric message encryption
- **Real-time Session Management**: Automatic session establishment and teardown
- **Connection State Monitoring**: Network resilience and automatic reconnection

#### User Experience
- **Map-Based User Discovery**: Interactive canvas-based interface for finding online users
- **Single Chat Session Management**: One-to-one chat sessions with duplicate prevention
- **Security Status Indicators**: Real-time encryption status and key exchange progress
- **Secure File Transfer**: Upload and share files with visual chat integration
- **Clean Professional UI**: Modern interface optimized for security-focused users
- **Desktop Notifications**: Cross-platform notification system
- **Session Isolation**: Complete data separation between chat sessions

#### Performance & Reliability
- **Single Session Enforcement**: Prevents concurrent logins for enhanced security
- **Comprehensive Cleanup**: Zero-delay deletion of all session data on exit
- **Python 3.13 Compatible**: Updated for latest Python version compatibility
- **Automated Database Maintenance**: Background cleanup of stale Firebase data
- **Memory-Safe Operations**: Secure key storage and automatic cleanup

## Problem Statement

Traditional messaging platforms suffer from critical vulnerabilities:

- **Lack of Confidentiality**: User data stored on company servers, vulnerable to breaches
- **Single Point of Failure**: Centralized servers create network-wide vulnerabilities  
- **Data Integrity Risks**: Messages can be intercepted and altered by attackers
- **Metadata Collection**: Service providers log sensitive communication patterns

CipherNet addresses these issues by providing **provable confidentiality, integrity, and availability** free from centralized control.

## Installation & Setup

### Prerequisites

- Python 3.9 or higher (tested up to Python 3.13)
- Firebase account (for authentication setup)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/arjun-christopher/CipherNet-Messenger.git
cd CipherNet-Messenger

# Run automated setup script
python setup.py

# Configure Firebase credentials in the generated .env file
# Then run the application
python src/main.py
```

### Automated Setup Features

The `setup.py` script provides:
- **Dependency Installation**: Automatically installs all required packages
- **Configuration Generation**: Creates `config.json` with optimal settings
- **Environment File Creation**: Generates `.env` template with Firebase placeholders
- **Compatibility Checking**: Validates Python version and system requirements
- **Interactive Setup**: Guides you through Firebase configuration

### Manual Setup (Alternative)

#### Install Dependencies

```bash
pip install -r requirements.txt
```

#### Configuration

1. **Run Setup**: `python setup.py` (recommended for automated configuration)
2. **Firebase Setup**: Create Firebase project with Authentication and Realtime Database
3. **Environment Variables**: Edit `.env` file with your Firebase credentials
4. **Application Settings**: Optionally customize `config.json`
5. **Launch Application**: `python src/main.py`

#### Firebase Configuration

Your `.env` file should contain:
```env
FIREBASE_API_KEY=your_api_key_here
FIREBASE_AUTH_DOMAIN=your_project.firebaseapp.com
FIREBASE_DATABASE_URL=https://your_project-default-rtdb.firebaseio.com/
FIREBASE_PROJECT_ID=your_project_id
```

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

- **Language**: Python 3.9+ (Compatible through Python 3.13)
- **GUI Framework**: CustomTkinter (modern Tkinter-based UI)
- **Cryptography**: pycryptodome (RSA, Blowfish, SHA-256, HMAC)
- **Backend Service**: Google Firebase (Authentication & Signaling only)
- **Networking**: Python socket library (TCP)
- **Concurrency**: threading (responsive UI during network operations)
- **Notifications**: desktop-notifier (cross-platform notifications)
- **Image Processing**: Pillow (file validation and sanitization)
- **Environment Management**: python-dotenv (secure configuration)

## Security Implementation

### Enhanced Cryptographic Algorithms

#### 1. **RSA-2048 with PKCS#1 OAEP**
- **Algorithm**: RSA (Rivest-Shamir-Adleman) 
- **Key Size**: Enforced 2048-bit keys (industry standard)
- **Padding**: PKCS#1 OAEP with SHA-256 for maximum security
- **Purpose**: Secure session key exchange and peer authentication
- **Entropy**: Hardware-based secure random number generation
- **Validation**: Automatic key size and format validation

#### 2. **Blowfish-256-CBC**
- **Algorithm**: Blowfish in CBC (Cipher Block Chaining) mode
- **Key Size**: Enhanced 256-bit session keys (increased from 128-bit)
- **Block Size**: 64-bit blocks with secure initialization vectors
- **Purpose**: High-speed bulk data encryption for messages and files
- **Performance**: Optimized for real-time message encryption

#### 3. **SHA-256 Cryptographic Hashing**
- **Algorithm**: SHA-256 (Secure Hash Algorithm)
- **Applications**: 
  - RSA public key fingerprinting and validation
  - HMAC-SHA256 message authentication codes
  - File integrity verification and validation
  - Session key derivation and management

### Enhanced Security Protocols

#### Secure Session Initiation Protocol

**Phase 1: Authentication (Firebase)**
1. User authenticates with Firebase (email/password)
2. No session key exists yet - authentication only

**Phase 2: Peer Discovery** 
1. Firebase acts as secure relay for public key exchange
2. Users publish RSA-2048 public keys to authenticated lobby
3. Public key fingerprints calculated and shared for validation
4. IP addresses shared through encrypted Firebase channels

**Phase 3: RSA-2048 Key Exchange**
1. **User A** generates cryptographically secure 256-bit session key (`K_session`)
2. **User A** encrypts `K_session` with **User B's** RSA-2048 public key using PKCS#1 OAEP-SHA256
3. **User A** sends encrypted session key package with metadata:
   ```json
   {
     "encrypted_session_key": "base64_encoded_data",
     "encryption_algorithm": "RSA-2048-OAEP-SHA256", 
     "session_algorithm": "Blowfish-256-CBC",
     "sender_key_fingerprint": "sha256_fingerprint",
     "timestamp": "unix_timestamp_ms"
   }
   ```
4. **User B** validates encryption parameters and sender identity
5. **User B** decrypts `K_session` with their RSA-2048 private key
6. **User B** confirms session establishment 

**Phase 4: Secure Communication**
- All subsequent messages encrypted with Blowfish-256-CBC using `K_session`
- Each message includes HMAC-SHA256 authentication code
- Session keys isolated per peer connection

#### Security Standards Compliance

- **Algorithms**: RSA-2048, PKCS#1 OAEP, SHA-256, Blowfish-256
- **Standards**: PKCS#1 OAEP padding standard compliance
- **Protocols**: Secure Signaling & Peer Discovery + Hybrid Encryption Protocol
- **Key Management**: Automatic generation, validation, and secure cleanup
- **Authentication**: Multi-layer validation with cryptographic fingerprints

#### Secure Signaling & Peer Discovery

1. Users publish public keys to Firebase `/lobby/`
2. Chat requests sent to private path `/requests/{UserID}/`
3. Upon acceptance, IP address shared via private channel `/chats/{ChatID}/`
4. Direct P2P connection established using shared IP
5. **Automated cleanup** removes processed requests to maintain database hygiene

#### Secure File Transfer

1. Sender calculates file SHA-256 hash
2. Control message sent with filename, size, and hash
3. File transmitted in encrypted 4096-byte chunks
4. Receiver verifies file integrity using hash comparison

### Session Management & Access Control

CipherNet implements robust **Single Session Enforcement** for enhanced security:

#### Session Policy
- **One User, One Session**: A user can only be logged in on one system at a time
- **One System, One User**: Only one user can be active per system/device simultaneously
- **Automatic Session Management**: Sessions are automatically created, tracked, and cleaned up

#### Session Features
- **Unique Session IDs**: Each login creates a cryptographically unique session identifier
- **Machine Fingerprinting**: Systems are identified using hostname and platform information
- **Activity Tracking**: Session activity is monitored with automatic timeout (30 minutes)
- **Conflict Detection**: Login attempts are blocked if session conflicts are detected
- **Graceful Cleanup**: Sessions are properly cleaned up on logout and application exit

#### Session Security Benefits
- **Account Takeover Prevention**: Unauthorized concurrent access is impossible
- **Resource Protection**: Prevents multiple instances depleting system resources
- **Audit Trail**: All login attempts and session activities are tracked
- **Consistency Guarantee**: Ensures single-user state consistency across the application

#### Session Messages
```
Login blocked: User is already logged in on another system (Session: dc064fa5...)
Login blocked: Another user (user2@gmail.com) is already logged in on this system
```

### Security Guarantees

#### Confidentiality
- **Hybrid Encryption**: RSA for key exchange, Blowfish for data
- **End-to-End Protection**: No plaintext data on intermediate servers
- **Session Isolation**: Each session is cryptographically isolated from others

#### Integrity
- **Message Authentication**: HMAC-SHA256 prevents tampering
- **File Verification**: SHA-256 hashing ensures file integrity
- **Session Validation**: All session operations are authenticated and validated

#### Availability
- **Decentralized Architecture**: No single point of failure
- **Direct P2P**: Independent of central server uptime
- **Session Recovery**: Graceful handling of network interruptions and reconnection

## Modern User Interface

### Map-Based User Discovery Interface

CipherNet features a revolutionary map-based interface for user discovery and interaction:

#### Map-Based Discovery
- **Interactive Canvas**: Users appear as positioned elements on a visual map
- **Random Coordinate Placement**: Dynamic user positioning for visual variety
- **Click-to-Connect**: Simple click interaction to initiate chat requests
- **Real-time Status Updates**: Live indicators for user availability and activity
- **Clean Visual Design**: Professional blue color scheme (#1e88e5, #1565c0, #e3f2fd)

#### Single Session Management
- **One Chat at a Time**: Users can only engage in one conversation simultaneously
- **Duplicate Prevention**: System prevents multiple sessions between same users
- **Active Session Tracking**: Comprehensive monitoring of all active connections
- **Automatic Status Management**: Real-time busy/available status updates

#### Chat Interface
- **Clean Message Bubbles**: Professional styling without emojis for accessibility
- **File Upload Integration**: Drag-and-drop file sharing with visual feedback
- **Message Timestamps**: Clean time display (HH:MM format)
- **Auto-Scroll**: Automatic scrolling to latest messages
- **Responsive Layout**: Adaptive design across different screen sizes

#### File Sharing Features
- **Visual File Upload**: Green file button positioned left of message input
- **File Type Recognition**: Color-coded indicators for different file types
  - Images: Red (#ff6b6b)
  - Documents: Teal (#4ecdc4)
  - Archives: Blue (#45b7d1)
  - Other Files: Green (#96ceb4)
- **File Information Display**: Shows filename, size, and type in chat
- **Cross-Platform File Opening**: Automatic file opening with system defaults
- **Integrated Chat Display**: Files appear as rich message bubbles

#### Professional Design
- **Text-Only Interface**: Removed all emojis for clean, professional appearance
- **Accessibility Focused**: High contrast colors and readable typography
- **Modern Framework**: CustomTkinter with native OS styling
- **Error Handling**: Graceful degradation with user-friendly messages

#### Real-Time Features
- **Bidirectional Request Handling**: Both sender and receiver move to chat automatically
- **Automatic Refresh**: Immediate status updates after chat sessions end
- **Response Monitoring**: 2-second polling for request acceptances
- **Live Status Indicators**: Real-time busy/available status management

### Comprehensive Data Management

- **Instant Cleanup**: All session data deleted immediately on exit
- **Comprehensive Cleanup**: Removes accepted requests, stale requests, inactive chats, and presence data
- **Session Validation**: Prevents duplicate cleanup calls with flag management
- **Real-time Updates**: Live status indicators and automatic map refresh

## Recent Updates (Version 2.0)

### **Map-Based Interface Redesign**
- **Complete UI Overhaul**: Replaced dashboard with interactive map-based user discovery
- **Canvas-Based Positioning**: Users appear at random coordinates on visual map
- **Single Session Management**: Enforced one-to-one chat sessions with duplicate prevention
- **Professional Clean Design**: Removed all emojis for accessibility and professional appearance

### **File Upload Integration**
- **In-Chat File Sharing**: Upload button integrated into chat interface
- **Visual File Display**: Rich file messages with type indicators and file information
- **Cross-Platform Support**: File opening with system default applications
- **File Type Recognition**: Color-coded indicators for images, documents, archives

### **Enhanced Chat Request Handling**
- **Bidirectional Automation**: Both sender and receiver automatically enter chat UI
- **Response Monitoring**: Real-time polling for request acceptances every 2 seconds
- **Automatic Status Updates**: Immediate refresh after chat sessions end
- **Duplicate Prevention**: System prevents multiple sessions between same users

### **Comprehensive Cleanup System**
- **Instant Data Removal**: Zero-delay cleanup of all session data on exit
- **Complete Firebase Cleanup**: Removes accepted requests, stale requests, inactive chats
- **Session Management**: Proper authentication state clearing and presence removal
- **Duplicate Prevention**: Cleanup flags prevent multiple cleanup operations

### **UI/UX Improvements**
- **Professional Appearance**: Clean, text-only interface without emojis
- **Real-Time Updates**: Live status indicators and automatic map refresh
- **Enhanced Navigation**: Removed map button from chat UI for cleaner experience
- **Improved Accessibility**: High contrast colors and readable typography

## Project Structure

```
CipherNet-Messenger/
├── docs/                       # Documentation
│   ├── Project Report.docx    # Complete project documentation
│   ├── Project Report.txt     # Text version of documentation
├── src/                        # Source code
│   ├── main.py                # Application entry point
│   ├── config.py              # Configuration management
│   ├── auth_manager.py        # Firebase authentication
│   ├── crypto_manager.py      # RSA/Blowfish encryption
│   ├── network_manager.py     # P2P networking
│   ├── firebase_manager.py    # Firebase signaling & database operations
│   ├── file_transfer_manager.py # Secure file sharing
│   ├── gui_manager.py         # User interface (CustomTkinter)
│   ├── notification_manager.py # Desktop notifications
│   ├── cleanup_manager.py     # Comprehensive Firebase cleanup utilities
│   └── archives/              # Archived versions for reference
│       └── gui_manager_backup.py # Previous dashboard implementation
├── .env                      # Environment variables (created by setup)
├── .gitignore               # Git ignore rules
├── requirements.txt         # Python dependencies
├── setup.py                # Automated setup script
├── LICENSE                 # MIT License file
└── README.md              # This file
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
- Maintain clean, professional UI design principles
- Document significant changes in appropriate markdown files

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Note**: This is a prototype/proof-of-concept developed for educational purposes. While it implements strong cryptographic principles, thorough security auditing would be required before production use.