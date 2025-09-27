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
- **Map-Based User Discovery**: Interactive canvas-based interface for finding online users
- **Single Chat Session Management**: One-to-one chat sessions with duplicate prevention
- **Secure File Transfer**: Upload and share files with visual chat integration
- **Clean Professional UI**: Modern interface without emojis for accessibility
- **Real-time Status Updates**: Automatic refresh and bidirectional request handling
- **Single Session Enforcement**: Prevents concurrent logins for enhanced security
- **Comprehensive Cleanup**: Zero-delay deletion of all session data on exit
- **Desktop Notifications**: Cross-platform notification system
- **Python 3.13 Compatible**: Updated for latest Python version compatibility
- **Automated Database Maintenance**: Background cleanup of stale Firebase data

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