# CipherNet Messenger

**A Secure P2P Messenger Utilizing Hybrid RSA-Blowfish Encryption Protocol with SHA-256 Based Integrity Controls**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-brightgreen.svg)
![Status](https://img.shields.io/badge/status-prototype-orange.svg)

## 🔒 Overview

CipherNet Messenger is a secure, decentralized peer-to-peer messaging application that prioritizes user privacy and security. Unlike traditional messaging platforms that rely on centralized servers, CipherNet establishes direct encrypted communication channels between users, eliminating single points of failure and surveillance risks.

### Key Features

- **🔐 End-to-End Encryption**: Hybrid RSA-Blowfish cryptosystem for maximum security
- **🌐 Peer-to-Peer Architecture**: Direct communication without central server dependency
- **🛡️ Data Integrity**: SHA-256 based integrity controls for all communications
- **🔍 Private Peer Discovery**: Secure user discovery without exposing IP addresses
- **📁 Secure File Transfer**: Encrypted file sharing with integrity verification
- **🎨 Modern GUI**: Clean, intuitive interface built with CustomTkinter

## 🚀 Problem Statement

Traditional messaging platforms suffer from critical vulnerabilities:

- **Lack of Confidentiality**: User data stored on company servers, vulnerable to breaches
- **Single Point of Failure**: Centralized servers create network-wide vulnerabilities
- **Data Integrity Risks**: Messages can be intercepted and altered by attackers
- **Metadata Collection**: Service providers log sensitive communication patterns

CipherNet addresses these issues by providing **provable confidentiality, integrity, and availability** free from centralized control.

## 🏗️ Architecture

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

## 🔧 Technology Stack

- **Language**: Python 3.9+
- **GUI Framework**: CustomTkinter (modern Tkinter-based UI)
- **Cryptography**: pycryptodome (RSA, Blowfish, SHA-256, HMAC)
- **Backend Service**: Google Firebase (Authentication & Signaling only)
- **Networking**: Python socket library (TCP)
- **Concurrency**: threading (responsive UI during network operations)
- **Notifications**: desktop-notifier (cross-platform notifications)
- **Image Processing**: Pillow (file validation and sanitization)

## 🔐 Security Implementation

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

## 📋 Installation & Setup

### Prerequisites

- Python 3.9 or higher
- Firebase account (for authentication setup)

### Dependencies

```bash
pip install pycryptodome customtkinter firebase-admin desktop-notifier Pillow
```

### Configuration

1. Set up Firebase project with Authentication and Realtime Database
2. Configure Firebase credentials in the application
3. Run the application

## 🎯 Project Results

The CipherNet Messenger prototype successfully demonstrates:

- ✅ Functional P2P messaging with intuitive GUI
- ✅ Strong end-to-end encryption implementation
- ✅ Secure peer discovery without IP exposure
- ✅ Guaranteed message and file integrity
- ✅ High performance with negligible latency
- ✅ Proof-of-concept for decentralized communication

## 🔍 Security Guarantees

### Confidentiality
- **Hybrid Encryption**: RSA for key exchange, Blowfish for data
- **End-to-End Protection**: No plaintext data on intermediate servers

### Integrity
- **Message Authentication**: HMAC-SHA256 prevents tampering
- **File Verification**: SHA-256 hashing ensures file integrity

### Availability
- **Decentralized Architecture**: No single point of failure
- **Direct P2P**: Independent of central server uptime

## 📚 Technical Documentation

For detailed technical information, see the complete [Project Report](docs/Project%20Report.txt) including:

- Comprehensive methodology
- Security analysis
- Implementation details
- Performance evaluation

## 🤝 Contributing

This project was developed as part of an Information Security course at Puducherry Technological University. Contributions and improvements are welcome!

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Arjun Christopher** [2201112007]  
Department of Information Technology  
Puducherry Technological University

**Supervisor**: Dr. G. Santhi B.E., M.E., Ph.D.  
Professor, Department of Information Technology

## 🔗 References

- [Blowfish Algorithm](https://www.schneier.com/academic/blowfish/)
- [RSA Cryptosystem](https://people.csail.mit.edu/rivest/Rsapaper.pdf)
- [HMAC Standard (RFC 2104)](https://tools.ietf.org/html/rfc2104)
- [pycryptodome Documentation](https://www.pycryptodome.org/en/latest/)
- [Firebase Documentation](https://firebase.google.com/docs)

---

**⚠️ Note**: This is a prototype/proof-of-concept developed for educational purposes. While it implements strong cryptographic principles, thorough security auditing would be required before production use.