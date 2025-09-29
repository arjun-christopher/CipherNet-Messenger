"""
Network Manager for CipherNet Messenger
Handles P2P TCP connections, message routing, and network communication.

Author: Arjun Christopher
"""

import socket
import threading
import json
import time
import base64
from typing import Callable, Optional, Dict, Any, Tuple
from datetime import datetime

# Import attack state manager for enhanced MITM detection
try:
    from attack_tools.attack_state_manager import get_attack_states
except ImportError:
    # Fallback if attack tools aren't available
    def get_attack_states():
        return {'rsa_mitm_active': False, 'hmac_tamper_active': False, 'sha256_bypass_active': False}


class NetworkManager:
    """Manages P2P network connections and message routing."""
    
    def __init__(self, config, crypto_manager):
        """
        Initialize network manager with enhanced security features.
        
        Args:
            config: Configuration manager instance
            crypto_manager: Enhanced cryptography manager instance
        """
        self.config = config
        self.crypto_manager = crypto_manager
        
        self.server_socket = None
        self.client_connections = {}  # {peer_id: socket}
        self.message_handlers = {}  # {message_type: callback}
        self.is_running = False
        self.local_ip = self._get_local_ip()
        self.port = config.get('network.default_port', 8888)
        self.connection_closed_callback = None  # Callback for connection closures
        
        # Enhanced session management
        self.peer_sessions = {}  # {peer_id: session_info}
        self.handshake_timeouts = {}  # {peer_id: timeout_timestamp}
        self.session_establishment_callbacks = {}  # {peer_id: callback}
        
        # Threading
        self.server_thread = None
        self.connection_threads = {}
        
        # Register enhanced message handlers
        self.register_message_handler('secure_handshake', self._handle_secure_handshake)
        self.register_message_handler('key_exchange', self._handle_key_exchange)
        self.register_message_handler('session_established', self._handle_session_established)
    
    def start_server(self) -> bool:
        """
        Start P2P server to accept incoming connections.
        
        Returns:
            True if server started successfully, False otherwise
        """
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            self.server_socket.bind((self.local_ip, self.port))
            self.server_socket.listen(5)
            
            self.is_running = True
            self.server_thread = threading.Thread(target=self._accept_connections, daemon=True)
            self.server_thread.start()
            
            print(f"P2P server started on {self.local_ip}:{self.port}")
            return True
            
        except Exception as e:
            print(f"Failed to start server: {e}")
            return False
    
    def stop_server(self):
        """Stop P2P server and close all connections."""
        self.is_running = False
        
        # Close all client connections
        for peer_id, conn in list(self.client_connections.items()):
            self._close_connection(peer_id, conn)
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        print("P2P server stopped")
    
    def connect_to_peer(self, peer_ip: str, peer_port: int, peer_id: str) -> bool:
        """
        Connect to a remote peer.
        
        Args:
            peer_ip: Peer's IP address
            peer_port: Peer's port number
            peer_id: Unique peer identifier
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            if peer_id in self.client_connections:
                print(f"Already connected to {peer_id}")
                return True
            
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Configure socket for better stability
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            
            client_socket.settimeout(self.config.get('network.connection_timeout', 60))
            client_socket.connect((peer_ip, peer_port))
            
            # Send handshake
            handshake_msg = {
                "type": "handshake",
                "peer_id": self._get_own_peer_id(),
                "timestamp": datetime.now().isoformat()
            }
            self._send_raw_message(client_socket, json.dumps(handshake_msg))
            
            # Store connection
            self.client_connections[peer_id] = client_socket
            
            # Start message handling thread
            thread = threading.Thread(
                target=self._handle_peer_connection,
                args=(client_socket, peer_id),
                daemon=True
            )
            thread.start()
            self.connection_threads[peer_id] = thread
            
            print(f"Connected to peer {peer_id} at {peer_ip}:{peer_port}")
            return True
            
        except Exception as e:
            print(f"Failed to connect to {peer_id}: {e}")
            return False
    
    def disconnect_from_peer(self, peer_id: str):
        """
        Disconnect from a specific peer.
        
        Args:
            peer_id: Unique peer identifier
        """
        if peer_id in self.client_connections:
            conn = self.client_connections[peer_id]
            self._close_connection(peer_id, conn)
    
    def send_message(self, peer_id: str, message_type: str, content: Dict[str, Any]) -> bool:
        """
        Send encrypted message to a peer.
        
        Args:
            peer_id: Target peer identifier
            message_type: Type of message (text, file, etc.)
            content: Message content
        
        Returns:
            True if message sent successfully, False otherwise
        """
        try:
            if peer_id not in self.client_connections:
                print(f"Not connected to {peer_id}")
                return False
            
            # Prepare message
            message = {
                "type": message_type,
                "timestamp": datetime.now().isoformat(),
                "sender": self._get_own_peer_id(),
                "content": content
            }
            
            # Encrypt message content
            message_json = json.dumps(message)
            encrypted_content = self.crypto_manager.encrypt_message(message_json, peer_id=peer_id)
            hmac_tag = self.crypto_manager.calculate_hmac(message_json, peer_id=peer_id)
            
            # Create encrypted message wrapper
            encrypted_message = {
                "encrypted": True,
                "content": encrypted_content.hex(),
                "hmac": hmac_tag.hex(),
                "timestamp": datetime.now().isoformat()
            }
            
            # Send message
            conn = self.client_connections[peer_id]
            return self._send_raw_message(conn, json.dumps(encrypted_message))
            
        except Exception as e:
            print(f"Failed to send message to {peer_id}: {e}")
            return False
    
    def initiate_secure_session(self, peer_id: str, peer_public_key_pem: bytes, 
                               callback: Callable = None) -> bool:
        """
        Initiate secure session establishment with RSA-2048 key exchange.
        
        Args:
            peer_id: Target peer identifier
            peer_public_key_pem: Peer's RSA-2048 public key in PEM format
            callback: Optional callback for session establishment completion
        
        Returns:
            True if session initiation started successfully, False otherwise
        """
        try:
            print(f"🔒 Initiating secure session with peer {peer_id}")
            
            # Validate peer's public key
            if not self.crypto_manager.validate_peer_public_key(peer_public_key_pem):
                print(f"❌ Invalid public key from peer {peer_id}")
                return False
            
            # Generate session key for this peer
            session_key = self.crypto_manager.generate_session_key(peer_id)
            
            # Encrypt session key with peer's public key using PKCS#1 OAEP
            key_exchange_data = self.crypto_manager.encrypt_session_key(
                session_key, peer_public_key_pem, peer_id
            )
            
            # Create secure key exchange message
            key_exchange_message = {
                "type": "key_exchange",
                "protocol_version": "1.0",
                "key_exchange_data": key_exchange_data,
                "sender_id": self._get_own_peer_id(),
                "handshake_data": self.crypto_manager.create_secure_handshake_data(peer_id),
                "timestamp": datetime.now().isoformat()
            }
            
            # Store session establishment callback
            if callback:
                self.session_establishment_callbacks[peer_id] = callback
            
            # Send key exchange message
            if peer_id in self.client_connections:
                conn = self.client_connections[peer_id]
                success = self._send_raw_message(conn, json.dumps(key_exchange_message))
                
                if success:
                    # Update session state
                    self.peer_sessions[peer_id] = {
                        'status': 'key_exchange_sent',
                        'initiated_at': time.time(),
                        'session_key': session_key,
                        'protocol_version': '1.0',
                        'peer_public_key': peer_public_key_pem
                    }
                    print(f"✅ Key exchange initiated with peer {peer_id}")
                    return True
                else:
                    print(f"❌ Failed to send key exchange to peer {peer_id}")
                    return False
            else:
                print(f"❌ No connection to peer {peer_id}")
                return False
            
        except Exception as e:
            print(f"❌ Failed to initiate secure session with {peer_id}: {e}")
            return False
    
    def register_message_handler(self, message_type: str, handler: Callable):
        """
        Register a callback handler for specific message types.
        
        Args:
            message_type: Type of message to handle
            handler: Callback function to handle the message
        """
        self.message_handlers[message_type] = handler
    
    def send_secure_handshake(self, peer_id: str) -> bool:
        """
        Send secure handshake to establish session parameters.
        
        Args:
            peer_id: Target peer identifier
        
        Returns:
            True if handshake sent successfully, False otherwise
        """
        try:
            handshake_data = self.crypto_manager.create_secure_handshake_data(peer_id)
            
            handshake_message = {
                "type": "secure_handshake",
                "handshake_data": handshake_data,
                "sender_id": self._get_own_peer_id(),
                "timestamp": datetime.now().isoformat()
            }
            
            if peer_id in self.client_connections:
                conn = self.client_connections[peer_id]
                success = self._send_raw_message(conn, json.dumps(handshake_message))
                
                if success:
                    self.handshake_timeouts[peer_id] = time.time() + 30  # 30 second timeout
                    print(f"✅ Secure handshake sent to peer {peer_id}")
                    return True
                    
            return False
            
        except Exception as e:
            print(f"❌ Failed to send secure handshake to {peer_id}: {e}")
            return False
    
    def register_connection_closed_callback(self, callback: Callable):
        """
        Register a callback for when connections are closed.
        
        Args:
            callback: Function to call when connection is closed (receives peer_id)
        """
        self.connection_closed_callback = callback
    
    def register_session_establishment_callback(self, peer_id: str, callback: Callable):
        """
        Register a callback for session establishment completion.
        
        Args:
            peer_id: Peer identifier
            callback: Function to call when session is established
        """
        self.session_establishment_callbacks[peer_id] = callback
    
    def get_local_address(self) -> Tuple[str, int]:
        """
        Get local IP address and port.
        
        Returns:
            Tuple of (ip_address, port)
        """
        return self.local_ip, self.port
    
    def get_connected_peers(self) -> list:
        """
        Get list of connected peer IDs.
        
        Returns:
            List of connected peer identifiers
        """
        return list(self.client_connections.keys())
    
    def is_session_established(self, peer_id: str) -> bool:
        """
        Check if secure session is established with peer.
        
        Args:
            peer_id: Peer identifier
        
        Returns:
            True if session is established, False otherwise
        """
        session_info = self.peer_sessions.get(peer_id, {})
        return session_info.get('status') == 'established'
    
    def get_session_info(self, peer_id: str) -> dict:
        """
        Get session information for peer.
        
        Args:
            peer_id: Peer identifier
        
        Returns:
            Session information dictionary
        """
        return self.peer_sessions.get(peer_id, {})
    
    def get_established_sessions(self) -> dict:
        """
        Get all established sessions.
        
        Returns:
            Dictionary mapping peer_id to session info for all established sessions
        """
        established = {}
        for peer_id, session_info in self.peer_sessions.items():
            if session_info.get('status') == 'established':
                established[peer_id] = session_info
        return established
    
    def _accept_connections(self):
        """Accept incoming connections (runs in separate thread)."""
        while self.is_running:
            try:
                client_socket, address = self.server_socket.accept()
                print(f"Incoming connection from {address}")
                
                # Handle connection in separate thread
                thread = threading.Thread(
                    target=self._handle_incoming_connection,
                    args=(client_socket, address),
                    daemon=True
                )
                thread.start()
                
            except Exception as e:
                if self.is_running:
                    print(f"Error accepting connection: {e}")
                break
    
    def _handle_incoming_connection(self, client_socket: socket.socket, address: tuple):
        """
        Handle incoming peer connection.
        
        Args:
            client_socket: Client socket object
            address: Client address tuple
        """
        peer_id = None
        try:
            # Configure client socket for better stability
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            
            # Wait for handshake
            client_socket.settimeout(60)
            data = self._receive_raw_message(client_socket)
            
            if data:
                handshake = json.loads(data)
                if handshake.get('type') == 'handshake':
                    peer_id = handshake.get('peer_id')
                    
                    if peer_id:
                        self.client_connections[peer_id] = client_socket
                        print(f"Peer {peer_id} connected from {address}")
                        
                        # Send handshake response
                        response = {
                            "type": "handshake_response",
                            "peer_id": self._get_own_peer_id(),
                            "timestamp": datetime.now().isoformat()
                        }
                        self._send_raw_message(client_socket, json.dumps(response))
                        
                        # Start message handling
                        self._handle_peer_connection(client_socket, peer_id)
        
        except Exception as e:
            print(f"Error handling incoming connection: {e}")
        finally:
            if peer_id:
                self._close_connection(peer_id, client_socket)
    
    def _handle_peer_connection(self, conn: socket.socket, peer_id: str):
        """
        Handle messages from a connected peer.
        
        Args:
            conn: Socket connection to the peer
            peer_id: Peer identifier
        """
        try:
            # Set socket timeout for receiving messages
            conn.settimeout(300)  # 5 minutes timeout for receiving
            
            while self.is_running and peer_id in self.client_connections:
                try:
                    data = self._receive_raw_message(conn)
                    if not data:
                        print(f"No data received from {peer_id}, connection may be closed")
                        break
                    
                    try:
                        message = json.loads(data)
                        self._process_received_message(message, peer_id)
                    except json.JSONDecodeError as e:
                        print(f"Invalid JSON from {peer_id}: {e}")
                        continue  # Continue processing other messages
                        
                except socket.timeout:
                    # Check if peer is still connected with a keep-alive
                    try:
                        conn.send(b'')  # Try to send empty data to test connection
                    except:
                        print(f"Connection timeout with {peer_id}")
                        break
                    continue
                except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
                    print(f"Connection error with {peer_id}: {e}")
                    break
                
        except Exception as e:
            print(f"Error handling peer {peer_id}: {e}")
        finally:
            self._close_connection(peer_id, conn)
    
    def _process_received_message(self, message: Dict[str, Any], peer_id: str):
        """
        Process received message from peer.
        
        Args:
            message: Received message dictionary
            peer_id: Sender peer identifier
        """
        try:
            message_type = message.get('type')
            
            # Handle encrypted messages
            if message.get('encrypted'):
                encrypted_content = bytes.fromhex(message.get('content', ''))
                received_hmac = bytes.fromhex(message.get('hmac', ''))
                
                # Decrypt message
                decrypted_json = self.crypto_manager.decrypt_message(encrypted_content, peer_id=peer_id)
                
                # Verify HMAC
                if not self.crypto_manager.verify_hmac(decrypted_json, received_hmac, peer_id=peer_id):
                    print(f"🚨 SECURITY ALERT: HMAC verification failed for message from {peer_id}")
                    print(f"⚠️  This could indicate a TAMPERING ATTACK or message corruption!")
                    print(f"⚠️  Message REJECTED for security reasons!")
                    
                    # Show security alert in GUI if available
                    if hasattr(self, 'gui_manager') and self.gui_manager:
                        self.gui_manager.show_security_alert(
                            f"Security Alert: Message from {peer_id} failed authentication check. "
                            f"This could indicate a tampering attack. Message was rejected."
                        )
                    return
                
                # Parse decrypted message
                decrypted_message = json.loads(decrypted_json)
                message_type = decrypted_message.get('type')
                
                # Call registered handler
                if message_type in self.message_handlers:
                    self.message_handlers[message_type](decrypted_message, peer_id)
            
            # Handle unencrypted control messages
            elif message_type in self.message_handlers:
                self.message_handlers[message_type](message, peer_id)
                
        except Exception as e:
            print(f"Error processing message from {peer_id}: {e}")
    
    def _send_raw_message(self, conn: socket.socket, message: str) -> bool:
        """
        Send raw message through socket.
        
        Args:
            conn: Socket connection
            message: Message string to send
        
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            message_bytes = message.encode('utf-8')
            message_length = len(message_bytes)
            
            # Add a small delay for large messages to prevent overwhelming the connection
            if message_length > 8192:  # 8KB threshold
                time.sleep(0.01)  # 10ms delay
            
            # Send message length first (4 bytes)
            conn.sendall(message_length.to_bytes(4, byteorder='big'))
            # Send message content
            conn.sendall(message_bytes)
            
            # Add small delay after sending to ensure data is processed
            time.sleep(0.001)  # 1ms delay
            return True
            
        except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
            print(f"Connection error sending message: {e}")
            return False
        except Exception as e:
            print(f"Error sending message: {e}")
            return False
    
    def _receive_raw_message(self, conn: socket.socket) -> Optional[str]:
        """
        Receive raw message from socket.
        
        Args:
            conn: Socket connection
        
        Returns:
            Received message string or None if error
        """
        try:
            # Receive message length (4 bytes)
            length_bytes = self._receive_exact(conn, 4)
            if not length_bytes:
                return None
            
            message_length = int.from_bytes(length_bytes, byteorder='big')
            
            # Validate message length to prevent memory issues
            if message_length > 10 * 1024 * 1024:  # 10MB limit
                print(f"Message too large: {message_length} bytes")
                return None
            
            # Receive message content
            message_bytes = self._receive_exact(conn, message_length)
            if not message_bytes:
                return None
            
            return message_bytes.decode('utf-8')
            
        except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
            print(f"Connection error receiving message: {e}")
            return None
        except Exception as e:
            print(f"Error receiving message: {e}")
            return None
    
    def _receive_exact(self, conn: socket.socket, num_bytes: int) -> Optional[bytes]:
        """
        Receive exact number of bytes from socket.
        
        Args:
            conn: Socket connection
            num_bytes: Number of bytes to receive
        
        Returns:
            Received bytes or None if error
        """
        data = b''
        while len(data) < num_bytes:
            try:
                bytes_needed = num_bytes - len(data)
                # Receive in smaller chunks to prevent blocking
                chunk_size = min(bytes_needed, 8192)  # 8KB chunks
                packet = conn.recv(chunk_size)
                
                if not packet:
                    return None
                data += packet
                
            except socket.timeout:
                # If we have partial data, continue trying
                if len(data) > 0:
                    continue
                else:
                    return None
            except (ConnectionResetError, ConnectionAbortedError, OSError):
                return None
        return data
    
    def _close_connection(self, peer_id: str, conn: socket.socket):
        """
        Close connection to a peer.
        
        Args:
            peer_id: Peer identifier
            conn: Socket connection
        """
        try:
            conn.close()
        except:
            pass
        
        if peer_id in self.client_connections:
            del self.client_connections[peer_id]
        
        if peer_id in self.connection_threads:
            del self.connection_threads[peer_id]
        
        print(f"Connection to {peer_id} closed")
        
        # Notify about connection closure for chat cleanup
        if hasattr(self, 'connection_closed_callback') and self.connection_closed_callback:
            try:
                self.connection_closed_callback(peer_id)
            except Exception as e:
                print(f"Error in connection closed callback: {e}")
    
    def get_local_ip(self) -> str:
        """
        Get local IP address (public method).
        
        Returns:
            Local IP address string
        """
        return self.local_ip
    
    def _get_local_ip(self) -> str:
        """
        Get local IP address (private method for initialization).
        
        Returns:
            Local IP address string
        """
        try:
            # Connect to a remote address to determine local IP
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp_socket.connect(("8.8.8.8", 80))
            local_ip = temp_socket.getsockname()[0]
            temp_socket.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    def _handle_secure_handshake(self, message: Dict[str, Any], peer_id: str):
        """
        Handle secure handshake message for session initiation.
        
        Args:
            message: Handshake message
            peer_id: Sender peer identifier
        """
        try:
            print(f"🔒 Received secure handshake from peer {peer_id}")
            
            handshake_data = message.get('handshake_data', {})
            
            # Validate protocol version
            protocol_version = handshake_data.get('protocol_version', '1.0')
            if protocol_version != '1.0':
                print(f"❌ Unsupported protocol version: {protocol_version}")
                return
            
            # Validate encryption algorithms
            encryption_algos = handshake_data.get('encryption_algorithms', [])
            if 'RSA-2048-OAEP-SHA256' not in encryption_algos:
                print(f"❌ Unsupported encryption algorithms: {encryption_algos}")
                return
            
            # Extract and validate peer's public key
            peer_public_key_b64 = handshake_data.get('public_key', '')
            if not peer_public_key_b64:
                print(f"❌ No public key in handshake from {peer_id}")
                return
            
            try:
                import base64
                peer_public_key_pem = base64.b64decode(peer_public_key_b64)
                
                # Validate peer's public key
                expected_fingerprint = handshake_data.get('key_fingerprint')
                if not self.crypto_manager.validate_peer_public_key(peer_public_key_pem, expected_fingerprint):
                    print(f"❌ Invalid public key from peer {peer_id}")
                    return
                
                # Respond with our own key exchange
                self.initiate_secure_session(peer_id, peer_public_key_pem)
                
                print(f"✅ Processed secure handshake from peer {peer_id}")
                
            except Exception as e:
                print(f"❌ Failed to process public key from {peer_id}: {e}")
                
        except Exception as e:
            print(f"❌ Error handling secure handshake from {peer_id}: {e}")
    
    def _handle_key_exchange(self, message: Dict[str, Any], peer_id: str):
        """
        Handle key exchange message for session establishment.
        
        Args:
            message: Key exchange message
            peer_id: Sender peer identifier
        """
        try:
            print(f"🔑 Received key exchange from peer {peer_id}")
            
            key_exchange_data = message.get('key_exchange_data', {})
            handshake_data = message.get('handshake_data', {})
            
            # Extract peer's public key from handshake data
            peer_public_key_b64 = handshake_data.get('public_key', '')
            peer_public_key_pem = None
            if peer_public_key_b64:
                try:
                    peer_public_key_pem = base64.b64decode(peer_public_key_b64.encode('utf-8'))
                except Exception as e:
                    print(f"❌ Failed to decode peer public key: {e}")
            
            # Decrypt the session key using our private key
            try:
                session_key = self.crypto_manager.decrypt_session_key(key_exchange_data, peer_id)
                
                if session_key:
                    # Update session state
                    session_info = {
                        'status': 'established',
                        'established_at': time.time(),
                        'session_key': session_key,
                        'protocol_version': message.get('protocol_version', '1.0')
                    }
                    
                    # Store peer's public key if available
                    if peer_public_key_pem:
                        session_info['peer_public_key'] = peer_public_key_pem
                    
                    self.peer_sessions[peer_id] = session_info
                    
                    # Send session establishment confirmation
                    confirmation_message = {
                        "type": "session_established",
                        "status": "confirmed",
                        "session_id": f"{self._get_own_peer_id()}_{peer_id}_{int(time.time())}",
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    if peer_id in self.client_connections:
                        conn = self.client_connections[peer_id]
                        self._send_raw_message(conn, json.dumps(confirmation_message))
                    
                    # Call session establishment callback if registered
                    if peer_id in self.session_establishment_callbacks:
                        callback = self.session_establishment_callbacks[peer_id]
                        callback(peer_id, True, "Session established successfully")
                        del self.session_establishment_callbacks[peer_id]
                    
                    print(f"✅ Secure session established with peer {peer_id}")
                else:
                    # Session key decryption failed (could be MITM attack)
                    print(f"❌ Failed to decrypt session key from peer {peer_id}")
                    
                    # Call failure callback if registered
                    if peer_id in self.session_establishment_callbacks:
                        callback = self.session_establishment_callbacks[peer_id]
                        callback(peer_id, False, "RSA key exchange failed - possible MITM attack detected!")
                        del self.session_establishment_callbacks[peer_id]
                    
            except Exception as decrypt_error:
                # Decryption failed - check if it's due to RSA MITM attack
                attack_states = get_attack_states()
                is_mitm_active = attack_states.get('rsa_mitm_active', False)
                
                if is_mitm_active:
                    print(f"🚨 RSA MITM ATTACK CONFIRMED! Attack is currently active.")
                    print(f"🚨 Key exchange compromised - session cannot be established!")
                    error_msg = '''🚨 MITM ATTACK DETECTED!
                    
                    The key exchange has been compromised by a Man-in-the-Middle attack.
                    Secure communication cannot be established.
                    ⚠️ This connection is NOT SAFE!'''
                else:
                    print(f"🚨 RSA decryption failed from peer {peer_id}: {decrypt_error}")
                    print(f"🚨 POSSIBLE RSA MITM ATTACK OR KEY MISMATCH!")
                    error_msg = f'''RSA Key Exchange Failed!
                    Unable to decrypt session key.
                    Possible causes:
                    • RSA MITM Attack
                    • Key corruption
                    • Protocol mismatch
                    
                    Error: {str(decrypt_error)}'''
                
                # Call failure callback if registered
                if peer_id in self.session_establishment_callbacks:
                    callback = self.session_establishment_callbacks[peer_id]
                    callback(peer_id, False, error_msg)
                    del self.session_establishment_callbacks[peer_id]
                
        except Exception as e:
            print(f"❌ Error handling key exchange from {peer_id}: {e}")
            
            # Call failure callback for any other errors
            if peer_id in self.session_establishment_callbacks:
                callback = self.session_establishment_callbacks[peer_id]
                callback(peer_id, False, f"Key exchange error: {str(e)}")
                del self.session_establishment_callbacks[peer_id]
    
    def _handle_session_established(self, message: Dict[str, Any], peer_id: str):
        """
        Handle session established confirmation message.
        
        Args:
            message: Session established message
            peer_id: Sender peer identifier
        """
        try:
            print(f"✅ Session establishment confirmed by peer {peer_id}")
            
            status = message.get('status')
            if status == 'confirmed':
                # Update our session state
                if peer_id in self.peer_sessions:
                    self.peer_sessions[peer_id]['status'] = 'established'
                    self.peer_sessions[peer_id]['confirmed_at'] = time.time()
                
                # Call session establishment callback if registered
                if peer_id in self.session_establishment_callbacks:
                    callback = self.session_establishment_callbacks[peer_id]
                    callback(peer_id, True, "Session confirmed by peer")
                    del self.session_establishment_callbacks[peer_id]
                
                print(f"🔐 Secure session fully established with peer {peer_id}")
                
        except Exception as e:
            print(f"❌ Error handling session establishment from {peer_id}: {e}")
    
    def cleanup_session_data(self, peer_id: str = None):
        """
        Clean up session data for specific peer or all peers.
        
        Args:
            peer_id: Peer to clean up, or None for all peers
        """
        try:
            if peer_id:
                # Clean up specific peer
                self.peer_sessions.pop(peer_id, None)
                self.handshake_timeouts.pop(peer_id, None)  
                self.session_establishment_callbacks.pop(peer_id, None)
                self.crypto_manager.clear_session_data(peer_id)
                print(f"🧹 Cleaned up session data for peer {peer_id}")
            else:
                # Clean up all sessions
                self.peer_sessions.clear()
                self.handshake_timeouts.clear()
                self.session_establishment_callbacks.clear()
                self.crypto_manager.clear_session_data()
                print("🧹 Cleaned up all session data")
                
        except Exception as e:
            print(f"Error cleaning up session data: {e}")

    def _get_own_peer_id(self) -> str:
        """
        Get own peer identifier.
        
        Returns:
            Own peer ID string
        """
        # This should be implemented based on user authentication
        # For now, return a placeholder
        return f"peer_{self.local_ip}_{self.port}"


class NetworkError(Exception):
    """Custom exception for network operations."""
    pass