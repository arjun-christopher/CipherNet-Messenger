"""
Network Manager for CipherNet Messenger
Handles P2P TCP connections, message routing, and network communication.

Author: Arjun Christopher
"""

import socket
import threading
import json
import time
from typing import Callable, Optional, Dict, Any, Tuple
from datetime import datetime


class NetworkManager:
    """Manages P2P network connections and message routing."""
    
    def __init__(self, config, crypto_manager):
        """
        Initialize network manager.
        
        Args:
            config: Configuration manager instance
            crypto_manager: Cryptography manager instance
        """
        self.config = config
        self.crypto_manager = crypto_manager
        
        self.server_socket = None
        self.client_connections = {}  # {peer_id: socket}
        self.message_handlers = {}  # {message_type: callback}
        self.is_running = False
        self.local_ip = self._get_local_ip()
        self.port = config.get('network.default_port', 8888)
        
        # Threading
        self.server_thread = None
        self.connection_threads = {}
    
    def start_server(self) -> bool:
        """
        Start P2P server to accept incoming connections.
        
        Returns:
            True if server started successfully, False otherwise
        """
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
            client_socket.settimeout(self.config.get('network.connection_timeout', 30))
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
            encrypted_content = self.crypto_manager.encrypt_message(message_json)
            hmac_tag = self.crypto_manager.calculate_hmac(message_json)
            
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
    
    def send_session_key(self, peer_id: str, session_key: bytes, public_key_pem: bytes) -> bool:
        """
        Send encrypted session key to peer.
        
        Args:
            peer_id: Target peer identifier
            session_key: Session key to send
            public_key_pem: Peer's public key
        
        Returns:
            True if session key sent successfully, False otherwise
        """
        try:
            encrypted_key = self.crypto_manager.encrypt_session_key(session_key, public_key_pem)
            
            key_message = {
                "type": "session_key",
                "encrypted_key": encrypted_key.hex(),
                "timestamp": datetime.now().isoformat(),
                "sender": self._get_own_peer_id()
            }
            
            if peer_id in self.client_connections:
                conn = self.client_connections[peer_id]
                return self._send_raw_message(conn, json.dumps(key_message))
            
            return False
            
        except Exception as e:
            print(f"Failed to send session key to {peer_id}: {e}")
            return False
    
    def register_message_handler(self, message_type: str, handler: Callable):
        """
        Register a callback handler for specific message types.
        
        Args:
            message_type: Type of message to handle
            handler: Callback function to handle the message
        """
        self.message_handlers[message_type] = handler
    
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
            # Wait for handshake
            client_socket.settimeout(30)
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
            while self.is_running and peer_id in self.client_connections:
                data = self._receive_raw_message(conn)
                if not data:
                    break
                
                try:
                    message = json.loads(data)
                    self._process_received_message(message, peer_id)
                except json.JSONDecodeError as e:
                    print(f"Invalid JSON from {peer_id}: {e}")
                
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
                decrypted_json = self.crypto_manager.decrypt_message(encrypted_content)
                
                # Verify HMAC
                if not self.crypto_manager.verify_hmac(decrypted_json, received_hmac):
                    print(f"HMAC verification failed for message from {peer_id}")
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
            
            # Send message length first (4 bytes)
            conn.sendall(message_length.to_bytes(4, byteorder='big'))
            # Send message content
            conn.sendall(message_bytes)
            return True
            
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
            
            # Receive message content
            message_bytes = self._receive_exact(conn, message_length)
            if not message_bytes:
                return None
            
            return message_bytes.decode('utf-8')
            
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
            packet = conn.recv(num_bytes - len(data))
            if not packet:
                return None
            data += packet
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
    
    def _get_local_ip(self) -> str:
        """
        Get local IP address.
        
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