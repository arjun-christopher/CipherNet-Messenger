"""
Tests for Network Manager
Tests P2P networking functionality including connections, message routing, and protocol handling.

Author: Arjun Christopher
"""

import pytest
import socket
import threading
import time
import json
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).parent.parent / "src"))

from network_manager import NetworkManager, NetworkError
from conftest import MockSocket


class TestNetworkManager:
    """Test cases for NetworkManager class."""
    
    def test_initialization(self, mock_config):
        """Test NetworkManager initialization."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        assert network_manager.config == mock_config
        assert network_manager.crypto_manager == crypto_manager
        assert network_manager.port == 8889  # From test config
        assert network_manager.is_running == False
        assert len(network_manager.client_connections) == 0
    
    @patch('network_manager.socket.socket')
    def test_start_server_success(self, mock_socket_class, mock_config):
        """Test successful server start."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        # Mock socket
        mock_socket = MockSocket()
        mock_socket_class.return_value = mock_socket
        
        success = network_manager.start_server()
        
        assert success == True
        assert network_manager.is_running == True
        assert network_manager.server_socket == mock_socket
        assert network_manager.server_thread is not None
    
    @patch('network_manager.socket.socket')
    def test_start_server_failure(self, mock_socket_class, mock_config):
        """Test server start failure."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        # Mock socket that raises exception
        mock_socket = Mock()
        mock_socket.bind.side_effect = OSError("Address already in use")
        mock_socket_class.return_value = mock_socket
        
        success = network_manager.start_server()
        
        assert success == False
        assert network_manager.is_running == False
    
    def test_stop_server(self, mock_config):
        """Test server stop functionality."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        # Set up running server state
        network_manager.is_running = True
        network_manager.server_socket = Mock()
        
        # Add mock connections
        mock_conn1 = Mock()
        mock_conn2 = Mock()
        network_manager.client_connections = {
            "peer1": mock_conn1,
            "peer2": mock_conn2
        }
        
        network_manager.stop_server()
        
        assert network_manager.is_running == False
        assert len(network_manager.client_connections) == 0
        network_manager.server_socket.close.assert_called_once()
    
    @patch('network_manager.socket.socket')
    def test_connect_to_peer_success(self, mock_socket_class, mock_config):
        """Test successful peer connection."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        mock_socket = MockSocket()
        mock_socket_class.return_value = mock_socket
        
        # Mock _send_raw_message to avoid actual network I/O
        network_manager._send_raw_message = Mock(return_value=True)
        
        success = network_manager.connect_to_peer("192.168.1.100", 8888, "peer123")
        
        assert success == True
        assert "peer123" in network_manager.client_connections
        assert network_manager.client_connections["peer123"] == mock_socket
    
    @patch('network_manager.socket.socket')
    def test_connect_to_peer_already_connected(self, mock_socket_class, mock_config):
        """Test connecting to already connected peer."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        # Simulate existing connection
        existing_socket = MockSocket()
        network_manager.client_connections["peer123"] = existing_socket
        
        success = network_manager.connect_to_peer("192.168.1.100", 8888, "peer123")
        
        assert success == True
        # Should not create new socket
        mock_socket_class.assert_not_called()
    
    @patch('network_manager.socket.socket')
    def test_connect_to_peer_failure(self, mock_socket_class, mock_config):
        """Test peer connection failure."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        mock_socket = Mock()
        mock_socket.connect.side_effect = ConnectionRefusedError("Connection refused")
        mock_socket_class.return_value = mock_socket
        
        success = network_manager.connect_to_peer("192.168.1.100", 8888, "peer123")
        
        assert success == False
        assert "peer123" not in network_manager.client_connections
    
    def test_disconnect_from_peer(self, mock_config):
        """Test disconnecting from peer."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        # Set up connection
        mock_socket = Mock()
        network_manager.client_connections["peer123"] = mock_socket
        
        network_manager.disconnect_from_peer("peer123")
        
        assert "peer123" not in network_manager.client_connections
        mock_socket.close.assert_called_once()
    
    def test_disconnect_from_nonexistent_peer(self, mock_config):
        """Test disconnecting from non-existent peer."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        # Should not raise exception
        network_manager.disconnect_from_peer("nonexistent_peer")
    
    def test_send_message_success(self, mock_config):
        """Test successful message sending."""
        crypto_manager = Mock()
        crypto_manager.encrypt_message.return_value = b"encrypted_data"
        crypto_manager.calculate_hmac.return_value = b"hmac_digest"
        
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        # Set up connection
        mock_socket = Mock()
        network_manager.client_connections["peer123"] = mock_socket
        network_manager._send_raw_message = Mock(return_value=True)
        
        success = network_manager.send_message("peer123", "text_message", {"message": "Hello"})
        
        assert success == True
        crypto_manager.encrypt_message.assert_called_once()
        crypto_manager.calculate_hmac.assert_called_once()
        network_manager._send_raw_message.assert_called_once()
    
    def test_send_message_no_connection(self, mock_config):
        """Test sending message without connection."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        success = network_manager.send_message("peer123", "text_message", {"message": "Hello"})
        
        assert success == False
    
    def test_send_session_key_success(self, mock_config):
        """Test successful session key sending."""
        crypto_manager = Mock()
        crypto_manager.encrypt_session_key.return_value = b"encrypted_key"
        
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        # Set up connection
        mock_socket = Mock()
        network_manager.client_connections["peer123"] = mock_socket
        network_manager._send_raw_message = Mock(return_value=True)
        
        success = network_manager.send_session_key("peer123", b"session_key", b"public_key")
        
        assert success == True
        crypto_manager.encrypt_session_key.assert_called_once_with(b"session_key", b"public_key")
        network_manager._send_raw_message.assert_called_once()
    
    def test_send_session_key_no_connection(self, mock_config):
        """Test sending session key without connection."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        success = network_manager.send_session_key("peer123", b"session_key", b"public_key")
        
        assert success == False
    
    def test_register_message_handler(self, mock_config):
        """Test registering message handlers."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        def test_handler(message, peer_id):
            pass
        
        network_manager.register_message_handler("test_message", test_handler)
        
        assert "test_message" in network_manager.message_handlers
        assert network_manager.message_handlers["test_message"] == test_handler
    
    def test_get_local_address(self, mock_config):
        """Test getting local address."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        ip, port = network_manager.get_local_address()
        
        assert isinstance(ip, str)
        assert isinstance(port, int)
        assert port == 8889  # From test config
    
    def test_get_connected_peers(self, mock_config):
        """Test getting connected peers list."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        # Add mock connections
        network_manager.client_connections = {
            "peer1": Mock(),
            "peer2": Mock(),
            "peer3": Mock()
        }
        
        peers = network_manager.get_connected_peers()
        
        assert len(peers) == 3
        assert "peer1" in peers
        assert "peer2" in peers
        assert "peer3" in peers
    
    def test_send_raw_message_success(self, mock_config):
        """Test successful raw message sending."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        mock_socket = MockSocket()
        test_message = "Hello, World!"
        
        success = network_manager._send_raw_message(mock_socket, test_message)
        
        assert success == True
        # Check that data was sent (length + message)
        assert len(mock_socket.sent_data) == 2
        # First should be length (4 bytes)
        assert len(mock_socket.sent_data[0]) == 4
        # Second should be message
        assert mock_socket.sent_data[1] == test_message.encode('utf-8')
    
    def test_send_raw_message_failure(self, mock_config):
        """Test raw message sending failure."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        mock_socket = Mock()
        mock_socket.sendall.side_effect = OSError("Connection broken")
        
        success = network_manager._send_raw_message(mock_socket, "Hello")
        
        assert success == False
    
    def test_receive_raw_message_success(self, mock_config):
        """Test successful raw message receiving."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        test_message = "Hello, World!"
        message_bytes = test_message.encode('utf-8')
        
        mock_socket = MockSocket()
        # Prepare receive data: length (4 bytes) + message
        mock_socket.receive_data = [
            len(message_bytes).to_bytes(4, byteorder='big'),
            message_bytes
        ]
        
        received = network_manager._receive_raw_message(mock_socket)
        
        assert received == test_message
    
    def test_receive_raw_message_failure(self, mock_config):
        """Test raw message receiving failure."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        mock_socket = MockSocket()
        # Empty receive data simulates connection closed
        mock_socket.receive_data = []
        
        received = network_manager._receive_raw_message(mock_socket)
        
        assert received is None
    
    def test_process_encrypted_message(self, mock_config):
        """Test processing encrypted messages."""
        crypto_manager = Mock()
        crypto_manager.decrypt_message.return_value = json.dumps({
            "type": "text_message",
            "content": {"message": "Hello"}
        })
        crypto_manager.verify_hmac.return_value = True
        
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        # Register handler
        test_handler = Mock()
        network_manager.register_message_handler("text_message", test_handler)
        
        encrypted_message = {
            "encrypted": True,
            "content": "deadbeef",  # hex encoded
            "hmac": "abcdef",      # hex encoded
            "timestamp": "2025-09-26T10:30:00Z"
        }
        
        network_manager._process_received_message(encrypted_message, "peer123")
        
        crypto_manager.decrypt_message.assert_called_once()
        crypto_manager.verify_hmac.assert_called_once()
        test_handler.assert_called_once()
    
    def test_process_message_hmac_verification_failure(self, mock_config):
        """Test processing message with HMAC verification failure."""
        crypto_manager = Mock()
        crypto_manager.decrypt_message.return_value = json.dumps({
            "type": "text_message",
            "content": {"message": "Hello"}
        })
        crypto_manager.verify_hmac.return_value = False  # HMAC verification fails
        
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        # Register handler
        test_handler = Mock()
        network_manager.register_message_handler("text_message", test_handler)
        
        encrypted_message = {
            "encrypted": True,
            "content": "deadbeef",
            "hmac": "wronghmac",
            "timestamp": "2025-09-26T10:30:00Z"
        }
        
        network_manager._process_received_message(encrypted_message, "peer123")
        
        # Handler should not be called due to HMAC failure
        test_handler.assert_not_called()
    
    def test_process_unencrypted_control_message(self, mock_config):
        """Test processing unencrypted control messages."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        # Register handler
        test_handler = Mock()
        network_manager.register_message_handler("handshake", test_handler)
        
        control_message = {
            "type": "handshake",
            "peer_id": "peer123",
            "timestamp": "2025-09-26T10:30:00Z"
        }
        
        network_manager._process_received_message(control_message, "peer123")
        
        test_handler.assert_called_once_with(control_message, "peer123")
    
    def test_process_message_no_handler(self, mock_config):
        """Test processing message with no registered handler."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        message = {
            "type": "unknown_message",
            "content": {"data": "test"}
        }
        
        # Should not raise exception
        network_manager._process_received_message(message, "peer123")
    
    def test_receive_exact_bytes_success(self, mock_config):
        """Test receiving exact number of bytes."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        test_data = b"Hello, World! This is test data."
        
        mock_socket = MockSocket()
        mock_socket.receive_data = [test_data]
        
        received = network_manager._receive_exact(mock_socket, len(test_data))
        
        assert received == test_data
    
    def test_receive_exact_bytes_partial(self, mock_config):
        """Test receiving exact bytes when data arrives in parts."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        # Simulate data arriving in multiple packets
        part1 = b"Hello, "
        part2 = b"World!"
        
        mock_socket = MockSocket()
        mock_socket.receive_data = [part1, part2]
        
        received = network_manager._receive_exact(mock_socket, len(part1 + part2))
        
        assert received == part1 + part2
    
    def test_receive_exact_bytes_connection_closed(self, mock_config):
        """Test receiving bytes when connection is closed."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        mock_socket = MockSocket()
        mock_socket.receive_data = []  # No data, connection closed
        
        received = network_manager._receive_exact(mock_socket, 10)
        
        assert received is None
    
    def test_close_connection(self, mock_config):
        """Test closing peer connection."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        # Set up connection
        mock_socket = Mock()
        network_manager.client_connections["peer123"] = mock_socket
        network_manager.connection_threads["peer123"] = Mock()
        
        network_manager._close_connection("peer123", mock_socket)
        
        assert "peer123" not in network_manager.client_connections
        assert "peer123" not in network_manager.connection_threads
        mock_socket.close.assert_called_once()
    
    @patch('network_manager.socket.socket')
    def test_get_local_ip(self, mock_socket_class, mock_config):
        """Test getting local IP address."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        mock_socket = Mock()
        mock_socket.getsockname.return_value = ("192.168.1.50", 12345)
        mock_socket_class.return_value = mock_socket
        
        local_ip = network_manager._get_local_ip()
        
        assert local_ip == "192.168.1.50"
    
    @patch('network_manager.socket.socket')
    def test_get_local_ip_fallback(self, mock_socket_class, mock_config):
        """Test local IP fallback to localhost."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        # Mock socket that raises exception
        mock_socket = Mock()
        mock_socket.connect.side_effect = OSError("Network unreachable")
        mock_socket_class.return_value = mock_socket
        
        local_ip = network_manager._get_local_ip()
        
        assert local_ip == "127.0.0.1"
    
    def test_get_own_peer_id(self, mock_config):
        """Test getting own peer identifier."""
        crypto_manager = Mock()
        network_manager = NetworkManager(mock_config, crypto_manager)
        
        peer_id = network_manager._get_own_peer_id()
        
        assert isinstance(peer_id, str)
        assert "peer_" in peer_id
        assert str(network_manager.port) in peer_id