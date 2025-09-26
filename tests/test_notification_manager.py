"""
Tests for Notification Manager
Tests desktop notification functionality for various events.

Author: Arjun Christopher
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).parent.parent / "src"))

from notification_manager import NotificationManager, NotificationError


class TestNotificationManager:
    """Test cases for NotificationManager class."""
    
    def test_initialization(self):
        """Test NotificationManager initialization."""
        notifier = NotificationManager("Test App")
        
        assert notifier.app_name == "Test App"
        assert notifier.enabled == True
        assert notifier.notifier is not None
    
    def test_enable_disable_notifications(self):
        """Test enabling and disabling notifications."""
        notifier = NotificationManager()
        
        # Default is enabled
        assert notifier.enabled == True
        
        # Disable notifications
        notifier.enable_notifications(False)
        assert notifier.enabled == False
        
        # Enable notifications
        notifier.enable_notifications(True)
        assert notifier.enabled == True
    
    @patch('notification_manager.threading.Thread')
    def test_chat_request_notification(self, mock_thread):
        """Test chat request notification."""
        notifier = NotificationManager()
        
        notifier.notify_chat_request("test@example.com", "Hello there!")
        
        # Should start a thread for async notification
        mock_thread.assert_called_once()
        thread_call = mock_thread.call_args
        assert thread_call[1]['daemon'] == True
    
    @patch('notification_manager.threading.Thread')
    def test_new_message_notification(self, mock_thread):
        """Test new message notification."""
        notifier = NotificationManager()
        
        notifier.notify_new_message("sender@example.com", "This is a test message")
        
        mock_thread.assert_called_once()
    
    @patch('notification_manager.threading.Thread')
    def test_file_request_notification(self, mock_thread):
        """Test file request notification."""
        notifier = NotificationManager()
        
        notifier.notify_file_request("sender@example.com", "test.pdf", 1024000)
        
        mock_thread.assert_called_once()
    
    @patch('notification_manager.threading.Thread')
    def test_file_complete_notification_success(self, mock_thread):
        """Test successful file completion notification."""
        notifier = NotificationManager()
        
        notifier.notify_file_complete("test.pdf", True)
        
        mock_thread.assert_called_once()
    
    @patch('notification_manager.threading.Thread')
    def test_file_complete_notification_failure(self, mock_thread):
        """Test failed file completion notification."""
        notifier = NotificationManager()
        
        notifier.notify_file_complete("test.pdf", False)
        
        mock_thread.assert_called_once()
    
    @patch('notification_manager.threading.Thread')
    def test_peer_connected_notification(self, mock_thread):
        """Test peer connected notification."""
        notifier = NotificationManager()
        
        notifier.notify_peer_connected("peer@example.com")
        
        mock_thread.assert_called_once()
    
    @patch('notification_manager.threading.Thread')
    def test_peer_disconnected_notification(self, mock_thread):
        """Test peer disconnected notification."""
        notifier = NotificationManager()
        
        notifier.notify_peer_disconnected("peer@example.com")
        
        mock_thread.assert_called_once()
    
    @patch('notification_manager.threading.Thread')
    def test_authentication_success_notification(self, mock_thread):
        """Test authentication success notification."""
        notifier = NotificationManager()
        
        notifier.notify_authentication_success("user@example.com")
        
        mock_thread.assert_called_once()
    
    @patch('notification_manager.threading.Thread')
    def test_error_notification(self, mock_thread):
        """Test error notification."""
        notifier = NotificationManager()
        
        notifier.notify_error("Something went wrong!")
        
        mock_thread.assert_called_once()
    
    @patch('notification_manager.threading.Thread')
    def test_security_warning_notification(self, mock_thread):
        """Test security warning notification."""
        notifier = NotificationManager()
        
        notifier.notify_security_warning("Potential security breach detected")
        
        mock_thread.assert_called_once()
    
    def test_notifications_disabled(self):
        """Test that no notifications are sent when disabled."""
        notifier = NotificationManager()
        notifier.enable_notifications(False)
        
        with patch('notification_manager.threading.Thread') as mock_thread:
            notifier.notify_new_message("test@example.com", "Test message")
            
            # Should not create thread when disabled
            mock_thread.assert_not_called()
    
    def test_long_message_truncation(self):
        """Test that long messages are properly truncated."""
        notifier = NotificationManager()
        
        # Long message (over 150 characters)
        long_message = "A" * 200
        
        with patch('notification_manager.threading.Thread') as mock_thread:
            notifier.notify_new_message("test@example.com", long_message)
            
            mock_thread.assert_called_once()
    
    def test_long_error_message_truncation(self):
        """Test that long error messages are properly truncated."""
        notifier = NotificationManager()
        
        # Long error message (over 200 characters)
        long_error = "Error: " + "X" * 250
        
        with patch('notification_manager.threading.Thread') as mock_thread:
            notifier.notify_error(long_error)
            
            mock_thread.assert_called_once()
    
    def test_file_size_formatting(self):
        """Test file size formatting."""
        notifier = NotificationManager()
        
        # Test various file sizes
        assert notifier._format_file_size(512) == "512 B"
        assert notifier._format_file_size(1536) == "1.5 KB"
        assert notifier._format_file_size(1048576) == "1.0 MB"
        assert notifier._format_file_size(2147483648) == "2.0 GB"
    
    def test_file_size_formatting_edge_cases(self):
        """Test edge cases in file size formatting."""
        notifier = NotificationManager()
        
        # Zero size
        assert notifier._format_file_size(0) == "0 B"
        
        # Exactly 1 KB
        assert notifier._format_file_size(1024) == "1.0 KB"
        
        # Exactly 1 MB
        assert notifier._format_file_size(1024 * 1024) == "1.0 MB"
        
        # Exactly 1 GB
        assert notifier._format_file_size(1024 * 1024 * 1024) == "1.0 GB"
    
    @patch('notification_manager.asyncio.new_event_loop')
    @patch('notification_manager.asyncio.set_event_loop')
    def test_send_notification_async_loop_creation(self, mock_set_loop, mock_new_loop):
        """Test that _send_notification creates proper async loop."""
        notifier = NotificationManager()
        
        mock_loop = Mock()
        mock_new_loop.return_value = mock_loop
        
        # Mock the notifier.send method to avoid actual notification
        with patch.object(notifier.notifier, 'send', new_callable=AsyncMock):
            # Use threading to test the actual method
            import threading
            
            def test_thread():
                notifier._send_notification("Test", "Body")
            
            thread = threading.Thread(target=test_thread)
            thread.start()
            thread.join(timeout=1)  # Wait max 1 second
        
        # Verify loop was created and set
        mock_new_loop.assert_called_once()
        mock_set_loop.assert_called_once_with(mock_loop)
    
    def test_notification_with_empty_message(self):
        """Test notification with empty message."""
        notifier = NotificationManager()
        
        with patch('notification_manager.threading.Thread') as mock_thread:
            notifier.notify_new_message("test@example.com", "")
            
            # Should still create notification even with empty message
            mock_thread.assert_called_once()
    
    def test_notification_with_special_characters(self):
        """Test notification with special characters."""
        notifier = NotificationManager()
        
        special_message = "Hello! 🔐 This message contains émojis and spécial charactërs 中文"
        
        with patch('notification_manager.threading.Thread') as mock_thread:
            notifier.notify_new_message("test@example.com", special_message)
            
            mock_thread.assert_called_once()
    
    def test_concurrent_notifications(self):
        """Test sending multiple notifications concurrently."""
        notifier = NotificationManager()
        
        with patch('notification_manager.threading.Thread') as mock_thread:
            # Send multiple notifications quickly
            notifier.notify_new_message("user1@example.com", "Message 1")
            notifier.notify_new_message("user2@example.com", "Message 2")
            notifier.notify_error("Error occurred")
            
            # Should create separate threads for each notification
            assert mock_thread.call_count == 3
    
    @patch('notification_manager.threading.Thread')
    def test_notification_thread_daemon_mode(self, mock_thread):
        """Test that notification threads are created in daemon mode."""
        notifier = NotificationManager()
        
        notifier.notify_new_message("test@example.com", "Test")
        
        # Check that thread was created with daemon=True
        thread_call = mock_thread.call_args
        assert thread_call[1]['daemon'] == True
    
    def test_app_name_in_notifier(self):
        """Test that app name is properly set in the notifier."""
        app_name = "Custom Messenger App"
        notifier = NotificationManager(app_name)
        
        assert notifier.app_name == app_name
        assert notifier.notifier.app_name == app_name