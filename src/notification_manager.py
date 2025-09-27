"""
Notification Manager for CipherNet Messenger
Handles desktop notifications for various events.

Author: Arjun Christopher
"""

import asyncio
import threading
from typing import Optional
from desktop_notifier import DesktopNotifier, Urgency


class NotificationManager:
    """Manages desktop notifications for the application."""
    
    def __init__(self, app_name: str = "CipherNet Messenger"):
        """
        Initialize notification manager.
        
        Args:
            app_name: Name of the application for notifications
        """
        self.app_name = app_name
        self.notifier = DesktopNotifier(
            app_name=app_name,
            app_icon=None  # No icon for now, can be set to Path object later
        )
        self.enabled = True
    
    def enable_notifications(self, enabled: bool = True):
        """
        Enable or disable notifications.
        
        Args:
            enabled: Whether to enable notifications
        """
        self.enabled = enabled
    
    def notify_chat_request(self, sender_email: str, message: str = ""):
        """
        Show notification for incoming chat request.
        
        Args:
            sender_email: Email of the person sending request
            message: Optional message content
        """
        if not self.enabled:
            return
        
        title = "New Chat Request"
        body = f"From: {sender_email}"
        if message:
            body += f"\nMessage: {message[:100]}..."
        
        self._send_notification(title, body, Urgency.Normal)
    
    def notify_chat_accepted(self, target_email: str):
        """
        Show notification when chat request is accepted.
        
        Args:
            target_email: Email of user who accepted the request
        """
        if not self.enabled:
            return
        
        title = "Chat Request Accepted"
        body = f"{target_email} accepted your chat request! Ready to connect."
        
        self._send_notification(title, body, Urgency.Normal)
    
    def notify_new_message(self, sender_email: str, message: str):
        """
        Show notification for new message.
        
        Args:
            sender_email: Email of message sender
            message: Message content
        """
        if not self.enabled:
            return
        
        title = f"New Message from {sender_email}"
        # Truncate long messages
        body = message[:150] + "..." if len(message) > 150 else message
        
        self._send_notification(title, body, Urgency.Normal)
    
    def notify_file_request(self, sender_email: str, filename: str, file_size: int):
        """
        Show notification for incoming file transfer request.
        
        Args:
            sender_email: Email of file sender
            filename: Name of the file
            file_size: Size of the file in bytes
        """
        if not self.enabled:
            return
        
        title = "Incoming File Transfer"
        size_str = self._format_file_size(file_size)
        body = f"From: {sender_email}\nFile: {filename}\nSize: {size_str}"
        
        self._send_notification(title, body, Urgency.Normal)
    
    def notify_file_complete(self, filename: str, success: bool = True):
        """
        Show notification when file transfer completes.
        
        Args:
            filename: Name of the transferred file
            success: Whether transfer was successful
        """
        if not self.enabled:
            return
        
        if success:
            title = "File Transfer Complete"
            body = f"Successfully received: {filename}"
            urgency = Urgency.Low
        else:
            title = "File Transfer Failed"
            body = f"Failed to receive: {filename}"
            urgency = Urgency.Normal
        
        self._send_notification(title, body, urgency)
    
    def notify_peer_connected(self, peer_email: str):
        """
        Show notification when peer connects.
        
        Args:
            peer_email: Email of connected peer
        """
        if not self.enabled:
            return
        
        title = "Peer Connected"
        body = f"{peer_email} is now online"
        
        self._send_notification(title, body, Urgency.Low)
    
    def notify_peer_disconnected(self, peer_email: str):
        """
        Show notification when peer disconnects.
        
        Args:
            peer_email: Email of disconnected peer
        """
        if not self.enabled:
            return
        
        title = "Peer Disconnected" 
        body = f"{peer_email} went offline"
        
        self._send_notification(title, body, Urgency.Low)
    
    def notify_authentication_success(self, email: str):
        """
        Show notification for successful login.
        
        Args:
            email: User's email
        """
        if not self.enabled:
            return
        
        title = "Login Successful"
        body = f"Welcome back, {email}!"
        
        self._send_notification(title, body, Urgency.Low)
    
    def notify_error(self, error_message: str):
        """
        Show notification for errors.
        
        Args:
            error_message: Error message to display
        """
        if not self.enabled:
            return
        
        title = "CipherNet Error"
        body = error_message[:200] + "..." if len(error_message) > 200 else error_message
        
        self._send_notification(title, body, Urgency.Critical)
    
    def notify_security_warning(self, warning_message: str):
        """
        Show notification for security warnings.
        
        Args:
            warning_message: Security warning message
        """
        if not self.enabled:
            return
        
        title = "🔒 Security Warning"
        body = warning_message
        
        self._send_notification(title, body, Urgency.Critical)
    
    def _send_notification(self, title: str, body: str, urgency: Urgency = Urgency.Normal):
        """
        Send desktop notification with simplified error handling.
        
        Args:
            title: Notification title
            body: Notification body
            urgency: Notification urgency level
        """
        # For now, just print to console to avoid asyncio issues
        # This can be enhanced later with a proper notification system
        try:
            print(f"🔔 NOTIFICATION: {title} - {body}")
            
            # Optionally try to send actual notification but don't fail if it doesn't work
            try:
                # Use a simple synchronous approach with Windows toast notifications
                import subprocess
                import sys
                if sys.platform == "win32":
                    # Use Windows 10/11 toast notifications via PowerShell
                    ps_script = f"""
                    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
                    $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
                    $template.GetElementsByTagName("text")[0].AppendChild($template.CreateTextNode("{title}"))
                    $template.GetElementsByTagName("text")[1].AppendChild($template.CreateTextNode("{body}"))
                    $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
                    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("CipherNet Messenger").Show($toast)
                    """
                    subprocess.run(["powershell", "-Command", ps_script], 
                                 capture_output=True, timeout=2)
            except:
                # If native notifications fail, just use console output
                pass
                
        except Exception:
            # Silently fail notifications to avoid disrupting the main app
            pass
    
    def _format_file_size(self, size_bytes: int) -> str:
        """
        Format file size in human readable format.
        
        Args:
            size_bytes: File size in bytes
        
        Returns:
            Formatted size string
        """
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


class NotificationError(Exception):
    """Custom exception for notification operations."""
    pass