"""
GUI Manager for CipherNet Messenger
Handles the graphical user interface using CustomTkinter.

Author: Arjun Christopher
"""

import tkinter as tk
from tkinter import messagebox, filedialog
import customtkinter as ctk
from typing import Dict, Any, List, Optional
import threading
from datetime import datetime
from pathlib import Path

from crypto_manager import CryptographyManager
from network_manager import NetworkManager
from firebase_manager import FirebaseManager
from file_transfer_manager import FileTransferManager
from notification_manager import NotificationManager
from cleanup_manager import comprehensive_cleanup, cleanup_user_chats_on_exit


class GUIManager:
    """Manages the graphical user interface for CipherNet Messenger."""
    
    def __init__(self, auth_manager, config):
        """
        Initialize GUI manager.
        
        Args:
            auth_manager: Authentication manager instance
            config: Configuration manager instance
        """
        self.auth_manager = auth_manager
        self.config = config
        
        # Core managers
        self.crypto_manager = CryptographyManager(config.get('security.rsa_key_size', 2048))
        self.network_manager = NetworkManager(config, self.crypto_manager)
        self.firebase_manager = FirebaseManager(config, auth_manager)
        self.notification_manager = NotificationManager(config.get('app.name', 'CipherNet Messenger'))
        self.file_transfer_manager = FileTransferManager(
            config, self.crypto_manager, self.network_manager, self.notification_manager
        )
        
        # GUI setup
        ctk.set_appearance_mode(config.get('ui.theme', 'dark'))
        ctk.set_default_color_theme("blue")
        
        self.root = None
        self.current_frame = None
        self.chat_windows = {}  # {peer_id: ChatWindow}
        
        # User data
        self.current_user = None
        self.online_users = []
        self.public_key_pem = None
        self.private_key_pem = None
        self.processed_requests = set()  # Track processed request IDs
    
    def start_application(self):
        """Start the GUI application."""
        self.root = ctk.CTk()
        self.root.title(self.config.get('app.name', 'CipherNet Messenger'))
        self.root.geometry(f"{self.config.get('ui.window_width', 1000)}x{self.config.get('ui.window_height', 700)}")
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        
        # Show login screen
        self.show_login_screen()
        
        # Start GUI main loop
        self.root.mainloop()
    
    def show_login_screen(self):
        """Display the login/registration screen."""
        self._clear_current_frame()
        
        self.current_frame = ctk.CTkFrame(self.root)
        self.current_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        title_label = ctk.CTkLabel(
            self.current_frame,
            text="CipherNet Messenger",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title_label.pack(pady=(40, 20))
        
        subtitle_label = ctk.CTkLabel(
            self.current_frame,
            text="Secure P2P Communication",
            font=ctk.CTkFont(size=16)
        )
        subtitle_label.pack(pady=(0, 40))
        
        # Login form
        form_frame = ctk.CTkFrame(self.current_frame)
        form_frame.pack(pady=20, padx=100, fill="x")
        
        # Email
        ctk.CTkLabel(form_frame, text="Email:").pack(pady=(20, 5), anchor="w")
        self.email_entry = ctk.CTkEntry(form_frame, placeholder_text="Enter your email")
        self.email_entry.pack(pady=(0, 10), padx=20, fill="x")
        
        # Password
        ctk.CTkLabel(form_frame, text="Password:").pack(pady=(10, 5), anchor="w")
        self.password_entry = ctk.CTkEntry(form_frame, placeholder_text="Enter your password", show="*")
        self.password_entry.pack(pady=(0, 20), padx=20, fill="x")
        
        # Buttons
        button_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        button_frame.pack(pady=(0, 20), fill="x")
        
        login_button = ctk.CTkButton(
            button_frame,
            text="Login",
            command=self._handle_login,
            width=100
        )
        login_button.pack(side="left", padx=(20, 10))
        
        register_button = ctk.CTkButton(
            button_frame,
            text="Register",
            command=self._handle_register,
            width=100
        )
        register_button.pack(side="right", padx=(10, 20))
        
        # Status label
        self.status_label = ctk.CTkLabel(self.current_frame, text="")
        self.status_label.pack(pady=(10, 20))
        
        # Bind Enter key
        self.root.bind('<Return>', lambda e: self._handle_login())
    
    def show_main_screen(self):
        """Display the main messenger screen."""
        self._clear_current_frame()
        
        # Generate RSA key pair
        self.public_key_pem, self.private_key_pem = self.crypto_manager.generate_rsa_keypair()
        
        # Start network server
        if not self.network_manager.start_server():
            messagebox.showerror("Error", "Failed to start P2P server")
            self.show_login_screen()
            return
        
        # Publish presence to Firebase
        if not self.firebase_manager.publish_user_presence(self.public_key_pem):
            messagebox.showwarning("Warning", "Failed to publish presence. You may not be discoverable by others.")
        
        # Setup main interface
        self.current_frame = ctk.CTkFrame(self.root)
        self.current_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create main layout
        self._create_main_layout()
        
        # Start listening for requests
        self.firebase_manager.listen_for_requests(self._handle_chat_request)
        
        # Refresh online users
        self._refresh_online_users()
        
        # Setup continuous automatic refresh
        self.root.after(2000, self._periodic_refresh)  # Refresh every 2 seconds
    
    def _create_main_layout(self):
        """Create the main application layout."""
        # Header
        header_frame = ctk.CTkFrame(self.current_frame, height=60)
        header_frame.pack(fill="x", padx=5, pady=(5, 0))
        header_frame.pack_propagate(False)
        
        # User info
        user_label = ctk.CTkLabel(
            header_frame,
            text=f"Logged in as: {self.current_user['email']}",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        user_label.pack(side="left", padx=20, pady=15)
        
        # Logout button
        logout_button = ctk.CTkButton(
            header_frame,
            text="Logout",
            command=self._handle_logout,
            width=80
        )
        logout_button.pack(side="right", padx=20, pady=15)
        
        # Main content area
        content_frame = ctk.CTkFrame(self.current_frame)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Users list
        users_frame = ctk.CTkFrame(content_frame, width=300)
        users_frame.pack(side="left", fill="y", padx=(5, 2), pady=5)
        users_frame.pack_propagate(False)
        
        users_title = ctk.CTkLabel(
            users_frame,
            text="Online Users",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        users_title.pack(pady=(15, 10))
        
        # Scrollable users list
        self.users_scroll = ctk.CTkScrollableFrame(users_frame)
        self.users_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 15))
        
        # Chat area
        chat_frame = ctk.CTkFrame(content_frame)
        chat_frame.pack(side="right", fill="both", expand=True, padx=(2, 5), pady=5)
        
        welcome_label = ctk.CTkLabel(
            chat_frame,
            text="Select a user to start secure messaging",
            font=ctk.CTkFont(size=18)
        )
        welcome_label.pack(expand=True)
    
    def _handle_login(self):
        """Handle user login."""
        email = self.email_entry.get().strip()
        password = self.password_entry.get()
        
        if not email or not password:
            self.status_label.configure(text="Please fill in all fields")
            return
        
        self.status_label.configure(text="Logging in...")
        self.root.update()
        
        # Perform login in background thread
        threading.Thread(target=self._login_worker, args=(email, password), daemon=True).start()
    
    def _handle_register(self):
        """Handle user registration."""
        email = self.email_entry.get().strip()
        password = self.password_entry.get()
        
        if not email or not password:
            self.status_label.configure(text="Please fill in all fields")
            return
        
        self.status_label.configure(text="Registering...")
        self.root.update()
        
        # Perform registration in background thread
        threading.Thread(target=self._register_worker, args=(email, password), daemon=True).start()
    
    def _login_worker(self, email: str, password: str):
        """Login worker thread."""
        success, message = self.auth_manager.login_user(email, password)
        
        # Update UI in main thread
        self.root.after(0, self._login_callback, success, message)
    
    def _register_worker(self, email: str, password: str):
        """Registration worker thread."""
        success, message = self.auth_manager.register_user(email, password)
        
        # Update UI in main thread
        self.root.after(0, self._register_callback, success, message)
    
    def _login_callback(self, success: bool, message: str):
        """Handle login result."""
        if success:
            self.current_user = self.auth_manager.get_current_user()
            self.notification_manager.notify_authentication_success(self.current_user['email'])
            
            # Startup cleanup no longer needed - cleanup moved to exit
            
            self.show_main_screen()
        else:
            self.status_label.configure(text=f"Login failed: {message}")
            self.notification_manager.notify_error(f"Login failed: {message}")
    
    def _register_callback(self, success: bool, message: str):
        """Handle registration result."""
        if success:
            self.status_label.configure(text="Registration successful! Please login.")
        else:
            self.status_label.configure(text=f"Registration failed: {message}")
    
    def _handle_logout(self):
        """Handle user logout."""
        # Comprehensive cleanup before logout
        if self.current_user:
            print("🧹 Performing cleanup before logout...")
            comprehensive_cleanup(self.auth_manager, self.firebase_manager, silent=False)
            # Mark cleanup as done to prevent duplicate in atexit
            if hasattr(self, '_cleanup_done_flag'):
                self._cleanup_done_flag[0] = True
        
        # Standard cleanup
        self.firebase_manager.cleanup()
        self.network_manager.stop_server()
        
        # Close chat windows
        for window in list(self.chat_windows.values()):
            window.destroy()
        self.chat_windows.clear()
        
        # Logout
        self.auth_manager.logout_user()
        self.current_user = None
        
        # Show login screen
        self.show_login_screen()
    
    def _refresh_online_users(self):
        """Refresh the online users list."""
        threading.Thread(target=self._refresh_users_worker, daemon=True).start()
    
    def _refresh_users_worker(self):
        """Refresh users worker thread."""
        users = self.firebase_manager.get_online_users()
        self.root.after(0, self._update_users_list, users)
    
    def _update_users_list(self, users: List[Dict[str, Any]]):
        """Update the users list UI."""
        # Clear existing users
        for widget in self.users_scroll.winfo_children():
            widget.destroy()
        
        self.online_users = users
        
        if not users:
            no_users_label = ctk.CTkLabel(self.users_scroll, text="No other users online")
            no_users_label.pack(pady=20)
            return
        
        # Add user buttons
        for user in users:
            user_frame = ctk.CTkFrame(self.users_scroll)
            user_frame.pack(fill="x", pady=5, padx=5)
            
            # User email
            email_label = ctk.CTkLabel(
                user_frame,
                text=user['email'],
                font=ctk.CTkFont(size=12, weight="bold")
            )
            email_label.pack(anchor="w", padx=10, pady=(8, 2))
            
            # Status
            status_label = ctk.CTkLabel(
                user_frame,
                text=f"Status: {user['status']}",
                font=ctk.CTkFont(size=10)
            )
            status_label.pack(anchor="w", padx=10, pady=(0, 5))
            
            # Chat button
            chat_button = ctk.CTkButton(
                user_frame,
                text="Start Chat",
                command=lambda u=user: self._start_chat_request(u),
                width=80,
                height=25
            )
            chat_button.pack(side="right", padx=10, pady=5)
    
    def _start_chat_request(self, user: Dict[str, Any]):
        """Send a chat request to a user."""
        success = self.firebase_manager.send_chat_request(
            user['uid'],
            "Hello! Let's chat securely using CipherNet Messenger."
        )
        
        if success:
            messagebox.showinfo("Chat Request", f"Chat request sent to {user['email']}")
        else:
            messagebox.showerror("Error", "Failed to send chat request")
    
    def _handle_chat_request(self, requests: Dict[str, Any]):
        """Handle incoming chat requests."""
        if not requests:
            return
        
        # Process new requests
        for request_id, request_data in requests.items():
            if isinstance(request_data, dict) and request_data.get('status') == 'pending':
                from_email = request_data.get('from_email', 'Unknown user')
                message = request_data.get('message', '')
                
                # Show desktop notification
                self.notification_manager.notify_chat_request(from_email, message)
                
                # Show request dialog
                result = messagebox.askyesno(
                    "Chat Request",
                    f"Chat request from {from_email}:\n\n{message}\n\nAccept this request?"
                )
                
                if result:
                    # Accept request
                    local_ip, local_port = self.network_manager.get_local_address()
                    self.firebase_manager.respond_to_chat_request(
                        request_data['from_uid'],
                        request_id,
                        True,
                        local_ip
                    )
                else:
                    # Decline request
                    self.firebase_manager.respond_to_chat_request(
                        request_data['from_uid'],
                        request_id,
                        False
                    )
    
    def _periodic_refresh(self):
        """Continuous automatic refresh of online users and chat responses."""
        if self.current_user:
            self._refresh_online_users()
            self._check_chat_responses()
            # Schedule next refresh for continuous updates
            self.root.after(2000, self._periodic_refresh)

    def _check_chat_responses(self):
        """Check for accepted chat requests and establish connections."""
        if not self.current_user:
            return
            
        try:
            accepted_requests = self.firebase_manager.check_sent_requests_responses()
            
            for request in accepted_requests:
                request_id = request.get('request_id')
                
                # Skip if we already processed this request
                if request_id in self.processed_requests:
                    continue
                
                # Mark as processed to avoid duplicates
                self.processed_requests.add(request_id)
                
                target_email = request.get('target_email', 'Unknown')
                chat_info = request.get('chat_info', {})
                participants = chat_info.get('participants', {})
                
                # Find the target user's connection info
                target_ip = None
                target_port = None
                
                for uid, participant in participants.items():
                    if uid != self.current_user['uid']:
                        target_ip = participant.get('ip')
                        target_port = participant.get('port', 8888)
                        break
                
                if target_ip and target_port:
                    # Show notification that request was accepted
                    self.notification_manager.notify_chat_accepted(target_email)
                    
                    # Clean up the request FIRST to prevent duplicates
                    request_path = f"requests/{request['target_uid']}/{request['request_id']}"
                    self.firebase_manager._delete_data(request_path)
                    
                    # Schedule dialog display on main thread
                    self.root.after(0, self._show_chat_accepted_dialog, 
                                   target_email, target_ip, target_port, request)
                
        except Exception as e:
            print(f"Error checking chat responses: {e}")

    def _show_chat_accepted_dialog(self, target_email: str, target_ip: str, 
                                  target_port: int, request: Dict[str, Any]):
        """Show chat accepted dialog on main thread."""
        try:
            # Show connection dialog
            result = messagebox.askyesno(
                "Chat Request Accepted",
                f"{target_email} accepted your chat request!\n\n"
                f"Connection details:\nIP: {target_ip}\nPort: {target_port}\n\n"
                f"Start secure chat session?"
            )
            
            if result:
                # TODO: Start chat session with the target
                messagebox.showinfo(
                    "Chat Session", 
                    f"Starting secure chat with {target_email}\n"
                    f"Connecting to {target_ip}:{target_port}"
                )
            
            # Request was already cleaned up before dialog
            
        except Exception as e:
            print(f"Error showing chat accepted dialog: {e}")



    def _clear_current_frame(self):
        """Clear the current frame."""
        if self.current_frame:
            self.current_frame.destroy()
            self.current_frame = None
    
    def _on_closing(self):
        """Handle application closing."""
        # Comprehensive cleanup before exit
        if self.current_user:
            print("🧹 Performing cleanup before exit...")
            comprehensive_cleanup(self.auth_manager, self.firebase_manager, silent=False)
            # Mark cleanup as done to prevent duplicate in atexit
            if hasattr(self, '_cleanup_done_flag'):
                self._cleanup_done_flag[0] = True
        
        # Standard cleanup
        self.firebase_manager.cleanup()
        
        if self.network_manager:
            self.network_manager.stop_server()
        
        self.root.destroy()


class ChatWindow:
    """Individual chat window for peer-to-peer communication."""
    
    def __init__(self, peer_id: str, peer_email: str, crypto_manager, network_manager, file_transfer_manager, notification_manager=None):
        """
        Initialize chat window.
        
        Args:
            peer_id: Peer identifier
            peer_email: Peer email address
            crypto_manager: Cryptography manager instance
            network_manager: Network manager instance
            file_transfer_manager: File transfer manager instance
            notification_manager: Notification manager instance (optional)
        """
        self.peer_id = peer_id
        self.peer_email = peer_email
        self.crypto_manager = crypto_manager
        self.network_manager = network_manager
        self.file_transfer_manager = file_transfer_manager
        self.notification_manager = notification_manager
        
        # Create window
        self.window = ctk.CTkToplevel()
        self.window.title(f"Secure Chat - {peer_email}")
        self.window.geometry("600x500")
        
        # Setup UI
        self._setup_ui()
        
        # Register message handlers
        self._register_handlers()
        
        # Handle window close
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)
    
    def _setup_ui(self):
        """Setup the chat window UI."""
        # Header
        header_frame = ctk.CTkFrame(self.window, height=50)
        header_frame.pack(fill="x", padx=5, pady=5)
        header_frame.pack_propagate(False)
        
        title_label = ctk.CTkLabel(
            header_frame,
            text=f"Chatting with {self.peer_email}",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        title_label.pack(side="left", padx=15, pady=15)
        
        # File button
        file_button = ctk.CTkButton(
            header_frame,
            text="Send File",
            command=self._send_file,
            width=80
        )
        file_button.pack(side="right", padx=15, pady=10)
        
        # Chat area
        self.chat_text = ctk.CTkTextbox(self.window, state="disabled")
        self.chat_text.pack(fill="both", expand=True, padx=5, pady=(0, 5))
        
        # Input area
        input_frame = ctk.CTkFrame(self.window, height=60)
        input_frame.pack(fill="x", padx=5, pady=(0, 5))
        input_frame.pack_propagate(False)
        
        self.message_entry = ctk.CTkEntry(input_frame, placeholder_text="Type your message...")
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(10, 5), pady=15)
        
        send_button = ctk.CTkButton(
            input_frame,
            text="Send",
            command=self._send_message,
            width=60
        )
        send_button.pack(side="right", padx=(0, 10), pady=15)
        
        # Bind Enter key
        self.message_entry.bind('<Return>', lambda e: self._send_message())
    
    def _register_handlers(self):
        """Register network message handlers."""
        self.network_manager.register_message_handler('text_message', self._handle_text_message)
        self.network_manager.register_message_handler('session_key', self._handle_session_key)
    
    def _send_message(self):
        """Send a text message."""
        message = self.message_entry.get().strip()
        if not message:
            return
        
        # Clear input
        self.message_entry.delete(0, tk.END)
        
        # Add to chat
        self._add_message("You", message, is_own=True)
        
        # Send message
        success = self.network_manager.send_message(
            self.peer_id,
            'text_message',
            {'message': message}
        )
        
        if not success:
            self._add_system_message("Failed to send message")
    
    def _send_file(self):
        """Send a file."""
        file_path = filedialog.askopenfilename(
            title="Select file to send",
            filetypes=[
                ("All supported", "*.txt;*.pdf;*.doc;*.docx;*.jpg;*.jpeg;*.png;*.gif;*.mp3;*.mp4;*.zip"),
                ("Text files", "*.txt"),
                ("Documents", "*.pdf;*.doc;*.docx"),
                ("Images", "*.jpg;*.jpeg;*.png;*.gif"),
                ("Media", "*.mp3;*.mp4"),
                ("Archives", "*.zip;*.rar"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            success = self.file_transfer_manager.send_file(self.peer_id, file_path)
            if success:
                self._add_system_message(f"Sending file: {Path(file_path).name}")
            else:
                self._add_system_message("Failed to initiate file transfer")
    
    def _handle_text_message(self, message: Dict[str, Any], peer_id: str):
        """Handle incoming text message."""
        if peer_id == self.peer_id:
            content = message.get('content', {})
            text = content.get('message', '')
            sender = message.get('sender', 'Unknown')
            
            self._add_message(self.peer_email, text, is_own=False)
            
            # Show notification if window is not focused
            if self.notification_manager and not self.window.focus_get():
                self.notification_manager.notify_new_message(self.peer_email, text)
    
    def _handle_session_key(self, message: Dict[str, Any], peer_id: str):
        """Handle incoming session key."""
        if peer_id == self.peer_id:
            encrypted_key = bytes.fromhex(message.get('encrypted_key', ''))
            session_key = self.crypto_manager.decrypt_session_key(encrypted_key)
            self._add_system_message("Secure session established")
    
    def _add_message(self, sender: str, message: str, is_own: bool = False):
        """Add message to chat display."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        self.chat_text.configure(state="normal")
        
        if is_own:
            self.chat_text.insert(tk.END, f"[{timestamp}] You: {message}\n")
        else:
            self.chat_text.insert(tk.END, f"[{timestamp}] {sender}: {message}\n")
        
        self.chat_text.configure(state="disabled")
        self.chat_text.see(tk.END)
    
    def _add_system_message(self, message: str):
        """Add system message to chat display."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        self.chat_text.configure(state="normal")
        self.chat_text.insert(tk.END, f"[{timestamp}] System: {message}\n")
        self.chat_text.configure(state="disabled")
        self.chat_text.see(tk.END)
    
    def _on_close(self):
        """Handle window close."""
        self.network_manager.disconnect_from_peer(self.peer_id)
        self.window.destroy()
    
    def destroy(self):
        """Destroy the chat window."""
        self.window.destroy()


class GUIError(Exception):
    """Custom exception for GUI operations."""
    pass