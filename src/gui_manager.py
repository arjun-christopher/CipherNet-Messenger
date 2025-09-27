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
        """Create the main application layout with navigation and integrated chat."""
        # Initialize current view state
        self.current_view = "dashboard"
        self.active_chat = None
        self.integrated_chat_widgets = {}
        
        # Compact header
        header_frame = ctk.CTkFrame(self.current_frame, height=45)
        header_frame.pack(fill="x", padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        # User info - more compact
        user_label = ctk.CTkLabel(
            header_frame,
            text=f"🔐 {self.current_user['email']}",
            font=ctk.CTkFont(size=12, weight="bold")
        )
        user_label.pack(side="left", padx=15, pady=12)
        
        # Navigation buttons
        nav_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        nav_frame.pack(side="left", padx=(20, 0))
        
        self.dashboard_btn = ctk.CTkButton(
            nav_frame,
            text="📊 Dashboard",
            command=lambda: self._switch_view("dashboard"),
            width=100,
            height=32,
            fg_color=("#1f538d", "#14375e")
        )
        self.dashboard_btn.pack(side="left", padx=(0, 5))
        
        self.chats_btn = ctk.CTkButton(
            nav_frame,
            text="💬 Chats",
            command=lambda: self._switch_view("chats"),
            width=100,
            height=32,
            fg_color=("#565b5e", "#343638")
        )
        self.chats_btn.pack(side="left", padx=5)
        
        # Logout button - more compact
        logout_button = ctk.CTkButton(
            header_frame,
            text="Logout",
            command=self._handle_logout,
            width=70,
            height=32
        )
        logout_button.pack(side="right", padx=15, pady=6)
        
        # Main content area - no padding waste
        self.content_frame = ctk.CTkFrame(self.current_frame)
        self.content_frame.pack(fill="both", expand=True, padx=0, pady=(2, 0))
        
        # Create dashboard view
        self._create_dashboard_view()
        
        # Create chat view (initially hidden)
        self._create_chat_view()
    
    def _switch_view(self, view_name):
        """Switch between dashboard and chat views."""
        self.current_view = view_name
        
        if view_name == "dashboard":
            self.dashboard_btn.configure(fg_color=("#1f538d", "#14375e"))
            self.chats_btn.configure(fg_color=("#565b5e", "#343638"))
            self.dashboard_view.pack(fill="both", expand=True)
            self.chat_view.pack_forget()
        elif view_name == "chats":
            self.dashboard_btn.configure(fg_color=("#565b5e", "#343638"))
            self.chats_btn.configure(fg_color=("#1f538d", "#14375e"))
            self.dashboard_view.pack_forget()
            self.chat_view.pack(fill="both", expand=True)
    
    def _create_dashboard_view(self):
        """Create the dashboard view with online users."""
        self.dashboard_view = ctk.CTkFrame(self.content_frame)
        self.dashboard_view.pack(fill="both", expand=True)
        
        # Split layout - users on left, info on right
        users_frame = ctk.CTkFrame(self.dashboard_view, width=280)
        users_frame.pack(side="left", fill="y", padx=5, pady=5)
        users_frame.pack_propagate(False)
        
        users_title = ctk.CTkLabel(
            users_frame,
            text="🌐 Online Users",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        users_title.pack(pady=(10, 5))
        
        # Compact scrollable users list
        self.users_scroll = ctk.CTkScrollableFrame(users_frame)
        self.users_scroll.pack(fill="both", expand=True, padx=8, pady=(0, 10))
        
        # Info panel - more useful content
        info_frame = ctk.CTkFrame(self.dashboard_view)
        info_frame.pack(side="right", fill="both", expand=True, padx=(0, 5), pady=5)
        
        # Connection status
        status_label = ctk.CTkLabel(
            info_frame,
            text="🔒 Secure P2P Connection Active",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        status_label.pack(pady=20)
        
        # Quick stats
        stats_frame = ctk.CTkFrame(info_frame)
        stats_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(
            stats_frame,
            text="📈 Connection Stats",
            font=ctk.CTkFont(size=12, weight="bold")
        ).pack(pady=(10, 5))
        
        self.stats_text = ctk.CTkTextbox(stats_frame, height=100)
        self.stats_text.pack(fill="x", padx=10, pady=(0, 10))
        self._update_stats()
        
        # Instructions
        ctk.CTkLabel(
            info_frame,
            text="💡 Click on a user to send a chat request",
            font=ctk.CTkFont(size=12)
        ).pack(pady=10)
    
    def _create_chat_view(self):
        """Create the integrated chat view."""
        self.chat_view = ctk.CTkFrame(self.content_frame)
        # Don't pack initially - will be shown when switching views
        
        # Chat list sidebar
        chat_list_frame = ctk.CTkFrame(self.chat_view, width=250)
        chat_list_frame.pack(side="left", fill="y", padx=5, pady=5)
        chat_list_frame.pack_propagate(False)
        
        ctk.CTkLabel(
            chat_list_frame,
            text="💬 Active Chats",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(pady=(10, 5))
        
        self.chat_list_scroll = ctk.CTkScrollableFrame(chat_list_frame)
        self.chat_list_scroll.pack(fill="both", expand=True, padx=8, pady=(0, 10))
        
        # Main chat area
        self.main_chat_area = ctk.CTkFrame(self.chat_view)
        self.main_chat_area.pack(side="right", fill="both", expand=True, padx=(0, 5), pady=5)
        
        # Welcome message for chat view
        self.chat_welcome_label = ctk.CTkLabel(
            self.main_chat_area,
            text="💬 Select a chat to start messaging\n\nSwitch to Dashboard to find online users",
            font=ctk.CTkFont(size=16),
            justify="center"
        )
        self.chat_welcome_label.pack(expand=True)
    
    def _update_stats(self):
        """Update connection statistics."""
        try:
            local_ip, local_port = self.network_manager.get_local_address()
            stats_text = f"Local IP: {local_ip}\nPort: {local_port}\nEncryption: RSA + Blowfish\nStatus: Active"
            self.stats_text.delete("0.0", "end")
            self.stats_text.insert("0.0", stats_text)
        except:
            self.stats_text.delete("0.0", "end")
            self.stats_text.insert("0.0", "Connection info unavailable")
    
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
                    
                    # Create integrated chat interface immediately for the accepter
                    try:
                        # Get the requester's connection info from the request
                        requester_ip = request_data.get('sender_ip', 'unknown')
                        requester_port = request_data.get('sender_port', 8888)
                        peer_id = f"{requester_ip}:{requester_port}"
                        
                        # Create integrated chat interface
                        self._create_integrated_chat(peer_id, from_email)
                        
                        # Switch to chat view
                        self._switch_view("chats")
                        
                        # Show success notification
                        self.notification_manager.notify_chat_started(from_email)
                        
                    except Exception as e:
                        print(f"Error creating integrated chat for accepted request: {e}")
                        messagebox.showwarning(
                            "Chat Interface Error",
                            f"Request accepted but failed to open chat interface.\n"
                            f"The other user should still be able to connect."
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
                # Start actual chat session with the target
                try:
                    # Connect to peer via network manager
                    peer_id = f"{target_ip}:{target_port}"
                    
                    # Create integrated chat interface
                    self._create_integrated_chat(peer_id, target_email)
                    
                    # Connect to the peer
                    self.network_manager.connect_to_peer(target_ip, target_port)
                    
                    # Switch to chat view
                    self._switch_view("chats")
                    
                    # Show success notification
                    self.notification_manager.notify_chat_started(target_email)
                    
                except Exception as e:
                    messagebox.showerror(
                        "Connection Error",
                        f"Failed to start chat session with {target_email}:\n{str(e)}"
                    )
                    print(f"Error starting chat session: {e}")
            
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
    
    def _create_integrated_chat(self, peer_id: str, peer_email: str):
        """Create an integrated chat interface within the main window."""
        # Initialize integrated_chat_widgets if not exists
        if not hasattr(self, 'integrated_chat_widgets'):
            self.integrated_chat_widgets = {}
        
        # Create chat entry in sidebar
        self._add_chat_to_sidebar(peer_id, peer_email)
        
        # Create chat interface data
        chat_data = {
            'peer_id': peer_id,
            'peer_email': peer_email,
            'messages': [],
            'chat_frame': None
        }
        
        self.integrated_chat_widgets[peer_id] = chat_data
        
        # Activate this chat
        self._activate_integrated_chat(peer_id)
    
    def _add_chat_to_sidebar(self, peer_id: str, peer_email: str):
        """Add chat to the sidebar list."""
        chat_btn = ctk.CTkButton(
            self.chat_list_scroll,
            text=f"💬 {peer_email.split('@')[0]}",
            command=lambda: self._activate_integrated_chat(peer_id),
            anchor="w",
            height=40,
            fg_color=("#2b2b2b", "#212121")
        )
        chat_btn.pack(fill="x", pady=2, padx=5)
        
        # Store reference
        if peer_id in self.integrated_chat_widgets:
            self.integrated_chat_widgets[peer_id]['sidebar_btn'] = chat_btn
    
    def _activate_integrated_chat(self, peer_id: str):
        """Activate and display the specified chat."""
        if not hasattr(self, 'integrated_chat_widgets') or peer_id not in self.integrated_chat_widgets:
            return
        
        # Hide welcome message
        if hasattr(self, 'chat_welcome_label'):
            self.chat_welcome_label.pack_forget()
        
        # Hide current active chat if any
        if hasattr(self, 'active_chat') and self.active_chat and self.active_chat in self.integrated_chat_widgets:
            current_frame = self.integrated_chat_widgets[self.active_chat].get('chat_frame')
            if current_frame:
                current_frame.pack_forget()
        
        # Set new active chat
        self.active_chat = peer_id
        chat_data = self.integrated_chat_widgets[peer_id]
        
        # Create chat interface if not exists
        if not chat_data.get('chat_frame'):
            self._create_chat_interface(peer_id)
        
        # Show the chat frame
        chat_data['chat_frame'].pack(fill="both", expand=True)
    
    def _create_chat_interface(self, peer_id: str):
        """Create the actual chat interface for a peer."""
        chat_data = self.integrated_chat_widgets[peer_id]
        peer_email = chat_data['peer_email']
        
        # Main chat frame
        chat_frame = ctk.CTkFrame(self.main_chat_area)
        chat_data['chat_frame'] = chat_frame
        
        # Modern header
        self._create_chat_header(chat_frame, peer_email)
        
        # Messages area
        messages_frame = ctk.CTkScrollableFrame(
            chat_frame,
            fg_color=("#e5ddd5", "#0a1014")
        )
        messages_frame.pack(fill="both", expand=True, padx=0, pady=0)
        chat_data['messages_frame'] = messages_frame
        
        # Input area
        self._create_chat_input(chat_frame, peer_id)
        
        # Add welcome message
        self._add_system_message_integrated(peer_id, "🔒 Secure end-to-end encrypted chat established")
    
    def _create_chat_header(self, parent, peer_email: str):
        """Create modern chat header."""
        header_frame = ctk.CTkFrame(
            parent,
            height=60,
            fg_color=("#128c7e", "#075e54"),
            corner_radius=0
        )
        header_frame.pack(fill="x", padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        # Avatar
        avatar_frame = ctk.CTkFrame(
            header_frame,
            width=40,
            height=40,
            fg_color=("#dcf8c6", "#128c7e"),
            corner_radius=20
        )
        avatar_frame.pack(side="left", padx=15, pady=10)
        avatar_frame.pack_propagate(False)
        
        ctk.CTkLabel(
            avatar_frame,
            text=peer_email[0].upper(),
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=("#075e54", "white")
        ).pack(expand=True)
        
        # User info
        info_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        info_frame.pack(side="left", fill="both", expand=True, padx=(5, 0))
        
        ctk.CTkLabel(
            info_frame,
            text=peer_email.split('@')[0].title(),
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="white",
            anchor="w"
        ).pack(anchor="w", pady=(8, 0))
        
        ctk.CTkLabel(
            info_frame,
            text="🟢 Online • End-to-end encrypted",
            font=ctk.CTkFont(size=10),
            text_color=("#dcf8c6", "#a0a0a0"),
            anchor="w"
        ).pack(anchor="w", pady=(0, 8))
    
    def _create_chat_input(self, parent, peer_id: str):
        """Create modern chat input area."""
        input_container = ctk.CTkFrame(
            parent,
            height=60,
            fg_color=("#f0f2f5", "#1e2428"),
            corner_radius=0
        )
        input_container.pack(fill="x", padx=0, pady=(2, 0))
        input_container.pack_propagate(False)
        
        input_frame = ctk.CTkFrame(
            input_container,
            fg_color=("white", "#2a2f32"),
            corner_radius=20,
            height=40
        )
        input_frame.pack(fill="x", padx=10, pady=10)
        input_frame.pack_propagate(False)
        
        # Message entry
        message_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="Type a message...",
            font=ctk.CTkFont(size=13),
            fg_color="transparent",
            border_width=0
        )
        message_entry.pack(side="left", fill="x", expand=True, padx=(15, 5), pady=5)
        
        # Send button
        send_btn = ctk.CTkButton(
            input_frame,
            text="➤",
            command=lambda: self._send_integrated_message(peer_id, message_entry),
            width=30,
            height=30,
            fg_color=("#128c7e", "#075e54"),
            corner_radius=15,
            font=ctk.CTkFont(size=12, weight="bold")
        )
        send_btn.pack(side="right", padx=(5, 10), pady=5)
        
        # Bind Enter key
        message_entry.bind('<Return>', lambda e: self._send_integrated_message(peer_id, message_entry))
        
        # Store reference
        self.integrated_chat_widgets[peer_id]['message_entry'] = message_entry
    
    def _send_integrated_message(self, peer_id: str, entry_widget):
        """Send message in integrated chat."""
        message = entry_widget.get().strip()
        if not message:
            return
        
        # Clear entry
        entry_widget.delete(0, "end")
        
        # Add to chat display
        self._add_message_integrated(peer_id, "You", message, is_own=True)
        
        # TODO: Send via network manager
        # For now, just add the message to display
    
    def _add_message_integrated(self, peer_id: str, sender: str, message: str, is_own: bool = False):
        """Add message to integrated chat display."""
        if not hasattr(self, 'integrated_chat_widgets') or peer_id not in self.integrated_chat_widgets:
            return
        
        chat_data = self.integrated_chat_widgets[peer_id]
        messages_frame = chat_data.get('messages_frame')
        if not messages_frame:
            return
        
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M")
        
        # Message container
        msg_container = ctk.CTkFrame(messages_frame, fg_color="transparent")
        msg_container.pack(fill="x", padx=10, pady=2)
        
        # Message bubble
        if is_own:
            bubble_frame = ctk.CTkFrame(
                msg_container,
                fg_color=("#dcf8c6", "#056162"),
                corner_radius=15
            )
            bubble_frame.pack(side="right", padx=(50, 0))
        else:
            bubble_frame = ctk.CTkFrame(
                msg_container,
                fg_color=("white", "#1f2937"),
                corner_radius=15
            )
            bubble_frame.pack(side="left", padx=(0, 50))
        
        # Message text
        ctk.CTkLabel(
            bubble_frame,
            text=message,
            font=ctk.CTkFont(size=13),
            text_color=("#2d3748", "white"),
            wraplength=300,
            justify="left"
        ).pack(padx=12, pady=(8, 4))
        
        # Timestamp
        time_text = f"{timestamp} ✓✓" if is_own else timestamp
        ctk.CTkLabel(
            bubble_frame,
            text=time_text,
            font=ctk.CTkFont(size=9),
            text_color=("#718096", "#a0a0a0")
        ).pack(padx=12, pady=(0, 6), anchor="e" if is_own else "w")
        
        # Auto-scroll
        messages_frame._parent_canvas.yview_moveto(1.0)
    
    def _add_system_message_integrated(self, peer_id: str, message: str):
        """Add system message to integrated chat."""
        if not hasattr(self, 'integrated_chat_widgets') or peer_id not in self.integrated_chat_widgets:
            return
        
        chat_data = self.integrated_chat_widgets[peer_id]
        messages_frame = chat_data.get('messages_frame')
        if not messages_frame:
            return
        
        # System message container
        sys_container = ctk.CTkFrame(messages_frame, fg_color="transparent")
        sys_container.pack(fill="x", padx=10, pady=4)
        
        # System message bubble
        sys_bubble = ctk.CTkFrame(
            sys_container,
            fg_color=("#f7fafc", "#374151"),
            corner_radius=15
        )
        sys_bubble.pack(anchor="center")
        
        ctk.CTkLabel(
            sys_bubble,
            text=message,
            font=ctk.CTkFont(size=11),
            text_color=("#718096", "#9ca3af")
        ).pack(padx=15, pady=6)


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
        """Setup modern Instagram/WhatsApp-inspired chat UI."""
        # Initialize message storage
        self.messages = []
        
        # Modern Header - WhatsApp style
        self._create_modern_header()
        
        # Messages Container with custom scrolling
        self._create_messages_area()
        
        # Modern Input Area - Instagram/WhatsApp style  
        self._create_modern_input_area()
        
        # Add welcome message
        self._add_system_message("🔒 Secure end-to-end encrypted chat established")
    
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
        """Add modern message bubble to chat display."""
        timestamp = datetime.now().strftime("%H:%M")
        
        # Store message data
        message_data = {
            'sender': sender,
            'message': message,
            'timestamp': timestamp,
            'is_own': is_own
        }
        self.messages.append(message_data)
        
        # Create message bubble
        self._create_message_bubble(message_data)
        
        # Auto-scroll to bottom
        self.messages_frame._parent_canvas.yview_moveto(1.0)
        
    def _create_message_bubble(self, message_data):
        """Create a modern message bubble."""
        is_own = message_data['is_own']
        message = message_data['message']
        timestamp = message_data['timestamp']
        sender = message_data['sender']
        
        # Message container
        msg_container = ctk.CTkFrame(
            self.messages_frame,
            fg_color="transparent"
        )
        msg_container.pack(fill="x", padx=10, pady=2)
        
        # Message bubble frame
        if is_own:
            # Own messages - right aligned
            bubble_frame = ctk.CTkFrame(
                msg_container,
                fg_color=("#dcf8c6", "#276DC9"), 
                corner_radius=15
            )
            bubble_frame.pack(side="right", padx=(50, 0))
            
            # Message text
            msg_label = ctk.CTkLabel(
                bubble_frame,
                text=message,
                font=ctk.CTkFont(size=14),
                text_color=("#2d3748", "white"),
                wraplength=300,
                justify="left"
            )
            msg_label.pack(padx=15, pady=(10, 5))
            
            # Timestamp with read status
            time_label = ctk.CTkLabel(
                bubble_frame,
                text=f"{timestamp}",
                font=ctk.CTkFont(size=10),
                text_color=("#718096", "#a0a0a0")
            )
            time_label.pack(padx=15, pady=(0, 8), anchor="e")
            
        else:
            # Other messages - left aligned, white/gray bubble
            bubble_frame = ctk.CTkFrame(
                msg_container,
                fg_color=("white", "#1f2937"),
                corner_radius=15
            )
            bubble_frame.pack(side="left", padx=(0, 50))
            
            # Sender name (if not own message)
            if sender != "You":
                sender_label = ctk.CTkLabel(
                    bubble_frame,
                    text=sender.split('@')[0].title(),
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=("#538ee6bc", "#2542e7")
                )
                sender_label.pack(padx=15, pady=(8, 0), anchor="w")
            
            # Message text
            msg_label = ctk.CTkLabel(
                bubble_frame,
                text=message,
                font=ctk.CTkFont(size=14),
                text_color=("#2d3748", "white"),
                wraplength=300,
                justify="left"
            )
            msg_label.pack(padx=15, pady=(5, 5))
            
            # Timestamp
            time_label = ctk.CTkLabel(
                bubble_frame,
                text=timestamp,
                font=ctk.CTkFont(size=10),
                text_color=("#718096", "#a0a0a0")
            )
            time_label.pack(padx=15, pady=(0, 8), anchor="w")
    
    def _add_system_message(self, message: str):
        """Add system message with modern styling."""
        timestamp = datetime.now().strftime("%H:%M")
        
        # System message container - centered
        sys_container = ctk.CTkFrame(
            self.messages_frame,
            fg_color="transparent"
        )
        sys_container.pack(fill="x", padx=10, pady=5)
        
        # System message bubble - centered, subtle styling
        sys_bubble = ctk.CTkFrame(
            sys_container,
            fg_color=("#f7fafc", "#374151"),
            corner_radius=20
        )
        sys_bubble.pack(anchor="center")
        
        # System message text
        sys_label = ctk.CTkLabel(
            sys_bubble,
            text=message,
            font=ctk.CTkFont(size=12),
            text_color=("#718096", "#9ca3af")
        )
        sys_label.pack(padx=20, pady=8)
        
        # Auto-scroll to bottom
        self.messages_frame._parent_canvas.yview_moveto(1.0)
    
    def _on_close(self):
        """Handle window close."""
        self.network_manager.disconnect_from_peer(self.peer_id)
        self.window.destroy()
    
    def _create_modern_header(self):
        """Create modern header with user info and actions."""
        # Header with gradient-like effect
        header_frame = ctk.CTkFrame(
            self.window, 
            height=70,
            fg_color=("#538ee6bc", "#2542e7"),
            corner_radius=0
        )
        header_frame.pack(fill="x", padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        # User avatar placeholder (could be enhanced with actual avatars)
        avatar_frame = ctk.CTkFrame(
            header_frame,
            width=45,
            height=45,
            fg_color=("#dcf8c6", "#538ee6bc"),
            corner_radius=22
        )
        avatar_frame.pack(side="left", padx=15, pady=12)
        avatar_frame.pack_propagate(False)
        
        # Avatar text (first letter of email)
        avatar_label = ctk.CTkLabel(
            avatar_frame,
            text=self.peer_email[0].upper(),
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=("#538ee6bc", "white")
        )
        avatar_label.pack(expand=True)
        
        # User info section
        info_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        info_frame.pack(side="left", fill="both", expand=True, padx=(5, 0))
        
        # User name
        name_label = ctk.CTkLabel(
            info_frame,
            text=self.peer_email.split('@')[0].title(),
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="white",
            anchor="w"
        )
        name_label.pack(anchor="w", pady=(8, 0))
        
        # Status
        self.status_label = ctk.CTkLabel(
            info_frame,
            text="🟢 Online • End-to-end encrypted",
            font=ctk.CTkFont(size=11),
            text_color=("#dcf8c6", "#a0a0a0"),
            anchor="w"
        )
        self.status_label.pack(anchor="w", pady=(0, 8))
        
        # Action buttons frame
        actions_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        actions_frame.pack(side="right", padx=10, pady=10)
        
        # File/attachment button - modern icon style
        file_button = ctk.CTkButton(
            actions_frame,
            text="📎",
            command=self._send_file,
            width=35,
            height=35,
            fg_color="transparent",
            hover_color=("#538ee6bc", "#2542e7"),
            font=ctk.CTkFont(size=16)
        )
        file_button.pack(side="right", padx=(5, 0))
        
        # More options button
        options_button = ctk.CTkButton(
            actions_frame,
            text="⋮",
            command=self._show_options_menu,
            width=35,
            height=35,
            fg_color="transparent",
            hover_color=("#538ee6bc", "#2542e7"),
            font=ctk.CTkFont(size=16)
        )
        options_button.pack(side="right", padx=(5, 0))
        
    def _create_messages_area(self):
        """Create modern messages area with custom styling."""
        # Messages container with WhatsApp-like background
        self.messages_frame = ctk.CTkScrollableFrame(
            self.window,
            fg_color=("#e5ddd5", "#0a1014"),  # WhatsApp chat background
            scrollbar_button_color=("#538ee6bc", "#2542e7"),
            scrollbar_button_hover_color=("#2542e7", "#538ee6bc")
        )
        self.messages_frame.pack(fill="both", expand=True, padx=0, pady=0)
        
        # Configure scrollbar
        self.messages_frame._scrollbar.configure(width=8)
        
    def _create_modern_input_area(self):
        """Create modern input area with emoji and media buttons."""
        # Input container - elevated design
        input_container = ctk.CTkFrame(
            self.window,
            height=70,
            fg_color=("#f0f2f5", "#1e2428"),
            corner_radius=0
        )
        input_container.pack(fill="x", padx=0, pady=0)
        input_container.pack_propagate(False)
        
        # Main input frame
        input_frame = ctk.CTkFrame(
            input_container,
            fg_color=("white", "#2a2f32"),
            corner_radius=25,
            height=45
        )
        input_frame.pack(fill="x", padx=12, pady=12)
        input_frame.pack_propagate(False)
        
        # Emoji button
        emoji_button = ctk.CTkButton(
            input_frame,
            text="😊",
            command=self._show_emoji_picker,
            width=35,
            height=35,
            fg_color="transparent",
            hover_color=("#f5f5f5", "#404040"),
            text_color=("#8696a0", "#8696a0"),
            font=ctk.CTkFont(size=16)
        )
        emoji_button.pack(side="left", padx=(10, 5), pady=5)
        
        # Message input - modern styling
        self.message_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="Type a message...",
            font=ctk.CTkFont(size=14),
            fg_color="transparent",
            border_width=0,
            text_color=("#3b4a54", "white"),
            placeholder_text_color=("#8696a0", "#8696a0")
        )
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(5, 5), pady=5)
        
        # Send button - modern circular design
        self.send_button = ctk.CTkButton(
            input_frame,
            text="➤",
            command=self._send_message,
            width=35,
            height=35,
            fg_color=("#538ee6bc", "#2542e7"),
            hover_color=("#2542e7", "#538ee6bc"),
            corner_radius=17,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.send_button.pack(side="right", padx=(5, 10), pady=5)
        
        # Bind events
        self.message_entry.bind('<Return>', lambda e: self._send_message())
        self.message_entry.bind('<KeyPress>', self._on_typing)
        self.message_entry.bind('<FocusIn>', lambda e: self._update_send_button())
        self.message_entry.bind('<KeyRelease>', lambda e: self._update_send_button())
        
    def _show_emoji_picker(self):
        """Show emoji picker (placeholder - could be enhanced with actual emoji picker)."""
        # Simple emoji options for now
        emojis = ["😊", "😂", "❤️", "👍", "😢", "😮", "😡", "🎉", "🔥", "✨"]
        
        # Create a simple popup with common emojis
        emoji_window = ctk.CTkToplevel(self.window)
        emoji_window.title("Emojis")
        emoji_window.geometry("300x100")
        emoji_window.transient(self.window)
        emoji_window.grab_set()
        
        # Center the popup
        emoji_window.geometry("+%d+%d" % (
            self.window.winfo_rootx() + 50,
            self.window.winfo_rooty() + 50
        ))
        
        frame = ctk.CTkFrame(emoji_window)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        for i, emoji in enumerate(emojis):
            row = i // 5
            col = i % 5
            
            btn = ctk.CTkButton(
                frame,
                text=emoji,
                width=40,
                height=40,
                font=ctk.CTkFont(size=16),
                command=lambda e=emoji: self._insert_emoji(e, emoji_window)
            )
            btn.grid(row=row, column=col, padx=2, pady=2)
            
    def _insert_emoji(self, emoji, window):
        """Insert selected emoji into message entry."""
        current_text = self.message_entry.get()
        self.message_entry.delete(0, "end")
        self.message_entry.insert(0, current_text + emoji)
        window.destroy()
        self.message_entry.focus()
        
    def _show_options_menu(self):
        """Show options menu (placeholder for future features)."""
        # Could include options like: Clear chat, Block user, Report, etc.
        options_window = ctk.CTkToplevel(self.window)
        options_window.title("Chat Options")
        options_window.geometry("200x150")
        options_window.transient(self.window)
        options_window.grab_set()
        
        # Center the popup
        options_window.geometry("+%d+%d" % (
            self.window.winfo_rootx() + 100,
            self.window.winfo_rooty() + 50
        ))
        
        frame = ctk.CTkFrame(options_window)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Clear chat option
        clear_btn = ctk.CTkButton(
            frame,
            text="🗑️ Clear Chat",
            command=lambda: self._clear_chat(options_window),
            width=180
        )
        clear_btn.pack(pady=5)
        
        # Close option
        close_btn = ctk.CTkButton(
            frame,
            text="❌ Close Chat",
            command=lambda: self._close_chat(options_window),
            width=180
        )
        close_btn.pack(pady=5)
        
    def _clear_chat(self, window):
        """Clear all messages from chat."""
        for widget in self.messages_frame.winfo_children():
            widget.destroy()
        self.messages = []
        self._add_system_message("🗑️ Chat cleared")
        window.destroy()
        
    def _close_chat(self, window):
        """Close the chat window."""
        window.destroy()
        self._on_close()
        
    def _on_typing(self, event):
        """Handle typing events for better UX."""
        # Could be used to show typing indicators in the future
        self._update_send_button()
        
    def _update_send_button(self):
        """Update send button appearance based on message content."""
        message_text = self.message_entry.get().strip()
        if message_text:
            self.send_button.configure(
                fg_color=("#538ee6bc", "#2542e7"),
                text="➤"
            )
        else:
            self.send_button.configure(
                fg_color=("#8696a0", "#404040"),
                text="➤"
            )
            
    def destroy(self):
        """Destroy the chat window."""
        self.window.destroy()


class GUIError(Exception):
    """Custom exception for GUI operations."""
    pass