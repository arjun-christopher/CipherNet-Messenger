"""
GUI Manager for CipherNet Messenger - Map-Based Interface
Handles the graphical user interface with map-based user discovery and single chat sessions.

Author: Arjun Christopher
"""

import tkinter as tk
from tkinter import messagebox, filedialog
import customtkinter as ctk
from typing import Dict, Any, List, Optional
import threading
from datetime import datetime
from pathlib import Path
import random
import math

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
        
        # User data
        self.current_user = None
        self.online_users = []
        self.public_key_pem = None
        self.private_key_pem = None
        self.processed_requests = set()
        
        # Single chat session management
        self.active_chat_session = None  # Current active chat session
        self.active_sessions = {}  # Track active sessions to prevent duplicates
        self.current_view = "map"  # "map" or "chat"
        
        # UI Components
        self.content_area = None
        self.user_map_canvas = None
        self.messages_frame = None
        self.message_entry = None
        self.chat_status_label = None
        
        # Cleanup management
        self._cleanup_done_flag = [False]  # Use list for mutable reference
        self._is_shutting_down = False  # Flag to prevent callbacks during shutdown
        
        # Periodic task management
        self._discovery_task_id = None
        self._response_monitoring_task_id = None
    
    def start_application(self):
        """Start the GUI application."""
        self.root = ctk.CTk()
        self.root.title(self.config.get('app.name', 'CipherNet Messenger'))
        self.root.geometry(f"{self.config.get('ui.window_width', 1200)}x{self.config.get('ui.window_height', 800)}")
        
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
            text="Secure P2P Communication with Map-Based Discovery",
            font=ctk.CTkFont(size=16)
        )
        subtitle_label.pack(pady=(0, 40))
        
        # Login form
        form_frame = ctk.CTkFrame(self.current_frame)
        form_frame.pack(pady=20, padx=100, fill="x")
        
        # Email
        ctk.CTkLabel(form_frame, text="Email:", font=ctk.CTkFont(size=12, weight="bold")).pack(pady=(20, 5), anchor="w", padx=20)
        self.email_entry = ctk.CTkEntry(form_frame, placeholder_text="Enter your email", height=35)
        self.email_entry.pack(pady=(0, 10), padx=20, fill="x")
        
        # Password
        ctk.CTkLabel(form_frame, text="Password:", font=ctk.CTkFont(size=12, weight="bold")).pack(pady=(10, 5), anchor="w", padx=20)
        self.password_entry = ctk.CTkEntry(form_frame, placeholder_text="Enter your password", show="*", height=35)
        self.password_entry.pack(pady=(0, 20), padx=20, fill="x")
        
        # Buttons
        button_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        button_frame.pack(pady=(0, 20), fill="x")
        
        login_button = ctk.CTkButton(
            button_frame,
            text="Login",
            command=self._handle_login,
            width=120,
            height=35,
            fg_color=("#1e88e5", "#1565c0")
        )
        login_button.pack(side="left", padx=(20, 10))
        
        register_button = ctk.CTkButton(
            button_frame,
            text="Register",
            command=self._handle_register,
            width=120,
            height=35,
            fg_color=("#28a745", "#1e7e34")
        )
        register_button.pack(side="right", padx=(10, 20))
        
        # Status label
        self.status_label = ctk.CTkLabel(self.current_frame, text="", font=ctk.CTkFont(size=12))
        self.status_label.pack(pady=(10, 20))
        
        # Bind Enter key
        self.root.bind('<Return>', lambda e: self._handle_login())
        
        # Focus email entry
        self.email_entry.focus()
    
    def show_main_screen(self):
        """Display the main map-based interface."""
        self._clear_current_frame()
        
        # Initialize session management
        self.active_chat_session = None
        self.active_sessions = {}
        
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
        self.current_frame.pack(fill="both", expand=True)
        
        # Create interface
        self._create_interface()
        
        # Start listening for requests
        self.firebase_manager.listen_for_requests(self._handle_chat_request)
        
        # Setup message handlers
        self.network_manager.register_message_handler('text_message', self._handle_text_message)
        self.network_manager.register_message_handler('session_key', self._handle_session_key)
        self.network_manager.register_message_handler('chat_terminated', self._handle_chat_termination)
        self.network_manager.register_connection_closed_callback(self._handle_network_disconnection)
        
        # Start user discovery
        self._start_user_discovery()
        
        # Start monitoring for chat request responses
        self._start_response_monitoring()
        
        # Start monitoring for chat request responses
        self._start_response_monitoring()
    
    def _create_interface(self):
        """Create the main interface."""
        # Header bar
        self._create_header_bar()
        
        # Content area
        self.content_area = ctk.CTkFrame(self.current_frame)
        self.content_area.pack(fill="both", expand=True)
        
        # Show map by default
        self._show_user_map()
    
    def _create_header_bar(self):
        """Create the top header bar."""
        header_frame = ctk.CTkFrame(
            self.current_frame,
            height=60,
            fg_color=("#1e88e5", "#1565c0")
        )
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)
        
        # App title
        title_label = ctk.CTkLabel(
            header_frame,
            text="CipherNet Map",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="white"
        )
        title_label.pack(side="left", padx=20, pady=15)
        
        # Right side controls
        controls_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        controls_frame.pack(side="right", padx=20, pady=10)
        
        # Logout button
        logout_button = ctk.CTkButton(
            controls_frame,
            text="Logout",
            command=self._handle_logout,
            width=80,
            height=35,
            fg_color=("#dc3545", "#b02a37"),
            hover_color=("#c82333", "#9a1e2a")
        )
        logout_button.pack(side="right")
        
        # User info
        user_info = f"{self.current_user['email'] if self.current_user else 'Unknown'}"
        user_label = ctk.CTkLabel(
            controls_frame,
            text=user_info,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="white"
        )
        user_label.pack(side="right", padx=(0, 20))
        
        # Chat status
        self.chat_status_label = ctk.CTkLabel(
            controls_frame,
            text="No active chat",
            font=ctk.CTkFont(size=12),
            text_color=("#e3f2fd", "#a0a0a0")
        )
        self.chat_status_label.pack(side="right", padx=(0, 20))
    
    def _show_user_map(self):
        """Display the user map interface."""
        # Clear content area
        for widget in self.content_area.winfo_children():
            widget.destroy()
        
        self.current_view = "map"
        
        # Map container
        map_container = ctk.CTkFrame(self.content_area, fg_color=("#f0f8ff", "#1a1a1a"))
        map_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Map header
        self._create_map_header(map_container)
        
        # Map canvas
        self._create_map_canvas(map_container)
        
        # Load users
        self._load_users_on_map()
    
    def _create_map_header(self, parent):
        """Create map header with controls."""
        control_frame = ctk.CTkFrame(parent, height=60, fg_color="transparent")
        control_frame.pack(fill="x", padx=10, pady=(10, 0))
        control_frame.pack_propagate(False)
        
        # Title
        map_title = ctk.CTkLabel(
            control_frame,
            text="Online Users - Click on a user to start chatting",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        map_title.pack(side="left", pady=15)
        
        # Controls on right
        controls_right = ctk.CTkFrame(control_frame, fg_color="transparent")
        controls_right.pack(side="right", pady=10)
        
        # User count
        self.user_count_label = ctk.CTkLabel(
            controls_right,
            text="Users online: 0",
            font=ctk.CTkFont(size=12)
        )
        self.user_count_label.pack(side="right", padx=(0, 20))
        
        # Refresh button
        refresh_btn = ctk.CTkButton(
            controls_right,
            text="Refresh",
            command=self._refresh_user_map,
            width=100,
            height=35,
            fg_color=("#1e88e5", "#1565c0")
        )
        refresh_btn.pack(side="right")
    
    def _create_map_canvas(self, parent):
        """Create the map canvas."""
        canvas_frame = ctk.CTkFrame(parent)
        canvas_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create canvas
        self.user_map_canvas = tk.Canvas(
            canvas_frame,
            bg="#f0f8ff" if ctk.get_appearance_mode() == "Light" else "#1a1a1a",
            highlightthickness=0
        )
        self.user_map_canvas.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Bind events
        self.user_map_canvas.bind("<Configure>", self._on_canvas_resize)
    
    def _on_canvas_resize(self, event):
        """Handle canvas resize."""
        if not self._is_shutting_down:
            self.root.after(100, self._load_users_on_map)
    
    def _load_users_on_map(self):
        """Load and display users on the map."""
        if not self.user_map_canvas:
            return
        
        # Check if canvas still exists and is valid
        try:
            if not self.user_map_canvas.winfo_exists():
                return
        except tk.TclError:
            # Canvas has been destroyed
            self.user_map_canvas = None
            return
        
        # Clear canvas
        try:
            self.user_map_canvas.delete("all")
        except tk.TclError:
            # Canvas has been destroyed during operation
            self.user_map_canvas = None
            return
        
        # Get canvas dimensions
        try:
            if not self.user_map_canvas:
                # Canvas is None, cannot proceed
                return
            self.user_map_canvas.update()
            canvas_width = self.user_map_canvas.winfo_width()
            canvas_height = self.user_map_canvas.winfo_height()
        except (tk.TclError, AttributeError):
            # Canvas has been destroyed during operation or is None
            self.user_map_canvas = None
            return
        
        if canvas_width <= 1 or canvas_height <= 1:
            if not self._is_shutting_down:
                self.root.after(100, self._load_users_on_map)
            return
        
        # Get online users
        try:
            online_users = self.firebase_manager.get_online_users()
        except:
            online_users = []
        
        # Update count
        if hasattr(self, 'user_count_label'):
            self.user_count_label.configure(text=f"Users online: {len(online_users)}")
        
        if not online_users:
            # Show "no users" message
            self.user_map_canvas.create_text(
                canvas_width // 2, canvas_height // 2,
                text="No other users online! Invite friends to join CipherNet!",
                font=("Arial", 16),
                fill="#666" if ctk.get_appearance_mode() == "Light" else "#aaa",
                justify="center"
            )
            return
        
        # Position users on map
        self._position_users_on_map(online_users, canvas_width, canvas_height)
    
    def _position_users_on_map(self, users, canvas_width, canvas_height):
        """Position users randomly on the map canvas."""
        random.seed(42)  # Consistent positioning across refreshes
        
        margin = 80
        min_distance = 120
        user_positions = []
        
        for user in users:
            # Try to find a good position
            attempts = 0
            while attempts < 100:
                x = random.randint(margin, max(margin + 50, canvas_width - margin))
                y = random.randint(margin, max(margin + 50, canvas_height - margin))
                
                # Check distance from other users
                too_close = False
                for px, py in user_positions:
                    distance = math.sqrt((x - px) ** 2 + (y - py) ** 2)
                    if distance < min_distance:
                        too_close = True
                        break
                
                if not too_close:
                    break
                attempts += 1
            
            user_positions.append((x, y))
            self._draw_user_on_map(x, y, user)
    
    def _draw_user_on_map(self, x, y, user):
        """Draw a user icon on the map."""
        email = user.get('email', 'Unknown')
        uid = user.get('uid', '')
        
        # Check if user is busy
        is_busy = self._user_has_active_session(uid)
        
        # Colors
        if is_busy:
            circle_color = "#ff6b6b"  # Red for busy
            text_color = "white"
            status_color = "#ff6b6b"
            status_text = "Busy"
        else:
            circle_color = "#51cf66"  # Green for available
            text_color = "white"
            status_color = "#51cf66"
            status_text = "Available"
        
        # Draw user circle
        circle_id = self.user_map_canvas.create_oval(
            x - 30, y - 30, x + 30, y + 30,
            fill=circle_color,
            outline="white",
            width=3
        )
        
        # User initial
        initial = email[0].upper() if email else "?"
        text_id = self.user_map_canvas.create_text(
            x, y,
            text=initial,
            font=("Arial", 18, "bold"),
            fill=text_color
        )
        
        # Email below circle
        display_email = email.split('@')[0] if '@' in email else email
        if len(display_email) > 15:
            display_email = display_email[:15] + "..."
        
        email_id = self.user_map_canvas.create_text(
            x, y + 50,
            text=display_email,
            font=("Arial", 11, "bold"),
            fill="#333" if ctk.get_appearance_mode() == "Light" else "#ddd"
        )
        
        # Status indicator
        status_id = self.user_map_canvas.create_text(
            x, y + 68,
            text=f"{status_text}",
            font=("Arial", 9),
            fill=status_color
        )
        
        # Bind click events (only for available users)
        if not is_busy:
            for item_id in [circle_id, text_id, email_id]:
                self.user_map_canvas.tag_bind(item_id, "<Button-1>", lambda e, u=user: self._on_user_click(u))
                self.user_map_canvas.tag_bind(item_id, "<Enter>", lambda e, ids=[circle_id]: self._on_user_hover(ids, True))
                self.user_map_canvas.tag_bind(item_id, "<Leave>", lambda e, ids=[circle_id]: self._on_user_hover(ids, False))
    
    def _on_user_hover(self, item_ids, entering):
        """Handle user hover effect."""
        if not self.user_map_canvas:
            return
        
        try:
            if not self.user_map_canvas.winfo_exists():
                return
        except tk.TclError:
            return
        
        try:
            if entering:
                for item_id in item_ids:
                    self.user_map_canvas.itemconfig(item_id, width=4)
            else:
                for item_id in item_ids:
                    self.user_map_canvas.itemconfig(item_id, width=3)
        except tk.TclError:
            # Canvas or items have been destroyed
            pass
    
    def _user_has_active_session(self, uid):
        """Check if user has an active session."""
        current_uid = self.current_user.get('uid', '') if self.current_user else ''
        
        # Check session combinations
        session_key1 = f"{current_uid}-{uid}"
        session_key2 = f"{uid}-{current_uid}"
        
        return session_key1 in self.active_sessions or session_key2 in self.active_sessions
    
    def _on_user_click(self, user):
        """Handle user click on map."""
        # Check if we already have an active session
        if self.active_chat_session:
            messagebox.showinfo(
                "Chat Active",
                f"You already have an active chat with {self.active_chat_session.get('email', 'someone')}. End the current chat to start a new one."
            )
            return
        
        # Check if clicked user is busy
        if self._user_has_active_session(user.get('uid', '')):
            messagebox.showinfo(
                "User Busy",
                f"{user.get('email', 'This user')} is currently in another chat session."
            )
            return
        
        # Confirm chat request
        result = messagebox.askyesno(
            "Start Chat",
            f"Send a chat request to {user.get('email', 'this user')}? They will be notified and can accept or decline."
        )
        
        if result:
            self._send_chat_request(user)
    
    def _send_chat_request(self, user):
        """Send a chat request to a user."""
        try:
            success = self.firebase_manager.send_chat_request(
                user['uid'],
                "Hello! Let's chat securely using CipherNet Messenger."
            )
            
            if success:
                messagebox.showinfo("Request Sent", f"Chat request sent to {user['email']}!")
                
                # Mark session as pending
                current_uid = self.current_user.get('uid', '') if self.current_user else ''
                session_key = f"{current_uid}-{user['uid']}"
                self.active_sessions[session_key] = True
                
                # Refresh map to show updated status
                self._load_users_on_map()
            else:
                messagebox.showerror("Error", "Failed to send chat request. Please try again.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send chat request: {str(e)}")
    
    def _start_chat_session(self, peer_user):
        """Start a secure chat session with enhanced RSA-2048 session initiation."""
        if self.active_chat_session:
            return
        
        try:
            print(f"🔐 Starting secure chat session with {peer_user.get('email', 'Unknown')}")
            
            # Update header to show connecting status
            self.chat_status_label.configure(
                text=f"🔒 Establishing secure session with {peer_user.get('email', 'Unknown')}...",
                text_color=("#ff9800", "#ff9800")
            )
            
            # Set active session
            self.active_chat_session = peer_user
            
            # Update session tracking
            current_uid = self.current_user.get('uid', '') if self.current_user else ''
            peer_uid = peer_user.get('uid', '')
            session_key = f"{current_uid}-{peer_uid}"
            self.active_sessions[session_key] = True
            
            # Create chat ID for Firebase monitoring
            chat_id = f"chat_{min(current_uid, peer_uid)}_{max(current_uid, peer_uid)}"
            self.active_chat_session['chat_id'] = chat_id
            
            # Set up chat monitoring for peer status changes
            self.firebase_manager.listen_for_chat_updates(chat_id, self._handle_chat_updates)
            
            # Update participant status to online
            self.firebase_manager.update_chat_participant_status(chat_id, 'online')
            
            # Show chat interface immediately (connection will be established in background)
            self._show_chat_interface()
            
            # Start secure session establishment process
            self._establish_secure_session(peer_user)
            
        except Exception as e:
            print(f"❌ Failed to start chat session: {e}")
            messagebox.showerror("Error", "Failed to start secure chat session")
            self._end_chat_session()
    
    def _establish_secure_session(self, peer_user):
        """
        Establish secure session using RSA-2048 key exchange with PKCS#1 OAEP.
        
        Args:
            peer_user: Peer user information
        """
        try:
            peer_uid = peer_user.get('uid', '')
            peer_email = peer_user.get('email', 'Unknown')
            peer_public_key = peer_user.get('public_key', '')
            
            if not peer_public_key:
                print(f"❌ No public key available for {peer_email}")
                self._show_session_error("No public key available for secure communication")
                return
            
            # Validate and parse peer's public key
            try:
                peer_public_key_pem = peer_public_key.encode('utf-8')
                
                # Validate peer's RSA-2048 public key
                if not self.crypto_manager.validate_peer_public_key(peer_public_key_pem):
                    print(f"❌ Invalid public key from {peer_email}")
                    self._show_session_error("Invalid public key - session cannot be established")
                    return
                
                print(f"✅ Public key validated for {peer_email}")
                
                # Get connection info from Firebase
                chat_id = self.active_chat_session.get('chat_id', '')
                chat_info = self.firebase_manager.get_chat_connection_info(chat_id)
                
                if not chat_info:
                    print(f"❌ No connection info available for chat {chat_id}")
                    self._show_session_error("Connection information not available")
                    return
                
                # Extract peer's IP and port
                participants = chat_info.get('participants', {})
                peer_info = participants.get(peer_uid, {})
                peer_ip = peer_info.get('ip', '')
                peer_port = peer_info.get('port', 8888)
                
                if not peer_ip:
                    print(f"❌ No IP address available for {peer_email}")
                    self._show_session_error("Peer IP address not available")
                    return
                
                print(f"🌐 Connecting to {peer_email} at {peer_ip}:{peer_port}")
                
                # Connect to peer
                if not self.network_manager.connect_to_peer(peer_ip, peer_port, peer_uid):
                    print(f"❌ Failed to connect to {peer_email}")
                    self._show_session_error("Failed to establish network connection")
                    return
                
                # Register session establishment callback
                self.network_manager.register_session_establishment_callback(
                    peer_uid, self._on_session_established
                )
                
                # Initiate secure session with RSA-2048 key exchange
                if self.network_manager.initiate_secure_session(peer_uid, peer_public_key_pem, 
                                                               self._on_session_established):
                    print(f"🔑 RSA-2048 key exchange initiated with {peer_email}")
                    
                    # Update status to show key exchange in progress
                    self.chat_status_label.configure(
                        text=f"🔑 Exchanging keys with {peer_email}...",
                        text_color=("#ff9800", "#ff9800")
                    )
                else:
                    print(f"❌ Failed to initiate key exchange with {peer_email}")
                    self._show_session_error("Failed to initiate secure key exchange")
                    
            except Exception as e:
                print(f"❌ Error processing public key for {peer_email}: {e}")
                self._show_session_error(f"Public key processing error: {str(e)}")
                
        except Exception as e:
            print(f"❌ Error establishing secure session: {e}")
            self._show_session_error(f"Session establishment error: {str(e)}")
    
    def _on_session_established(self, peer_id: str, success: bool, message: str):
        """
        Callback for when secure session establishment completes.
        
        Args:
            peer_id: Peer identifier
            success: Whether session establishment succeeded
            message: Status message
        """
        try:
            if success:
                print(f"✅ Secure session established with peer {peer_id}")
                
                # Update UI to show secure session is active
                if self.active_chat_session:
                    peer_email = self.active_chat_session.get('email', 'Unknown')
                    self.chat_status_label.configure(
                        text=f"🔐 Secure session active with {peer_email}",
                        text_color=("#51cf66", "#51cf66")
                    )
                    
                    # Add system message about encryption
                    self._add_system_message(
                        "🔐 End-to-end encryption enabled with RSA-2048 + Blowfish-256"
                    )
                    
                    # Update security status
                    if hasattr(self, 'security_status_label') and self.security_status_label:
                        self.security_status_label.configure(
                            text="🔐 RSA-2048 + Blowfish-256 encryption active",
                            text_color=("#51cf66", "#51cf66")
                        )
                    
                    # Enable message input controls
                    if hasattr(self, 'message_entry') and self.message_entry:
                        self.message_entry.configure(state="normal")
                        self.message_entry.configure(
                            placeholder_text="Type your secure message..."
                        )
                        self.message_entry.focus()
                    
                    if hasattr(self, 'send_btn') and self.send_btn:
                        self.send_btn.configure(state="normal")
                    
                    if hasattr(self, 'file_btn') and self.file_btn:
                        self.file_btn.configure(state="normal")
                
            else:
                print(f"❌ Failed to establish secure session with peer {peer_id}: {message}")
                self._show_session_error(f"Session establishment failed: {message}")
                
        except Exception as e:
            print(f"❌ Error in session establishment callback: {e}")
    
    def _show_session_error(self, error_message: str):
        """
        Show session establishment error and handle gracefully.
        
        Args:
            error_message: Error message to display
        """
        try:
            # Update status to show error
            self.chat_status_label.configure(
                text=f"❌ {error_message}",
                text_color=("#f44336", "#f44336")
            )
            
            # Add system message about the error
            self._add_system_message(f"❌ {error_message}")
            
            # Update security status
            if hasattr(self, 'security_status_label') and self.security_status_label:
                self.security_status_label.configure(
                    text="❌ Encryption failed - session not secure",
                    text_color=("#f44336", "#f44336")
                )
            
            # Disable message input controls
            if hasattr(self, 'message_entry') and self.message_entry:
                self.message_entry.configure(state="disabled")
                self.message_entry.configure(
                    placeholder_text="Session establishment failed - cannot send messages"
                )
            
            if hasattr(self, 'send_btn') and self.send_btn:
                self.send_btn.configure(state="disabled")
            
            if hasattr(self, 'file_btn') and self.file_btn:
                self.file_btn.configure(state="disabled")
            
            # Show error dialog after a delay
            self.root.after(2000, lambda: messagebox.showerror(
                "Session Error", 
                f"Failed to establish secure session:\n{error_message}\n\nPlease try again."
            ))
            
        except Exception as e:
            print(f"Error displaying session error: {e}")
    
    def _show_chat_interface(self):
        """Display the chat interface."""
        if not self.active_chat_session:
            return
        
        # Clear content area
        for widget in self.content_area.winfo_children():
            widget.destroy()
        
        self.current_view = "chat"
        
        # Chat container
        chat_container = ctk.CTkFrame(self.content_area)
        chat_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Chat header
        self._create_chat_header(chat_container)
        
        # Messages area
        self._create_messages_area(chat_container)
        
        # Input area
        self._create_input_area(chat_container)
    
    def _add_system_message(self, message: str):
        """
        Add system message to chat (for security notifications).
        
        Args:
            message: System message to display
        """
        try:
            if hasattr(self, 'messages_frame') and self.messages_frame:
                from datetime import datetime
                
                # Create system message frame
                msg_frame = ctk.CTkFrame(
                    self.messages_frame,
                    fg_color=("#e3f2fd", "#263238"),
                    corner_radius=10
                )
                msg_frame.pack(fill="x", padx=20, pady=5)
                
                # System message content
                msg_content = ctk.CTkFrame(msg_frame, fg_color="transparent")
                msg_content.pack(fill="x", padx=10, pady=8)
                
                # Message text
                msg_label = ctk.CTkLabel(
                    msg_content,
                    text=message,
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=("#1565c0", "#81c784"),
                    anchor="w",
                    justify="left"
                )
                msg_label.pack(fill="x")
                
                # Timestamp
                timestamp = datetime.now().strftime("%H:%M:%S")
                time_label = ctk.CTkLabel(
                    msg_content,
                    text=timestamp,
                    font=ctk.CTkFont(size=10),
                    text_color=("#757575", "#757575"),
                    anchor="w"
                )
                time_label.pack(fill="x")
                
                # Scroll to bottom
                self.messages_frame.update()
                if hasattr(self, 'messages_canvas'):
                    self.messages_canvas.configure(scrollregion=self.messages_canvas.bbox("all"))
                    self.messages_canvas.yview_moveto(1.0)
        
        except Exception as e:
            print(f"Error adding system message: {e}")
    
    def _create_chat_header(self, parent):
        """Create chat header."""
        peer_user = self.active_chat_session
        
        header_frame = ctk.CTkFrame(
            parent,
            height=80,
            fg_color=("#1e88e5", "#1565c0")
        )
        header_frame.pack(fill="x", pady=(0, 10))
        header_frame.pack_propagate(False)
        
        # Left side - user info
        info_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        info_frame.pack(side="left", fill="y", padx=20, pady=10)
        
        # Avatar
        avatar_frame = ctk.CTkFrame(
            info_frame,
            width=60,
            height=60,
            fg_color=("#e3f2fd", "#1e88e5"),
            corner_radius=30
        )
        avatar_frame.pack(side="left")
        avatar_frame.pack_propagate(False)
        
        avatar_label = ctk.CTkLabel(
            avatar_frame,
            text=peer_user.get('email', 'U')[0].upper(),
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=("#1565c0", "white")
        )
        avatar_label.pack(expand=True)
        
        # User details
        details_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
        details_frame.pack(side="left", fill="y", padx=(15, 0))
        
        name_label = ctk.CTkLabel(
            details_frame,
            text=peer_user.get('email', 'Unknown').split('@')[0].title(),
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="white",
            anchor="w"
        )
        name_label.pack(anchor="w", pady=(8, 0))
        
        status_label = ctk.CTkLabel(
            details_frame,
            text="End-to-end encrypted",
            font=ctk.CTkFont(size=12),
            text_color=("#e3f2fd", "#a0a0a0"),
            anchor="w"
        )
        status_label.pack(anchor="w", pady=(0, 8))
        
        # Right side - controls
        controls_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        controls_frame.pack(side="right", padx=20, pady=15)
        
        # End chat button
        end_btn = ctk.CTkButton(
            controls_frame,
            text="End Chat",
            command=self._end_chat_session,
            width=100,
            height=35,
            fg_color=("#dc3545", "#b02a37"),
            hover_color=("#c82333", "#9a1e2a")
        )
        end_btn.pack(side="right")
    
    def _create_messages_area(self, parent):
        """Create messages display area."""
        self.messages_frame = ctk.CTkScrollableFrame(
            parent,
            fg_color=("#ffffff", "#2d2d2d")
        )
        self.messages_frame.pack(fill="both", expand=True, pady=(0, 10))
        
        # Welcome message
        welcome_frame = ctk.CTkFrame(self.messages_frame, fg_color="transparent")
        welcome_frame.pack(pady=30)
        
        welcome_label = ctk.CTkLabel(
            welcome_frame,
            text="Secure Chat Session Started",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=("#1e88e5", "#1e88e5")
        )
        welcome_label.pack()
        
        info_label = ctk.CTkLabel(
            welcome_frame,
            text="All messages are end-to-end encrypted\\nOnly you and your chat partner can read them",
            font=ctk.CTkFont(size=12),
            text_color=("#666", "#aaa"),
            justify="center"
        )
        info_label.pack(pady=(5, 0))
    
    def _create_input_area(self, parent):
        """Create message input area with security status."""
        input_frame = ctk.CTkFrame(parent, height=90)
        input_frame.pack(fill="x")
        input_frame.pack_propagate(False)
        
        # Security status frame
        security_frame = ctk.CTkFrame(input_frame, height=20, fg_color="transparent")
        security_frame.pack(fill="x", padx=15, pady=(5, 0))
        security_frame.pack_propagate(False)
        
        # Security status label
        self.security_status_label = ctk.CTkLabel(
            security_frame,
            text="🔐 RSA-2048 encryption establishing...",
            font=ctk.CTkFont(size=10),
            text_color=("#ff9800", "#ff9800"),
            anchor="w"
        )
        self.security_status_label.pack(side="left")
        
        # Input controls frame
        controls_frame = ctk.CTkFrame(input_frame, height=50, fg_color="transparent")
        controls_frame.pack(fill="x", padx=15, pady=(5, 15))
        controls_frame.pack_propagate(False)
        
        # File upload button
        self.file_btn = ctk.CTkButton(
            controls_frame,
            text="File",
            command=self._upload_file,
            width=50,
            height=45,
            fg_color=("#28a745", "#1e7e34"),
            hover_color=("#218838", "#155724"),
            font=ctk.CTkFont(size=12),
            state="disabled"  # Disabled until session established
        )
        self.file_btn.pack(side="left", padx=(0, 5))
        
        # Message entry
        self.message_entry = ctk.CTkEntry(
            controls_frame,
            placeholder_text="Establishing secure session...",
            height=45,
            font=ctk.CTkFont(size=14),
            state="disabled"  # Disabled until session established
        )
        self.message_entry.pack(side="left", fill="both", expand=True, padx=(5, 10))
        
        # Send button
        self.send_btn = ctk.CTkButton(
            controls_frame,
            text="Send",
            command=self._send_message,
            width=60,
            height=45,
            fg_color=("#1e88e5", "#1565c0"),
            font=ctk.CTkFont(size=12),
            state="disabled"  # Disabled until session established
        )
        self.send_btn.pack(side="right")
        
        # Bind Enter key (will be enabled after session establishment)
        self.message_entry.bind('<Return>', lambda e: self._send_message() if self.message_entry.cget("state") == "normal" else None)
    
    def _send_message(self):
        """Send a secure message using established session key."""
        if not self.active_chat_session or not self.message_entry:
            return
        
        message = self.message_entry.get().strip()
        if not message:
            return
        
        try:
            peer_uid = self.active_chat_session.get('uid', '')
            
            # Check if secure session is established
            if not self.network_manager.is_session_established(peer_uid):
                self._add_system_message("❌ Cannot send message: Secure session not established")
                return
            
            # Clear entry
            self.message_entry.delete(0, "end")
            
            # Add to display immediately
            self._add_message_to_chat("You", message, is_own=True)
            
            # Send encrypted message via network manager
            success = self.network_manager.send_message(
                peer_uid, 
                "text_message", 
                {
                    "text": message,
                    "sender": self.current_user.get('email', 'Unknown') if self.current_user else 'Unknown',
                    "encryption": "RSA-2048-OAEP + Blowfish-256-CBC"
                }
            )
            
            if not success:
                # Show error and add system message
                self._add_system_message("❌ Failed to send message - please try again")
                print(f"❌ Failed to send message to {peer_uid}")
            else:
                print(f"✅ Secure message sent to {peer_uid}")
                
        except Exception as e:
            print(f"❌ Error sending message: {e}")
            self._add_system_message(f"❌ Error sending message: {str(e)}")
    
    def _add_message_to_chat(self, sender, message, is_own=False, message_type="text"):
        """Add a message to the chat display."""
        if not self.messages_frame:
            return
        
        # Handle file messages differently
        if message_type == "file" and isinstance(message, dict):
            self._add_file_message_to_chat(sender, message, is_own)
            return
        
        # Message container
        msg_container = ctk.CTkFrame(self.messages_frame, fg_color="transparent")
        msg_container.pack(fill="x", padx=15, pady=(0, 10))
        
        # Timestamp
        timestamp = datetime.now().strftime("%H:%M")
        
        if is_own:
            # Own message (right-aligned, blue)
            time_label = ctk.CTkLabel(
                msg_container,
                text=timestamp,
                font=ctk.CTkFont(size=10),
                text_color=("#666", "#aaa")
            )
            time_label.pack(side="right", anchor="e", padx=(0, 5))
            
            bubble_frame = ctk.CTkFrame(
                msg_container,
                fg_color=("#e3f2fd", "#1e88e5"),
                corner_radius=20
            )
            bubble_frame.pack(side="right", padx=(50, 0))
            
            msg_label = ctk.CTkLabel(
                bubble_frame,
                text=message,
                font=ctk.CTkFont(size=13),
                text_color=("#1565c0", "white"),
                wraplength=400,
                justify="left"
            )
            msg_label.pack(padx=18, pady=12)
        else:
            # Peer message (left-aligned, gray)
            time_label = ctk.CTkLabel(
                msg_container,
                text=timestamp,
                font=ctk.CTkFont(size=10),
                text_color=("#666", "#aaa")
            )
            time_label.pack(side="left", anchor="w", padx=(5, 0))
            
            bubble_frame = ctk.CTkFrame(
                msg_container,
                fg_color=("#f1f3f4", "#404040"),
                corner_radius=20
            )
            bubble_frame.pack(side="left", padx=(0, 50))
            
            msg_label = ctk.CTkLabel(
                bubble_frame,
                text=message,
                font=ctk.CTkFont(size=13),
                text_color=("#333", "#ddd"),
                wraplength=400,
                justify="left"
            )
            msg_label.pack(padx=18, pady=12)
        
        # Auto-scroll to bottom
        self.messages_frame._parent_canvas.update_idletasks()
        self.messages_frame._parent_canvas.yview_moveto(1.0)
    
    def _upload_file(self):
        """Handle file upload."""
        if not self.active_chat_session:
            return
        
        # Open file dialog
        file_path = filedialog.askopenfilename(
            title="Select File to Upload",
            filetypes=[
                ("All Files", "*.*"),
                ("Images", "*.png *.jpg *.jpeg *.gif *.bmp *.tiff"),
                ("Documents", "*.pdf *.doc *.docx *.txt *.rtf"),
                ("Archives", "*.zip *.rar *.7z *.tar *.gz")
            ]
        )
        
        if file_path:
            # Get file info
            file_name = Path(file_path).name
            file_size = Path(file_path).stat().st_size
            
            # Format file size
            if file_size < 1024:
                size_str = f"{file_size} B"
            elif file_size < 1024 * 1024:
                size_str = f"{file_size / 1024:.1f} KB"
            else:
                size_str = f"{file_size / (1024 * 1024):.1f} MB"
            
            # Add file message to chat
            file_info = {
                'type': 'file',
                'name': file_name,
                'size': size_str,
                'path': file_path
            }
            
            self._add_file_message_to_chat("You", file_info, is_own=True)
            
            # TODO: Send file via network manager
            # For now, simulate echo response
            self.root.after(1000, lambda: self._add_message_to_chat(
                self.active_chat_session.get('email', 'Peer'),
                f"File received: {file_name}",
                is_own=False
            ))
    
    def _add_file_message_to_chat(self, sender, file_info, is_own=False):
        """Add a file message to the chat display."""
        if not self.messages_frame:
            return
        
        # Message container
        msg_container = ctk.CTkFrame(self.messages_frame, fg_color="transparent")
        msg_container.pack(fill="x", padx=15, pady=(0, 10))
        
        # Timestamp
        timestamp = datetime.now().strftime("%H:%M")
        
        if is_own:
            # Own file message (right-aligned, blue)
            time_label = ctk.CTkLabel(
                msg_container,
                text=timestamp,
                font=ctk.CTkFont(size=10),
                text_color=("#666", "#aaa")
            )
            time_label.pack(side="right", anchor="e", padx=(0, 5))
            
            bubble_frame = ctk.CTkFrame(
                msg_container,
                fg_color=("#e3f2fd", "#1e88e5"),
                corner_radius=20
            )
            bubble_frame.pack(side="right", padx=(50, 0))
        else:
            # Peer file message (left-aligned, gray)
            time_label = ctk.CTkLabel(
                msg_container,
                text=timestamp,
                font=ctk.CTkFont(size=10),
                text_color=("#666", "#aaa")
            )
            time_label.pack(side="left", anchor="w", padx=(5, 0))
            
            bubble_frame = ctk.CTkFrame(
                msg_container,
                fg_color=("#f1f3f4", "#404040"),
                corner_radius=20
            )
            bubble_frame.pack(side="left", padx=(0, 50))
        
        # File content frame
        file_content_frame = ctk.CTkFrame(bubble_frame, fg_color="transparent")
        file_content_frame.pack(padx=18, pady=12)
        
        # File icon and info
        file_header_frame = ctk.CTkFrame(file_content_frame, fg_color="transparent")
        file_header_frame.pack(fill="x", pady=(0, 8))
        
        # File type indicator
        file_ext = Path(file_info['name']).suffix.lower()
        if file_ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff']:
            file_type = "Image"
            type_color = "#ff6b6b"
        elif file_ext in ['.pdf', '.doc', '.docx', '.txt', '.rtf']:
            file_type = "Document"
            type_color = "#4ecdc4"
        elif file_ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
            file_type = "Archive"
            type_color = "#45b7d1"
        else:
            file_type = "File"
            type_color = "#96ceb4"
        
        type_label = ctk.CTkLabel(
            file_header_frame,
            text=file_type,
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=type_color
        )
        type_label.pack(side="left")
        
        # File name
        name_label = ctk.CTkLabel(
            file_content_frame,
            text=file_info['name'],
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#1565c0", "white") if is_own else ("#333", "#ddd"),
            wraplength=300,
            justify="left"
        )
        name_label.pack(anchor="w")
        
        # File size
        size_label = ctk.CTkLabel(
            file_content_frame,
            text=f"Size: {file_info['size']}",
            font=ctk.CTkFont(size=10),
            text_color=("#1565c0", "#ccc") if is_own else ("#666", "#aaa")
        )
        size_label.pack(anchor="w", pady=(2, 0))
        
        # Open file button (only for own files)
        if is_own and 'path' in file_info:
            open_btn = ctk.CTkButton(
                file_content_frame,
                text="Open File",
                command=lambda: self._open_file(file_info['path']),
                width=80,
                height=25,
                fg_color=("#28a745", "#1e7e34"),
                hover_color=("#218838", "#155724"),
                font=ctk.CTkFont(size=10)
            )
            open_btn.pack(anchor="w", pady=(8, 0))
        
        # Auto-scroll to bottom
        self.messages_frame._parent_canvas.update_idletasks()
        self.messages_frame._parent_canvas.yview_moveto(1.0)
    
    def _open_file(self, file_path):
        """Open uploaded file in default application."""
        try:
            import os
            import platform
            
            if platform.system() == 'Windows':
                os.startfile(file_path)
            elif platform.system() == 'Darwin':  # macOS
                os.system(f'open "{file_path}"')
            else:  # Linux
                os.system(f'xdg-open "{file_path}"')
        except Exception as e:
            messagebox.showerror("Error", f"Could not open file: {str(e)}")
    
    def _end_chat_session(self, show_confirmation=True):
        """End the current chat session."""
        if not self.active_chat_session:
            return
        
        peer_email = self.active_chat_session.get('email', 'this user')
        
        # Show confirmation dialog only if requested
        if show_confirmation:
            result = messagebox.askyesno(
                "End Chat",
                f"End chat session with {peer_email}?"
            )
            if not result:
                return
        
        # Get chat and user info before clearing session
        current_uid = self.current_user.get('uid', '') if self.current_user else ''
        peer_uid = self.active_chat_session.get('uid', '')
        chat_id = self.active_chat_session.get('chat_id', '')
        
        # Initialize network message status
        network_message_sent = False
        
        # Send termination message via network if connected (try network first)
        try:
            if hasattr(self, 'network_manager') and self.network_manager:
                termination_content = {
                    'sender': current_uid,
                    'reason': 'user_initiated'
                }
                print(f"📡 Sending network termination message to {peer_uid}")
                # Send via network manager to connected peer
                network_message_sent = self.network_manager.send_message(peer_uid, 'chat_terminated', termination_content)
                if network_message_sent:
                    print(f"✅ Network termination message sent to {peer_uid}")
                else:
                    print(f"❌ Network termination message failed - peer not connected. Firebase backup will handle this.")
        except Exception as e:
            print(f"❌ Failed to send network termination message: {e}. Firebase backup will handle this.")
        
        # Notify peer about chat termination via Firebase (backup mechanism)
        if chat_id:
            print(f"🔄 Terminating chat {chat_id} by user {current_uid}")
            # Update current user's status to 'terminated' and set chat as terminated
            participant_update_success = self.firebase_manager.update_chat_participant_status(chat_id, 'terminated')
            chat_terminate_success = self.firebase_manager.set_chat_terminated(chat_id, current_uid)
            print(f"📊 Firebase updates - Participant: {participant_update_success}, Chat: {chat_terminate_success}")
            
            # Clean up related chat requests immediately
            self._cleanup_chat_requests(current_uid, peer_uid)
            
            # Schedule instant deletion of chat session data after giving peer time to see termination
            deletion_delay = 5000 if not network_message_sent else 3000  # Longer delay if network failed
            print(f"⏱️ Scheduling chat data deletion in {deletion_delay}ms (network_sent: {network_message_sent})")
            
            # Stop listener first, then delete chat data
            if not self._is_shutting_down:
                # Stop listening to chat updates
                self.root.after(2000, lambda: self.firebase_manager.stop_listening(f"chats/{chat_id}"))
                # Delete chat session data from Firebase after delay
                self.root.after(deletion_delay, lambda: self._delete_chat_session_data(chat_id))
        
        # Clear session data
        session_keys = [f"{current_uid}-{peer_uid}", f"{peer_uid}-{current_uid}"]
        for key in session_keys:
            self.active_sessions.pop(key, None)
        
        self.active_chat_session = None
        
        # Update header status
        self.chat_status_label.configure(
            text="No active chat",
            text_color=("#e3f2fd", "#a0a0a0")
        )
        
        # Return to map and refresh
        self._show_user_map()
        # Force immediate refresh of user map
        if not self._is_shutting_down:
            self.root.after(100, self._load_users_on_map)
        
        # Additional redirect ensuring both users see dashboard
        if not self._is_shutting_down:
            self.root.after(300, self._ensure_dashboard_redirect)
    
    def _refresh_user_map(self):
        """Refresh the user map."""
        self._load_users_on_map()
    
    def _start_user_discovery(self):
        """Start periodic user discovery."""
        # Check if shutting down
        if self._is_shutting_down:
            return
            
        # Only run if we're on the map view and logged in
        if not self.current_user or self.current_view != "map":
            # Still schedule next check in case user returns to map
            if self.current_user and not self._is_shutting_down:  # Only continue if user is still logged in
                self.root.after(5000, self._start_user_discovery)
            return
        
        self._load_users_on_map()
        # Refresh every 5 seconds
        if not self._is_shutting_down:
            self.root.after(5000, self._start_user_discovery)
    
    def _start_response_monitoring(self):
        """Start monitoring for chat request responses."""
        # Check if shutting down
        if self._is_shutting_down:
            return
            
        # Only run if user is logged in
        if not self.current_user:
            return
        
        self._check_request_responses()
        # Check every 5 seconds for responses
        if not self._is_shutting_down:
            self.root.after(5000, self._start_response_monitoring)

    def _check_request_responses(self):
        """Check for responses to sent chat requests."""
        if not self.current_user or self.active_chat_session:
            return
        
        try:
            responses = self.firebase_manager.check_sent_requests_responses()
            for response in responses:
                target_uid = response.get('target_uid')
                target_email = response.get('target_email')
                chat_info = response.get('chat_info', {})
                
                # Start chat session with the user who accepted
                peer_user = {'uid': target_uid, 'email': target_email}
                self._start_chat_session(peer_user)
                
                # Connect to peer's network
                peer_ip = chat_info.get('initiator_ip')
                if peer_ip:
                    # Connect to peer (this would normally be handled by network manager)
                    print(f"Connecting to peer at {peer_ip}")
                
                break  # Handle one response at a time
        except Exception as e:
            print(f"Error checking request responses: {e}")
    
    def _start_response_monitoring(self):
        """Start monitoring for chat request responses."""
        self._check_request_responses()
        # Check every 5 seconds for responses
        self.root.after(5000, self._start_response_monitoring)

    def _check_request_responses(self):
        """Check for responses to sent chat requests."""
        if not self.current_user or self.active_chat_session:
            return
        
        try:
            responses = self.firebase_manager.check_sent_requests_responses()
            for response in responses:
                target_uid = response.get('target_uid')
                target_email = response.get('target_email')
                chat_info = response.get('chat_info', {})
                
                # Start chat session with the user who accepted
                peer_user = {'uid': target_uid, 'email': target_email}
                self._start_chat_session(peer_user)
                
                # Connect to peer's network
                peer_ip = chat_info.get('initiator_ip')
                if peer_ip:
                    # Connect to peer (this would normally be handled by network manager)
                    print(f"Connecting to peer at {peer_ip}")
                
                break  # Handle one response at a time
        except Exception as e:
            print(f"Error checking request responses: {e}")
    
    def _start_response_monitoring(self):
        """Start monitoring for chat request responses."""
        self._check_request_responses()
        # Check every 5 seconds for responses
        self.root.after(5000, self._start_response_monitoring)

    def _check_request_responses(self):
        """Check for responses to sent chat requests."""
        if not self.current_user or self.active_chat_session:
            return
        
        try:
            responses = self.firebase_manager.check_sent_requests_responses()
            for response in responses:
                target_uid = response.get('target_uid')
                target_email = response.get('target_email')
                chat_info = response.get('chat_info', {})
                
                # Start chat session with the user who accepted
                peer_user = {'uid': target_uid, 'email': target_email}
                self._start_chat_session(peer_user)
                
                # Connect to peer's network
                peer_ip = chat_info.get('initiator_ip')
                if peer_ip:
                    # Connect to peer (this would normally be handled by network manager)
                    print(f"Connecting to peer at {peer_ip}")
                
                break  # Handle one response at a time
        except Exception as e:
            print(f"Error checking request responses: {e}")
    
    def _handle_chat_request(self, requests):
        """Handle incoming chat requests."""
        if not requests:
            return
        
        # Process new requests
        for request_id, request_data in requests.items():
            if (isinstance(request_data, dict) and 
                request_data.get('status') == 'pending' and 
                request_id not in self.processed_requests):
                
                self.processed_requests.add(request_id)
                
                from_email = request_data.get('from_email', 'Unknown')
                from_uid = request_data.get('from_uid', '')
                message = request_data.get('message', '')
                
                # Check if we're busy
                if self.active_chat_session:
                    # Auto-decline
                    self.firebase_manager.respond_to_chat_request(from_uid, request_id, False, None)
                    continue
                
                # Check if requester is busy
                if self._user_has_active_session(from_uid):
                    # Auto-decline
                    self.firebase_manager.respond_to_chat_request(from_uid, request_id, False, None)
                    continue
                
                # Show notification
                self.notification_manager.notify_chat_request(from_email, message)
                
                # Show dialog
                result = messagebox.askyesno(
                    "Chat Request",
                    f"Chat request from: {from_email} \"{message}\". Accept this chat request?"
                )
                
                if result:
                    # Accept
                    local_ip, local_port = self.network_manager.get_local_address()
                    self.firebase_manager.respond_to_chat_request(from_uid, request_id, True, local_ip)
                    
                    # Start chat
                    peer_user = {'uid': from_uid, 'email': from_email}
                    self._start_chat_session(peer_user)
                else:
                    # Decline
                    self.firebase_manager.respond_to_chat_request(from_uid, request_id, False, None)
    
    def _handle_text_message(self, message, peer_id):
        """Handle incoming encrypted text message."""
        try:
            if self.active_chat_session and self.current_view == "chat":
                # Extract message content
                content_data = message.get('content', {})
                text_content = content_data.get('text', '')
                sender_email = content_data.get('sender', 'Unknown')
                encryption_info = content_data.get('encryption', 'Unknown')
                
                if text_content:
                    # Add the decrypted message to chat
                    self._add_message_to_chat(sender_email, text_content, is_own=False)
                    
                    # Add encryption status (only first time)
                    if not hasattr(self, '_encryption_status_shown'):
                        self._add_system_message(f"🔐 Message encrypted with {encryption_info}")
                        self._encryption_status_shown = True
                    
                    print(f"✅ Received encrypted message from {peer_id}: {text_content[:50]}...")
                else:
                    print(f"❌ Empty message content from {peer_id}")
            else:
                print(f"❌ Received message from {peer_id} but no active chat session")
                
        except Exception as e:
            print(f"❌ Error handling text message from {peer_id}: {e}")
            if self.active_chat_session and self.current_view == "chat":
                self._add_system_message("❌ Error processing received message")
    
    def _handle_session_key(self, message, peer_id):
        """Handle session key exchange."""
        if self.active_chat_session and self.current_view == "chat":
            self._add_message_to_chat("System", "Encryption keys exchanged", is_own=False)
    
    def _handle_chat_updates(self, chat_data):
        """Handle Firebase chat updates (peer status changes)."""
        if not self.active_chat_session or not chat_data:
            return
        
        try:
            current_uid = self.current_user.get('uid', '') if self.current_user else ''
            print(f"🔄 Chat update received: {chat_data}")
            
            # Check if chat has been terminated
            chat_status = chat_data.get('status', '')
            terminated_by = chat_data.get('terminated_by', '')
            
            print(f"📊 Chat status: {chat_status}, terminated_by: {terminated_by}, current_uid: {current_uid}")
            
            # Check if chat was terminated by peer (not by current user)
            if chat_status == 'terminated' and terminated_by and terminated_by != current_uid:
                print(f"🚨 Chat terminated by peer {terminated_by}, handling termination")
                # Chat was terminated by the peer, handle it as peer termination
                chat_id = self.active_chat_session.get('chat_id', '') if self.active_chat_session else ''
                self.root.after(0, lambda: self._handle_peer_chat_termination())
                return
            elif chat_status == 'terminated' and terminated_by == current_uid:
                print(f"📍 Chat terminated by current user {current_uid}, cleanup will be handled by _end_chat_session")
                # This termination was initiated by current user, cleanup already scheduled
                return
            
            # Also check individual participant status for backward compatibility
            participants = chat_data.get('participants', {})
            peer_uid = self.active_chat_session.get('uid', '')
            
            # Check if peer has terminated the chat (but avoid double-processing)
            peer_status = participants.get(peer_uid, {}).get('status', '')
            print(f"👥 Peer {peer_uid} status: {peer_status}")
            
            # Only trigger peer termination if:
            # 1. Peer status is terminated AND
            # 2. We didn't already handle this via the global chat status check above
            if peer_status == 'terminated' and chat_status != 'terminated':
                print(f"🚨 Peer {peer_uid} terminated chat (individual status), handling termination")
                # Peer has ended the chat, terminate our side too
                self.root.after(0, lambda: self._handle_peer_chat_termination())
            elif peer_status == 'terminated' and chat_status == 'terminated':
                print(f"ℹ️ Peer {peer_uid} status is terminated, but already handled via global chat status")
                
        except Exception as e:
            print(f"Error handling chat updates: {e}")
    
    def _handle_chat_termination(self, message, peer_id):
        """Handle incoming chat termination message via network."""
        print(f"📡 Received network chat termination from {peer_id}: {message}")
        if self.active_chat_session:
            print(f"🔄 Processing network chat termination")
            # Peer terminated chat via network message
            self.root.after(0, lambda: self._handle_peer_chat_termination())
        else:
            print(f"⚠️ No active chat session for network termination from {peer_id}")
    
    def _handle_peer_chat_termination(self):
        """Handle when peer terminates the chat session."""
        if not self.active_chat_session:
            print("⚠️ No active chat session for peer termination")
            return
        
        peer_email = self.active_chat_session.get('email', 'Unknown')
        chat_id = self.active_chat_session.get('chat_id', '')
        print(f"🚨 Handling peer termination from {peer_email}")
        
        # Show notification that peer ended the chat
        messagebox.showinfo(
            "Chat Ended",
            f"{peer_email} has ended the chat session."
        )
        
        # Get current user info before ending session
        current_uid = self.current_user.get('uid', '') if self.current_user else ''
        peer_uid = self.active_chat_session.get('uid', '')
        
        # Clean up chat requests between users
        if current_uid and peer_uid:
            self._cleanup_chat_requests(current_uid, peer_uid)
        
        # End chat session without showing confirmation (peer initiated termination)
        print(f"🔄 Ending chat session without confirmation due to peer termination")
        self._end_chat_session(show_confirmation=False)
        
        # Since peer terminated, also delete chat data after a short delay
        if chat_id and not self._is_shutting_down:
            print(f"🗑️ Scheduling chat data deletion after peer termination")
            self.root.after(2000, lambda: self._delete_chat_session_data(chat_id))
        
        # Ensure redirection to dashboard after notification
        print(f"📍 Scheduling dashboard redirect")
        if not self._is_shutting_down:
            self.root.after(200, self._ensure_dashboard_redirect)
    
    def _delete_chat_session_data(self, chat_id: str):
        """Delete chat session data from Firebase after termination."""
        try:
            print(f"🗑️ Executing instant deletion of chat session data: {chat_id}")
            success = self.firebase_manager.delete_chat_session(chat_id)
            
            if success:
                print(f"✅ Chat session data for {chat_id} deleted successfully")
            else:
                print(f"❌ Failed to delete chat session data for {chat_id}")
                
        except Exception as e:
            print(f"❌ Error deleting chat session data for {chat_id}: {e}")
    
    def _cleanup_chat_requests(self, current_uid: str, peer_uid: str):
        """Clean up chat requests between current user and peer."""
        try:
            print(f"🧼 Cleaning up chat requests between {current_uid} and {peer_uid}")
            
            # Clean up requests in both directions
            cleaned_count = 0
            
            # Check requests sent by current user to peer
            peer_requests = self.firebase_manager._read_data(f"requests/{peer_uid}")
            if peer_requests:
                for request_id, request_data in peer_requests.items():
                    if (isinstance(request_data, dict) and 
                        request_data.get('from_uid') == current_uid):
                        if self.firebase_manager.delete_chat_request(peer_uid, request_id):
                            cleaned_count += 1
            
            # Check requests sent by peer to current user
            current_requests = self.firebase_manager._read_data(f"requests/{current_uid}")
            if current_requests:
                for request_id, request_data in current_requests.items():
                    if (isinstance(request_data, dict) and 
                        request_data.get('from_uid') == peer_uid):
                        if self.firebase_manager.delete_chat_request(current_uid, request_id):
                            cleaned_count += 1
            
            print(f"🎉 Cleaned up {cleaned_count} chat requests")
            
        except Exception as e:
            print(f"❌ Error cleaning up chat requests: {e}")
    
    def _ensure_dashboard_redirect(self):
        """Ensure user is redirected to dashboard/map view after chat termination."""
        if self._is_shutting_down:
            return
            
        if self.current_view != "map":
            # Force redirect to map view
            self._show_user_map()
        
        # Force refresh of user map to show updated statuses
        if not self._is_shutting_down:
            self.root.after(100, self._load_users_on_map)
        
        # Update status label if it exists
        if hasattr(self, 'chat_status_label') and self.chat_status_label:
            try:
                self.chat_status_label.configure(
                    text="No active chat",
                    text_color=("#e3f2fd", "#a0a0a0")
                )
            except tk.TclError:
                # Label might have been destroyed
                pass
    
    def _handle_login(self):
        """Handle login."""
        try:
            if not hasattr(self, 'email_entry') or not self.email_entry.winfo_exists():
                return
            
            email = self.email_entry.get().strip()
            password = self.password_entry.get()
            
            if not email or not password:
                self.status_label.configure(text="Please fill in all fields")
                return
            
            self.status_label.configure(text="Logging in...")
            self.root.update()
            
            # Login in background
            threading.Thread(target=self._login_worker, args=(email, password), daemon=True).start()
        except Exception as e:
            self.status_label.configure(text=f"Error: {str(e)}")
    
    def _handle_register(self):
        """Handle registration."""
        try:
            if not hasattr(self, 'email_entry') or not self.email_entry.winfo_exists():
                return
            
            email = self.email_entry.get().strip()
            password = self.password_entry.get()
            
            if not email or not password:
                self.status_label.configure(text="Please fill in all fields")
                return
            
            self.status_label.configure(text="Registering...")
            self.root.update()
            
            # Register in background
            threading.Thread(target=self._register_worker, args=(email, password), daemon=True).start()
        except Exception as e:
            self.status_label.configure(text=f"Error: {str(e)}")
    
    def _login_worker(self, email, password):
        """Login worker thread."""
        success, message = self.auth_manager.login_user(email, password)
        self.root.after(0, self._login_callback, success, message)
    
    def _register_worker(self, email, password):
        """Register worker thread."""
        success, message = self.auth_manager.register_user(email, password)
        self.root.after(0, self._register_callback, success, message)
    
    def _login_callback(self, success, message):
        """Handle login result."""
        if success:
            self.current_user = self.auth_manager.get_current_user()
            self.notification_manager.notify_authentication_success(self.current_user['email'])
            self.show_main_screen()
        else:
            self.status_label.configure(text=f"Login failed: {message}")
    
    def _register_callback(self, success, message):
        """Handle register result."""
        if success:
            self.status_label.configure(text="Registration successful! Please login.")
        else:
            self.status_label.configure(text=f"Registration failed: {message}")
    
    def _handle_logout(self):
        """Handle logout."""
        result = messagebox.askyesno("Logout", "Are you sure you want to logout?")
        if result:
            # Set shutdown flag to prevent callbacks
            self._is_shutting_down = True
            
            # Comprehensive cleanup before logout
            if self.current_user:
                print("🧹 Performing cleanup before logout...")
                comprehensive_cleanup(self.auth_manager, self.firebase_manager, silent=False)
                # Mark cleanup as done to prevent duplicate in atexit
                if hasattr(self, '_cleanup_done_flag'):
                    self._cleanup_done_flag[0] = True
            
            # End any active chat
            if self.active_chat_session:
                self._end_chat_session()
            
            # Clear sessions
            self.active_sessions.clear()
            
            # Standard cleanup
            self.firebase_manager.cleanup()
            self.network_manager.stop_server()
            
            # Logout
            self.auth_manager.logout_user()
            self.current_user = None
            self.show_login_screen()
    
    def _clear_current_frame(self):
        """Clear current frame."""
        if self.current_frame:
            self.current_frame.destroy()
            self.current_frame = None
        
        # Clear references
        self.content_area = None
        self.user_map_canvas = None
        self.messages_frame = None
        self.message_entry = None
    
    def _on_closing(self):
        """Handle application closing."""
        try:
            # Set shutdown flag to prevent callbacks
            self._is_shutting_down = True
            
            # Comprehensive cleanup before exit
            if self.current_user:
                print("🧹 Performing cleanup before exit...")
                comprehensive_cleanup(self.auth_manager, self.firebase_manager, silent=False)
                # Mark cleanup as done to prevent duplicate in atexit
                if hasattr(self, '_cleanup_done_flag'):
                    self._cleanup_done_flag[0] = True
            
            # End active chat
            if self.active_chat_session:
                self._end_chat_session()
            
            # Standard cleanup
            self.firebase_manager.cleanup()
            
            if self.network_manager:
                self.network_manager.stop_server()
            
        except Exception as e:
            print(f"Error during cleanup: {e}")
        finally:
            self.root.destroy()
    def _handle_network_disconnection(self, peer_id):
        print(f" Network disconnection detected for peer: {peer_id}")
        
        # If we have an active chat with this peer, clean up the chat data
        if (self.active_chat_session and 
            self.active_chat_session.get('uid') == peer_id):
            
            chat_id = self.active_chat_session.get('chat_id', '')
            print(f" Active chat {chat_id} disconnected, scheduling cleanup")
            
            # Schedule chat termination and cleanup after a delay
            # This gives time for the peer to reconnect if it's a temporary issue
            if chat_id and not self._is_shutting_down:
                self.root.after(10000, lambda: self._cleanup_disconnected_chat(chat_id, peer_id))
    def _handle_network_disconnection(self, peer_id):
        """Handle network disconnection from peer."""
        print(f"🔌 Network disconnection detected for peer: {peer_id}")
        
        # If we have an active chat with this peer, clean up the chat data
        if (self.active_chat_session and 
            self.active_chat_session.get('uid') == peer_id):
            
            chat_id = self.active_chat_session.get('chat_id', '')
            print(f"💬 Active chat {chat_id} disconnected, scheduling cleanup")
            
            # Schedule chat termination and cleanup after a delay
            # This gives time for the peer to reconnect if it's a temporary issue
            if chat_id and not self._is_shutting_down:
                self.root.after(10000, lambda: self._cleanup_disconnected_chat(chat_id, peer_id))
    
    def _cleanup_disconnected_chat(self, chat_id, peer_id):
        """Clean up chat data after network disconnection."""
        try:
            # Check if chat session is still active and peer is still disconnected
            if (self.active_chat_session and 
                self.active_chat_session.get('chat_id') == chat_id and
                peer_id not in self.network_manager.get_connected_peers()):
                
                print(f"🧹 Cleaning up disconnected chat {chat_id} with peer {peer_id}")
                
                # End the chat session
                self._end_chat_session(show_confirmation=False)
                
                # Delete the chat data
                self._delete_chat_session_data(chat_id)
                
        except Exception as e:
            print(f"❌ Error cleaning up disconnected chat: {e}")
