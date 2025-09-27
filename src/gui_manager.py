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
            text="🗺️ CipherNet Messenger",
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
            text="🚀 Login",
            command=self._handle_login,
            width=120,
            height=35,
            fg_color=("#1e88e5", "#1565c0")
        )
        login_button.pack(side="left", padx=(20, 10))
        
        register_button = ctk.CTkButton(
            button_frame,
            text="📝 Register",
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
        
        # Start user discovery
        self._start_user_discovery()
    
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
            text="🗺️ CipherNet Map",
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
            text="🚪 Logout",
            command=self._handle_logout,
            width=80,
            height=35,
            fg_color=("#dc3545", "#b02a37"),
            hover_color=("#c82333", "#9a1e2a")
        )
        logout_button.pack(side="right")
        
        # User info
        user_info = f"👤 {self.current_user['email'] if self.current_user else 'Unknown'}"
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
            text="🔴 No active chat",
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
            text="🌐 Online Users - Click on a user to start chatting",
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
            text="🔄 Refresh",
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
        self.root.after(100, self._load_users_on_map)
    
    def _load_users_on_map(self):
        """Load and display users on the map."""
        if not self.user_map_canvas:
            return
        
        # Clear canvas
        self.user_map_canvas.delete("all")
        
        # Get canvas dimensions
        self.user_map_canvas.update()
        canvas_width = self.user_map_canvas.winfo_width()
        canvas_height = self.user_map_canvas.winfo_height()
        
        if canvas_width <= 1 or canvas_height <= 1:
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
                text="🌐 No other users online\\n\\n👥 Invite friends to join CipherNet!",
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
            text=f"● {status_text}",
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
        if entering:
            for item_id in item_ids:
                self.user_map_canvas.itemconfig(item_id, width=4)
        else:
            for item_id in item_ids:
                self.user_map_canvas.itemconfig(item_id, width=3)
    
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
                f"You already have an active chat with {self.active_chat_session.get('email', 'someone')}.\\n\\nEnd the current chat to start a new one."
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
            f"Send a chat request to {user.get('email', 'this user')}?\\n\\nThey will be notified and can accept or decline."
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
        """Start a chat session with a peer."""
        if self.active_chat_session:
            return
        
        # Set active session
        self.active_chat_session = peer_user
        
        # Update session tracking
        current_uid = self.current_user.get('uid', '') if self.current_user else ''
        peer_uid = peer_user.get('uid', '')
        session_key = f"{current_uid}-{peer_uid}"
        self.active_sessions[session_key] = True
        
        # Update header status
        self.chat_status_label.configure(
            text=f"💬 Chatting with {peer_user.get('email', 'Unknown')}",
            text_color=("#51cf66", "#51cf66")
        )
        
        # Show chat interface
        self._show_chat_interface()
    
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
            text="🔒 End-to-end encrypted",
            font=ctk.CTkFont(size=12),
            text_color=("#e3f2fd", "#a0a0a0"),
            anchor="w"
        )
        status_label.pack(anchor="w", pady=(0, 8))
        
        # Right side - controls
        controls_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        controls_frame.pack(side="right", padx=20, pady=15)
        
        # Back to map button
        back_btn = ctk.CTkButton(
            controls_frame,
            text="🗺️ Map",
            command=self._show_user_map,
            width=90,
            height=35,
            fg_color=("#28a745", "#1e7e34"),
            hover_color=("#218838", "#155724")
        )
        back_btn.pack(side="right", padx=(10, 0))
        
        # End chat button
        end_btn = ctk.CTkButton(
            controls_frame,
            text="❌ End Chat",
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
            text="🔐 Secure Chat Session Started",
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
        """Create message input area."""
        input_frame = ctk.CTkFrame(parent, height=70)
        input_frame.pack(fill="x")
        input_frame.pack_propagate(False)
        
        # Message entry
        self.message_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="Type your message...",
            height=45,
            font=ctk.CTkFont(size=14)
        )
        self.message_entry.pack(side="left", fill="both", expand=True, padx=(15, 10), pady=12)
        
        # Send button
        send_btn = ctk.CTkButton(
            input_frame,
            text="📤",
            command=self._send_message,
            width=60,
            height=45,
            fg_color=("#1e88e5", "#1565c0"),
            font=ctk.CTkFont(size=20)
        )
        send_btn.pack(side="right", padx=(0, 15), pady=12)
        
        # Bind Enter key
        self.message_entry.bind('<Return>', lambda e: self._send_message())
        self.message_entry.focus()
    
    def _send_message(self):
        """Send a message."""
        if not self.active_chat_session or not self.message_entry:
            return
        
        message = self.message_entry.get().strip()
        if not message:
            return
        
        # Clear entry
        self.message_entry.delete(0, "end")
        
        # Add to display
        self._add_message_to_chat("You", message, is_own=True)
        
        # TODO: Send via network manager
        # For now, simulate echo response
        self.root.after(1000, lambda: self._add_message_to_chat(
            self.active_chat_session.get('email', 'Peer'),
            f"Echo: {message}",
            is_own=False
        ))
    
    def _add_message_to_chat(self, sender, message, is_own=False):
        """Add a message to the chat display."""
        if not self.messages_frame:
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
    
    def _end_chat_session(self):
        """End the current chat session."""
        if not self.active_chat_session:
            return
        
        peer_email = self.active_chat_session.get('email', 'this user')
        result = messagebox.askyesno(
            "End Chat",
            f"End chat session with {peer_email}?"
        )
        
        if result:
            # Clear session data
            current_uid = self.current_user.get('uid', '') if self.current_user else ''
            peer_uid = self.active_chat_session.get('uid', '')
            
            # Remove from active sessions
            session_keys = [f"{current_uid}-{peer_uid}", f"{peer_uid}-{current_uid}"]
            for key in session_keys:
                self.active_sessions.pop(key, None)
            
            self.active_chat_session = None
            
            # Update header status
            self.chat_status_label.configure(
                text="🔴 No active chat",
                text_color=("#e3f2fd", "#a0a0a0")
            )
            
            # Return to map
            self._show_user_map()
    
    def _refresh_user_map(self):
        """Refresh the user map."""
        self._load_users_on_map()
    
    def _start_user_discovery(self):
        """Start periodic user discovery."""
        self._load_users_on_map()
        # Refresh every 5 seconds
        self.root.after(5000, self._start_user_discovery)
    
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
                    "💬 Chat Request",
                    f"Chat request from:\\n{from_email}\\n\\n\\\"{message}\\\"\\n\\nAccept this chat request?"
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
        """Handle incoming text message."""
        if self.active_chat_session and self.current_view == "chat":
            sender = message.get('sender', 'Unknown')
            content = message.get('content', {}).get('content', '')
            self._add_message_to_chat(sender, content, is_own=False)
    
    def _handle_session_key(self, message, peer_id):
        """Handle session key exchange."""
        if self.active_chat_session and self.current_view == "chat":
            self._add_message_to_chat("System", "🔐 Encryption keys exchanged", is_own=False)
    
    def _handle_login(self):
        """Handle login."""
        try:
            if not hasattr(self, 'email_entry') or not self.email_entry.winfo_exists():
                return
            
            email = self.email_entry.get().strip()
            password = self.password_entry.get()
            
            if not email or not password:
                self.status_label.configure(text="❌ Please fill in all fields")
                return
            
            self.status_label.configure(text="🔄 Logging in...")
            self.root.update()
            
            # Login in background
            threading.Thread(target=self._login_worker, args=(email, password), daemon=True).start()
        except Exception as e:
            self.status_label.configure(text=f"❌ Error: {str(e)}")
    
    def _handle_register(self):
        """Handle registration."""
        try:
            if not hasattr(self, 'email_entry') or not self.email_entry.winfo_exists():
                return
            
            email = self.email_entry.get().strip()
            password = self.password_entry.get()
            
            if not email or not password:
                self.status_label.configure(text="❌ Please fill in all fields")
                return
            
            self.status_label.configure(text="🔄 Registering...")
            self.root.update()
            
            # Register in background
            threading.Thread(target=self._register_worker, args=(email, password), daemon=True).start()
        except Exception as e:
            self.status_label.configure(text=f"❌ Error: {str(e)}")
    
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
            self.status_label.configure(text=f"❌ Login failed: {message}")
    
    def _register_callback(self, success, message):
        """Handle register result."""
        if success:
            self.status_label.configure(text="✅ Registration successful! Please login.")
        else:
            self.status_label.configure(text=f"❌ Registration failed: {message}")
    
    def _handle_logout(self):
        """Handle logout."""
        result = messagebox.askyesno("Logout", "Are you sure you want to logout?")
        if result:
            # End any active chat
            if self.active_chat_session:
                self._end_chat_session()
            
            # Clear sessions
            self.active_sessions.clear()
            
            # Stop network
            if hasattr(self, 'network_manager'):
                self.network_manager.stop_server()
            
            # Remove presence
            if hasattr(self, 'firebase_manager'):
                self.firebase_manager.remove_user_presence()
            
            # Logout
            self.auth_manager.logout_user()
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
            # End active chat
            if self.active_chat_session:
                self._end_chat_session()
            
            # Stop network
            if hasattr(self, 'network_manager'):
                self.network_manager.stop_server()
            
            # Remove presence
            if hasattr(self, 'firebase_manager'):
                self.firebase_manager.remove_user_presence()
            
            # Cleanup
            comprehensive_cleanup()
            
        except Exception as e:
            print(f"Error during cleanup: {e}")
        finally:
            self.root.destroy()