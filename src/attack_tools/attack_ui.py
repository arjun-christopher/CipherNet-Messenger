#!/usr/bin/env python3
"""
CipherNet-Messenger Attack Control Panel UI

This file provides a graphical user interface for controlling cryptographic
attack demonstrations in the CipherNet-Messenger system. It offers toggle
switches to enable/disable various attack vectors for educational and
security testing purposes.

Features:
- Dark-themed attack control panel
- Real-time toggle switches for different attack types
- Visual feedback for active attacks
- Integration with hooks.py attack implementations

Supported Attack Controls:
- RSA Man-in-the-Middle (MITM) Attack Toggle
- HMAC Message Tampering Attack Toggle
- SHA256 Hash Bypass Attack Toggle

The UI provides an intuitive way to demonstrate how various cryptographic
attacks can compromise secure communication systems, helping users understand
the importance of proper security implementations.

WARNING: This tool is for educational and authorized security testing only.
Ensure you have proper authorization before testing these attacks on any system.

Author: Arjun Christopher
"""

import customtkinter as ctk
import sys
import os

# Import hooks and global flags
sys.path.append(os.path.dirname(__file__))
import hooks

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class AttackControlUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CipherNet Attack Control Panel")
        self.geometry("420x320")
        self.configure(bg="#2c0a0a")

        self.label = ctk.CTkLabel(self, text="Enable/Disable Attacks", font=("Arial", 22), text_color="#ff3c3c")
        self.label.pack(pady=20)

        # RSA MITM toggle
        self.rsa_var = ctk.BooleanVar(value=False)
        self.rsa_toggle = ctk.CTkSwitch(self, text="RSA Man-in-the-Middle", variable=self.rsa_var,
                                        onvalue=True, offvalue=False, fg_color="#ff3c3c",
                                        progress_color="#ff3c3c", button_color="#3c0a0a",
                                        command=self.toggle_rsa)
        self.rsa_toggle.pack(pady=10)

        # HMAC Tamper toggle
        self.hmac_var = ctk.BooleanVar(value=False)
        self.hmac_toggle = ctk.CTkSwitch(self, text="HMAC Message Tampering", variable=self.hmac_var,
                                         onvalue=True, offvalue=False, fg_color="#ff3c3c",
                                         progress_color="#ff3c3c", button_color="#3c0a0a",
                                         command=self.toggle_hmac)
        self.hmac_toggle.pack(pady=10)

        # SHA256 Bypass toggle
        self.sha_var = ctk.BooleanVar(value=False)
        self.sha_toggle = ctk.CTkSwitch(self, text="SHA-256 File Integrity Bypass", variable=self.sha_var,
                                        onvalue=True, offvalue=False, fg_color="#ff3c3c",
                                        progress_color="#ff3c3c", button_color="#3c0a0a",
                                        command=self.toggle_sha)
        self.sha_toggle.pack(pady=10)

        self.info_box = ctk.CTkTextbox(self, width=380, height=80, fg_color="#1a0000", text_color="#ff3c3c")
        self.info_box.pack(pady=10)
        self.info_box.insert("0.0", "Use switches to enable/disable real-time attacks. Messenger must call hooks.py functions.")

    def toggle_rsa(self):
        hooks.HOOK_RSA_MITM_ACTIVE = self.rsa_var.get()
        self.show_status()

    def toggle_hmac(self):
        hooks.HOOK_HMAC_TAMPER_ACTIVE = self.hmac_var.get()
        self.show_status()

    def toggle_sha(self):
        hooks.HOOK_SHA256_BYPASS_ACTIVE = self.sha_var.get()
        self.show_status()

    def show_status(self):
        status = f"RSA MITM: {'ON' if hooks.HOOK_RSA_MITM_ACTIVE else 'OFF'}\n"
        status += f"HMAC Tamper: {'ON' if hooks.HOOK_HMAC_TAMPER_ACTIVE else 'OFF'}\n"
        status += f"SHA-256 Bypass: {'ON' if hooks.HOOK_SHA256_BYPASS_ACTIVE else 'OFF'}\n"
        self.info_box.delete("0.0", "end")
        self.info_box.insert("0.0", status)

if __name__ == "__main__":
    app = AttackControlUI()
    app.mainloop()