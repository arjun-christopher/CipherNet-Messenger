"""
File Transfer Manager for CipherNet Messenger
Handles secure file sharing with encryption and integrity verification.

Author: Arjun Christopher
"""

import os
import json
import threading
import time
from pathlib import Path
from typing import Dict, Any, Callable, Optional, Tuple
from PIL import Image
import mimetypes


class FileTransferManager:
    """Manages secure file transfer operations."""
    
    def __init__(self, config, crypto_manager, network_manager, notification_manager=None):

        self.config = config
        self.crypto_manager = crypto_manager
        self.network_manager = network_manager
        self.notification_manager = notification_manager
        
        self.chunk_size = config.get('network.file_chunk_size', 4096)
        self.downloads_dir = Path(__file__).parent.parent / "downloads"
        self.downloads_dir.mkdir(parents=True, exist_ok=True)

        # File transfer tracking
        self.active_transfers = {}  # {transfer_id: transfer_info}
        self.transfer_callbacks = {}  # {transfer_id: callback}
        
        # Allowed file types for security
        self.allowed_extensions = {
            '.txt', '.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png', '.gif',
            '.mp3', '.mp4', '.avi', '.zip', '.rar', '.py', '.js', '.html', '.css'
        }
        
        self.max_file_size = 100 * 1024 * 1024  # 100MB limit
        
        # Register network handlers
        self._register_handlers()
    
    def send_file(self, peer_id: str, file_path: str, 
                  progress_callback: Optional[Callable[[int, int], None]] = None) -> bool:
        """
        Send a file to a peer.
        
        Args:
            peer_id: Target peer identifier
            file_path: Path to the file to send
            progress_callback: Optional callback for progress updates (sent_bytes, total_bytes)
        
        Returns:
            True if file transfer initiated successfully, False otherwise
        """
        try:
            file_path = Path(file_path)
            
            # Validate file
            if not self._validate_file_for_sending(file_path):
                return False
            
            # Calculate file hash
            file_hash = self.crypto_manager.calculate_file_hash(str(file_path))
            file_size = file_path.stat().st_size
            
            # Generate transfer ID
            transfer_id = f"send_{peer_id}_{int(os.urandom(4).hex(), 16)}"
            
            # Store transfer info with timestamp
            import time
            self.active_transfers[transfer_id] = {
                'type': 'send',
                'peer_id': peer_id,
                'file_path': file_path,
                'file_size': file_size,
                'file_hash': file_hash,
                'bytes_transferred': 0,
                'status': 'initiating',
                'start_time': time.time()
            }
            
            if progress_callback:
                self.transfer_callbacks[transfer_id] = progress_callback
            
            # Prepare file metadata for HMAC authentication
            file_metadata = {
                'transfer_id': transfer_id,
                'filename': file_path.name,
                'file_size': file_size,
                'file_hash': file_hash,
                'mime_type': mimetypes.guess_type(str(file_path))[0] or 'application/octet-stream',
                'encryption_algorithm': 'Blowfish-256-CBC',
                'authentication_algorithm': 'HMAC-SHA256'
            }
            
            # Generate HMAC for control message integrity
            metadata_json = json.dumps(file_metadata, sort_keys=True)
            control_message_hmac = self.crypto_manager.calculate_hmac(metadata_json, peer_id=peer_id)
            
            # Send authenticated file metadata
            file_info = {
                **file_metadata,
                'control_message_hmac': control_message_hmac.hex(),
                'security_protocol': 'Secure File Transfer Protocol'
            }
            
            success = self.network_manager.send_message(
                peer_id, 'file_request', file_info
            )
            
            if success:
                self.active_transfers[transfer_id]['status'] = 'waiting_for_acceptance'
                print(f"File transfer request sent: {file_path.name}")
                return True
            else:
                del self.active_transfers[transfer_id]
                return False
                
        except Exception as e:
            print(f"Failed to initiate file transfer: {e}")
            return False
    
    def accept_file_transfer(self, transfer_id: str, peer_id: str) -> bool:
        """
        Accept an incoming file transfer.
        
        Args:
            transfer_id: Transfer identifier
            peer_id: Sender peer identifier
        
        Returns:
            True if acceptance sent successfully, False otherwise
        """
        try:
            response = {
                'transfer_id': transfer_id,
                'accepted': True
            }
            
            return self.network_manager.send_message(
                peer_id, 'file_response', response
            )
            
        except Exception as e:
            print(f"Failed to accept file transfer: {e}")
            return False
    
    def decline_file_transfer(self, transfer_id: str, peer_id: str, reason: str = "Declined by user") -> bool:
        """
        Decline an incoming file transfer.
        
        Args:
            transfer_id: Transfer identifier
            peer_id: Sender peer identifier
            reason: Reason for declining
        
        Returns:
            True if decline sent successfully, False otherwise
        """
        try:
            response = {
                'transfer_id': transfer_id,
                'accepted': False,
                'reason': reason
            }
            
            return self.network_manager.send_message(
                peer_id, 'file_response', response
            )
            
        except Exception as e:
            print(f"Failed to decline file transfer: {e}")
            return False
    
    def cancel_transfer(self, transfer_id: str) -> bool:
        """
        Cancel an active file transfer.
        
        Args:
            transfer_id: Transfer identifier
        
        Returns:
            True if cancelled successfully, False otherwise
        """
        try:
            if transfer_id in self.active_transfers:
                transfer_info = self.active_transfers[transfer_id]
                peer_id = transfer_info['peer_id']
                
                # Notify peer of cancellation
                cancel_message = {
                    'transfer_id': transfer_id,
                    'reason': 'Cancelled by user'
                }
                
                self.network_manager.send_message(peer_id, 'file_cancel', cancel_message)
                
                # Cleanup
                self._cleanup_transfer(transfer_id)
                return True
            
            return False
            
        except Exception as e:
            print(f"Failed to cancel transfer: {e}")
            return False
    
    def get_transfer_status(self, transfer_id: str) -> Optional[Dict[str, Any]]:
        """
        Get status of a file transfer.
        
        Args:
            transfer_id: Transfer identifier
        
        Returns:
            Transfer status dictionary or None if not found
        """
        return self.active_transfers.get(transfer_id)
    
    def get_active_transfers(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all active file transfers.
        
        Returns:
            Dictionary of active transfers
        """
        return self.active_transfers.copy()
    
    def _register_handlers(self):
        """Register network message handlers for file operations."""
        self.network_manager.register_message_handler('file_request', self._handle_file_request)
        self.network_manager.register_message_handler('file_response', self._handle_file_response)
        self.network_manager.register_message_handler('file_chunk', self._handle_file_chunk)
        self.network_manager.register_message_handler('file_complete', self._handle_file_complete)
        self.network_manager.register_message_handler('file_cancel', self._handle_file_cancel)
    
    def _handle_file_request(self, message: Dict[str, Any], peer_id: str):
        """
        Handle incoming file transfer request.
        
        Args:
            message: File request message
            peer_id: Sender peer identifier
        """
        try:
            content = message.get('content', {})
            transfer_id = content.get('transfer_id')
            filename = content.get('filename')
            file_size = content.get('file_size', 0)
            file_hash = content.get('file_hash')
            mime_type = content.get('mime_type', 'application/octet-stream')
            
            # Validate file request
            if not self._validate_incoming_file(filename, file_size, mime_type):
                self.decline_file_transfer(
                    transfer_id, peer_id, 
                    "File not allowed or too large"
                )
                return
            
            # Store incoming transfer info with timestamp
            import time
            self.active_transfers[transfer_id] = {
                'type': 'receive',
                'peer_id': peer_id,
                'filename': filename,
                'file_size': file_size,
                'file_hash': file_hash,
                'mime_type': mime_type,
                'bytes_received': 0,
                'chunks': [],
                'status': 'pending',
                'start_time': time.time()
            }
            
            # Notify application about incoming file
            print(f"Incoming file transfer: {filename} ({file_size} bytes)")
            
            # Show desktop notification
            if self.notification_manager:
                self.notification_manager.notify_file_request("Unknown User", filename, file_size)
            
            # Auto-accept for demo (in real app, this should prompt user)
            self.accept_file_transfer(transfer_id, peer_id)
            
        except Exception as e:
            print(f"Error handling file request: {e}")
    
    def _handle_file_response(self, message: Dict[str, Any], peer_id: str):
        """
        Handle file transfer response.
        
        Args:
            message: File response message
            peer_id: Responder peer identifier
        """
        try:
            content = message.get('content', {})
            transfer_id = content.get('transfer_id')
            accepted = content.get('accepted', False)
            
            if transfer_id not in self.active_transfers:
                return
            
            transfer_info = self.active_transfers[transfer_id]
            
            if accepted:
                transfer_info['status'] = 'accepted'
                print(f"File transfer accepted: {transfer_info['file_path'].name}")
                
                # Start sending file chunks
                threading.Thread(
                    target=self._send_file_chunks,
                    args=(transfer_id,),
                    daemon=True
                ).start()
            else:
                reason = content.get('reason', 'No reason provided')
                print(f"File transfer declined: {reason}")
                self._cleanup_transfer(transfer_id)
                
        except Exception as e:
            print(f"Error handling file response: {e}")
    
    def _handle_file_chunk(self, message: Dict[str, Any], peer_id: str):
        """
        Handle incoming encrypted file chunk with HMAC verification.
        
        Args:
            message: File chunk message
            peer_id: Sender peer identifier
        """
        try:
            content = message.get('content', {})
            transfer_id = content.get('transfer_id')
            chunk_index = content.get('chunk_index')
            encrypted_chunk_data = bytes.fromhex(content.get('encrypted_chunk_data', ''))
            metadata = content.get('metadata', {})
            metadata_hmac = bytes.fromhex(content.get('metadata_hmac', ''))
            is_last_chunk = content.get('is_last_chunk', False)
            
            if transfer_id not in self.active_transfers:
                return
            
            transfer_info = self.active_transfers[transfer_id]
            
            # Verify metadata HMAC for chunk integrity
            metadata_json = json.dumps(metadata, sort_keys=True)
            if not self.crypto_manager.verify_hmac(metadata_json, metadata_hmac, peer_id=peer_id):
                print(f"❌ HMAC verification failed for chunk {chunk_index} - possible tampering")
                return
            
            # Decrypt chunk data using Blowfish with K_session
            decrypted_chunk_hex = self.crypto_manager.decrypt_message(encrypted_chunk_data, peer_id=peer_id)
            chunk_data = bytes.fromhex(decrypted_chunk_hex)
            
            # Verify chunk size matches metadata
            if len(chunk_data) != metadata.get('chunk_size', 0):
                print(f"❌ Chunk size mismatch for chunk {chunk_index}")
                return
            
            print(f"✅ Chunk {chunk_index} decrypted and authenticated successfully ({len(chunk_data)} bytes)")
            
            # Store decrypted chunk
            transfer_info['chunks'].append((chunk_index, chunk_data))
            transfer_info['bytes_received'] += len(chunk_data)
            
            # Update progress and add debug info
            progress = (transfer_info['bytes_received'] / transfer_info['file_size']) * 100
            chunks_received = len(transfer_info['chunks'])
            print(f"📁 Secure file transfer progress: {progress:.1f}% (Blowfish + HMAC) - Chunk {chunk_index} - Total chunks: {chunks_received}")
            print(f"📊 Transfer status - Received: {transfer_info['bytes_received']}/{transfer_info['file_size']} bytes")
            
            if is_last_chunk:
                print(f"🏁 Last chunk received! Assembling and saving file...")
                print(f"🔍 Debug info before assembly:")
                print(f"   - Transfer ID: {transfer_id}")
                print(f"   - Filename: {transfer_info.get('filename', 'UNKNOWN')}")
                print(f"   - Total chunks: {len(transfer_info['chunks'])}")
                print(f"   - Downloads dir: {self.downloads_dir}")
                print(f"   - Downloads dir exists: {self.downloads_dir.exists()}")
                
                # Assemble and save file with integrity verification
                result = self._assemble_and_save_file(transfer_id)
                print(f"🏁 File assembly result: {'SUCCESS' if result else 'FAILED'}")
                
            elif progress >= 99.0:  # Safety check for near-complete transfers
                print(f"⚠️ Transfer appears complete ({progress:.1f}%) but last chunk flag not set. Attempting to save...")
                # Try to save what we have
                result = self._assemble_and_save_file(transfer_id)
                print(f"⚠️ Forced assembly result: {'SUCCESS' if result else 'FAILED'}")
                
        except Exception as e:
            print(f"Error handling file chunk: {e}")
    
    def _handle_file_complete(self, message: Dict[str, Any], peer_id: str):
        """
        Handle file transfer completion notification.
        Note: We don't cleanup here to avoid race condition with last chunk processing.
        
        Args:
            message: File complete message
            peer_id: Sender peer identifier
        """
        try:
            content = message.get('content', {})
            transfer_id = content.get('transfer_id')
            success = content.get('success', False)
            
            if transfer_id in self.active_transfers:
                transfer_info = self.active_transfers[transfer_id]
                if success:
                    print(f"📤 Sender reports successful completion for: {transfer_info.get('filename', 'unknown')}")
                    # Mark as sender-complete but don't cleanup yet
                    transfer_info['sender_complete'] = True
                else:
                    print(f"📤 Sender reports completion with errors for: {transfer_info.get('filename', 'unknown')}")
                    transfer_info['sender_complete'] = False
                
                # Don't cleanup here - let receiver cleanup after processing all chunks
                print(f"🔄 Keeping transfer active to process any remaining chunks...")
                
        except Exception as e:
            print(f"Error handling file completion: {e}")
    
    def _handle_file_cancel(self, message: Dict[str, Any], peer_id: str):
        """
        Handle file transfer cancellation.
        
        Args:
            message: File cancel message
            peer_id: Sender peer identifier
        """
        try:
            content = message.get('content', {})
            transfer_id = content.get('transfer_id')
            reason = content.get('reason', 'Cancelled by peer')
            
            print(f"File transfer cancelled: {reason}")
            self._cleanup_transfer(transfer_id)
            
        except Exception as e:
            print(f"Error handling file cancellation: {e}")
    
    def _send_file_chunks(self, transfer_id: str):
        """
        Send file in encrypted chunks.
        
        Args:
            transfer_id: Transfer identifier
        """
        try:
            if transfer_id not in self.active_transfers:
                return
            
            transfer_info = self.active_transfers[transfer_id]
            file_path = transfer_info['file_path']
            peer_id = transfer_info['peer_id']
            chunk_index = 0
            
            with open(file_path, 'rb') as file:
                while True:
                    chunk = file.read(self.chunk_size)
                    if not chunk:
                        break
                    
                    is_last_chunk = len(chunk) < self.chunk_size
                    
                    # Encrypt chunk with Blowfish using K_session
                    encrypted_chunk = self.crypto_manager.encrypt_message(chunk.hex(), peer_id=peer_id)
                    
                    # Create chunk metadata for HMAC authentication
                    chunk_metadata = {
                        'transfer_id': transfer_id,
                        'chunk_index': chunk_index,
                        'chunk_size': len(chunk),
                        'is_last_chunk': is_last_chunk
                    }
                    metadata_json = json.dumps(chunk_metadata, sort_keys=True)
                    
                    # Generate HMAC for chunk metadata integrity
                    metadata_hmac = self.crypto_manager.calculate_hmac(metadata_json, peer_id=peer_id)
                    
                    # Send encrypted chunk with authenticated metadata
                    chunk_message = {
                        'transfer_id': transfer_id,
                        'chunk_index': chunk_index,
                        'encrypted_chunk_data': encrypted_chunk.hex(),
                        'metadata': chunk_metadata,
                        'metadata_hmac': metadata_hmac.hex(),
                        'is_last_chunk': is_last_chunk,
                        'encryption': 'Blowfish-256-CBC',
                        'authentication': 'HMAC-SHA256'
                    }
                    
                    # Add retry logic for chunk sending
                    max_retries = 3
                    retry_count = 0
                    success = False
                    
                    while retry_count < max_retries and not success:
                        success = self.network_manager.send_message(
                            peer_id, 'file_chunk', chunk_message
                        )
                        
                        if not success:
                            retry_count += 1
                            if retry_count < max_retries:
                                print(f"Failed to send chunk {chunk_index}, retrying ({retry_count}/{max_retries})...")
                                time.sleep(0.1)  # 100ms delay before retry
                            else:
                                print(f"Failed to send chunk {chunk_index} after {max_retries} attempts")
                        else:
                            # Small delay between successful chunk sends to prevent overwhelming
                            time.sleep(0.05)  # 50ms delay
                    
                    if not success:
                        print("Failed to send file chunk")
                        break
                    
                    # Update progress
                    transfer_info['bytes_transferred'] += len(chunk)
                    
                    # Call progress callback if available
                    if transfer_id in self.transfer_callbacks:
                        callback = self.transfer_callbacks[transfer_id]
                        callback(transfer_info['bytes_transferred'], transfer_info['file_size'])
                    
                    chunk_index += 1
                    
                    if is_last_chunk:
                        break
            
            # Send completion notification
            complete_message = {
                'transfer_id': transfer_id,
                'success': True
            }
            
            self.network_manager.send_message(peer_id, 'file_complete', complete_message)
            print(f"📤 Sent completion notification for transfer: {transfer_id}")
            
            # Mark sender transfer as completed but don't cleanup immediately
            if transfer_id in self.active_transfers:
                self.active_transfers[transfer_id]['status'] = 'completed'
                self.active_transfers[transfer_id]['completion_time'] = time.time()
            
            # Schedule cleanup of sender transfers after a short delay
            def delayed_cleanup():
                time.sleep(2)  # Wait 2 seconds for receiver to process
                self.cleanup_sender_transfers()
            
            # Start cleanup in a separate thread
            import threading
            cleanup_thread = threading.Thread(target=delayed_cleanup, daemon=True)
            cleanup_thread.start()
            
        except Exception as e:
            print(f"Error sending file chunks: {e}")
            self._cleanup_transfer(transfer_id)
    
    def _assemble_and_save_file(self, transfer_id: str):
        """
        Assemble received chunks and save file.
        
        Args:
            transfer_id: Transfer identifier
        """
        print(f"🔧 _assemble_and_save_file called for transfer_id: {transfer_id}")
        try:
            if transfer_id not in self.active_transfers:
                print(f"❌ Transfer ID {transfer_id} not found in active transfers!")
                return False
                
            transfer_info = self.active_transfers[transfer_id]
            print(f"✅ Transfer info found: {list(transfer_info.keys())}")
            filename = transfer_info['filename']
            expected_hash = transfer_info['file_hash']
            chunks = transfer_info['chunks']
            
            # Sort chunks by index
            chunks.sort(key=lambda x: x[0])
            
            # Assemble file data
            file_data = b''.join(chunk[1] for chunk in chunks)
            
            # Verify file integrity using SHA-256 hash comparison
            calculated_hash = self.crypto_manager.calculate_data_hash(file_data)
            
            print(f"🔍 Verifying file integrity using SHA-256...")
            print(f"   Filename: {filename}")
            print(f"   File size: {len(file_data)} bytes")
            print(f"   Chunks assembled: {len(chunks)}")
            print(f"   Expected SHA-256: {expected_hash}")
            print(f"   Calculated SHA-256: {calculated_hash}")
            
            if calculated_hash != expected_hash:
                print("❌ File integrity check failed! File may be corrupted or tampered with.")
                print(f"   Saving anyway as partial file for debugging...")
                # Save with _partial suffix for debugging
                safe_filename = self._sanitize_filename(f"PARTIAL_{filename}")
                file_path = self.downloads_dir / safe_filename
                with open(file_path, 'wb') as f:
                    f.write(file_data)
                print(f"⚠️ Partial file saved for debugging: {file_path}")
                return False
            
            print("✅ File integrity verified - SHA-256 hashes match")
            
            # Save file
            print(f"💾 Preparing to save file...")
            safe_filename = self._sanitize_filename(filename)
            file_path = self.downloads_dir / safe_filename
            print(f"📁 Initial save path: {file_path}")
            
            # Ensure unique filename
            counter = 1
            original_path = file_path
            while file_path.exists():
                name = original_path.stem
                suffix = original_path.suffix
                file_path = original_path.parent / f"{name}_{counter}{suffix}"
                counter += 1
                print(f"📁 File exists, trying: {file_path}")
            
            print(f"💾 Writing file to: {file_path}")
            with open(file_path, 'wb') as f:
                f.write(file_data)
            print(f"✅ File write completed")
            
            # Sanitize image files
            if self._is_image_file(file_path):
                self._sanitize_image(file_path)
            
            print(f"💾 File saved successfully: {file_path}")
            print(f"📁 File location: {file_path.absolute()}")
            print(f"📊 Final file size: {file_path.stat().st_size} bytes")
            
            # Show completion notification
            if self.notification_manager:
                self.notification_manager.notify_file_complete(filename, True)
            
            # Notify sender of successful completion
            complete_message = {
                'transfer_id': transfer_id,
                'success': True
            }
            
            self.network_manager.send_message(
                transfer_info['peer_id'], 'file_complete', complete_message
            )
            
            # Cleanup transfer after successful assembly
            print(f"🧹 Cleaning up transfer after successful file save: {transfer_id}")
            self._cleanup_transfer(transfer_id)
            
            return True
            
        except Exception as e:
            print(f"Error assembling file: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _validate_file_for_sending(self, file_path: Path) -> bool:
        """
        Validate file before sending.
        
        Args:
            file_path: Path to the file
        
        Returns:
            True if file is valid for sending, False otherwise
        """
        try:
            if not file_path.exists():
                print("File does not exist")
                return False
            
            if not file_path.is_file():
                print("Path is not a file")
                return False
            
            if file_path.stat().st_size > self.max_file_size:
                print(f"File too large (max {self.max_file_size} bytes)")
                return False
            
            if file_path.suffix.lower() not in self.allowed_extensions:
                print(f"File type not allowed: {file_path.suffix}")
                return False
            
            return True
            
        except Exception as e:
            print(f"Error validating file: {e}")
            return False
    
    def _validate_incoming_file(self, filename: str, file_size: int, mime_type: str) -> bool:
        """
        Validate incoming file request.
        
        Args:
            filename: Incoming filename
            file_size: File size in bytes
            mime_type: MIME type
        
        Returns:
            True if file is acceptable, False otherwise
        """
        try:
            file_path = Path(filename)
            
            if file_size > self.max_file_size:
                return False
            
            if file_path.suffix.lower() not in self.allowed_extensions:
                return False
            
            return True
            
        except Exception as e:
            print(f"Error validating incoming file: {e}")
            return False
    
    def _sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename for safe storage.
        
        Args:
            filename: Original filename
        
        Returns:
            Sanitized filename
        """
        # Remove dangerous characters
        dangerous_chars = '<>:"/\\|?*'
        for char in dangerous_chars:
            filename = filename.replace(char, '_')
        
        # Limit length
        if len(filename) > 255:
            name = Path(filename).stem[:200]
            suffix = Path(filename).suffix
            filename = f"{name}{suffix}"
        
        return filename
    
    def _is_image_file(self, file_path: Path) -> bool:
        """
        Check if file is an image.
        
        Args:
            file_path: Path to the file
        
        Returns:
            True if file is an image, False otherwise
        """
        image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
        return file_path.suffix.lower() in image_extensions
    
    def _sanitize_image(self, file_path: Path):
        """
        Sanitize image file to remove potential malicious data.
        
        Args:
            file_path: Path to the image file
        """
        try:
            with Image.open(file_path) as img:
                # Create clean copy without metadata
                clean_img = Image.new(img.mode, img.size)
                clean_img.putdata(list(img.getdata()))
                
                # Save clean version
                clean_img.save(file_path)
                print(f"Image sanitized: {file_path.name}")
                
        except Exception as e:
            print(f"Failed to sanitize image {file_path.name}: {e}")
    
    def _cleanup_transfer(self, transfer_id: str):
        """
        Cleanup transfer resources.
        
        Args:
            transfer_id: Transfer identifier
        """
        if transfer_id in self.active_transfers:
            del self.active_transfers[transfer_id]
        
        if transfer_id in self.transfer_callbacks:
            del self.transfer_callbacks[transfer_id]
    
    def save_incomplete_transfers(self):
        """
        Save any incomplete transfers as partial files when connection is lost.
        This is called when the application is shutting down or connections are lost.
        """
        try:
            for transfer_id, transfer_info in list(self.active_transfers.items()):
                if 'chunks' in transfer_info and transfer_info['chunks']:
                    chunks_count = len(transfer_info['chunks'])
                    bytes_received = transfer_info.get('bytes_received', 0)
                    file_size = transfer_info.get('file_size', 0)
                    progress = (bytes_received / file_size) * 100 if file_size > 0 else 0
                    
                    if progress > 10:  # Only save if we have substantial data
                        print(f"💾 Saving incomplete transfer: {transfer_info['filename']} ({progress:.1f}% complete)")
                        
                        # Sort chunks by index
                        chunks = transfer_info['chunks']
                        chunks.sort(key=lambda x: x[0])
                        
                        # Assemble partial file data
                        file_data = b''.join(chunk[1] for chunk in chunks)
                        
                        # Save with INCOMPLETE prefix
                        filename = transfer_info['filename']
                        safe_filename = self._sanitize_filename(f"INCOMPLETE_{filename}")
                        file_path = Path(self.downloads_dir) / safe_filename
                        
                        # Ensure unique filename
                        counter = 1
                        original_path = file_path
                        while file_path.exists():
                            name = original_path.stem
                            suffix = original_path.suffix
                            file_path = original_path.parent / f"{name}_{counter}{suffix}"
                            counter += 1
                        
                        with open(file_path, 'wb') as f:
                            f.write(file_data)
                        
                        print(f"💾 Incomplete file saved: {file_path}")
                        print(f"📊 Saved {len(file_data)} bytes ({chunks_count} chunks)")
                        
        except Exception as e:
            print(f"Error saving incomplete transfers: {e}")
    
    def cleanup_stale_transfers(self, max_age_seconds: int = 300):
        """
        Clean up transfers that have been active too long (5 minutes default).
        This prevents memory leaks from abandoned transfers.
        
        Args:
            max_age_seconds: Maximum age in seconds before considering transfer stale
        """
        import time
        current_time = time.time()
        stale_transfers = []
        
        for transfer_id, transfer_info in self.active_transfers.items():
            # Check if transfer has a start time
            start_time = transfer_info.get('start_time', current_time)
            age = current_time - start_time
            
            if age > max_age_seconds:
                stale_transfers.append(transfer_id)
                print(f"🕰️ Found stale transfer: {transfer_id} (age: {age:.1f}s)")
        
        # Clean up stale transfers
        for transfer_id in stale_transfers:
            transfer_info = self.active_transfers.get(transfer_id, {})
            filename = transfer_info.get('filename', 'unknown')
            print(f"🧹 Cleaning up stale transfer: {filename} ({transfer_id})")
            self._cleanup_transfer(transfer_id)
        
        if stale_transfers:
            print(f"🧹 Cleaned up {len(stale_transfers)} stale transfers")
    
    def cleanup_sender_transfers(self):
        """
        Clean up completed sender transfers that are no longer needed.
        This should be called after sending completion notifications.
        """
        sender_transfers = []
        for transfer_id, transfer_info in self.active_transfers.items():
            if transfer_info.get('type') == 'send' and transfer_info.get('status') == 'completed':
                sender_transfers.append(transfer_id)
        
        for transfer_id in sender_transfers:
            print(f"🧹 Cleaning up completed sender transfer: {transfer_id}")
            self._cleanup_transfer(transfer_id)


class FileTransferError(Exception):
    """Custom exception for file transfer operations."""
    pass