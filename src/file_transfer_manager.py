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
        
        # Start periodic transfer completion check
        self._start_transfer_monitor()
    
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
            
            # Generate a unique receive transfer ID (don't overwrite the sender's ID)
            receive_transfer_id = f"receive_{peer_id}_{int(os.urandom(4).hex(), 16)}"
            
            # Store incoming transfer info with timestamp
            import time
            self.active_transfers[receive_transfer_id] = {
                'type': 'receive',
                'peer_id': peer_id,
                'filename': filename,
                'file_size': file_size,
                'file_hash': file_hash,
                'mime_type': mime_type,
                'bytes_received': 0,
                'chunks': [],
                'status': 'pending',
                'start_time': time.time(),
                'assembly_attempted': False,  # Prevent duplicate assembly attempts
                'file_saved': False,  # Track if file has been successfully saved
                'sender_transfer_id': transfer_id  # Keep reference to sender's transfer ID
            }
            

            
            # Notify application about incoming file
            print(f"Incoming file transfer: {filename} ({file_size} bytes)")
            
            # Show desktop notification
            if self.notification_manager:
                self.notification_manager.notify_file_request("Unknown User", filename, file_size)
            
            # Note: File acceptance is handled by GUI - no auto-accept here
            
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
                filename = transfer_info.get('file_path', Path('unknown')).name if hasattr(transfer_info.get('file_path', ''), 'name') else str(transfer_info.get('file_path', 'unknown'))
                print(f"File transfer accepted: {filename}")
                
                # Only start sending if this is a send transfer
                if transfer_info.get('type') == 'send':
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
            
            # Find the receive transfer that corresponds to this sender transfer ID
            receive_transfer_id = None
            for tid, tinfo in self.active_transfers.items():
                if (tinfo.get('type') == 'receive' and 
                    tinfo.get('sender_transfer_id') == transfer_id):
                    receive_transfer_id = tid
                    break
            
            if receive_transfer_id is None:
                # Only log this error occasionally to avoid spam
                import time
                current_time = time.time()
                if not hasattr(self, '_last_chunk_error_log'):
                    self._last_chunk_error_log = {}
                
                # Only log once per minute per transfer ID
                if (transfer_id not in self._last_chunk_error_log or 
                    current_time - self._last_chunk_error_log[transfer_id] > 60):
                    print(f"⚠️ No receive transfer found for sender transfer {transfer_id}")
                    self._last_chunk_error_log[transfer_id] = current_time
                return
            
            transfer_info = self.active_transfers[receive_transfer_id]
            
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
            
            # Check if we should attempt file assembly
            should_assemble = False
            
            if is_last_chunk:
                print(f"🏁 Last chunk received! Preparing to assemble and save file...")
                should_assemble = True
            elif progress >= 99.0 and transfer_info['bytes_received'] >= transfer_info['file_size']:
                print(f"⚠️ Transfer appears complete ({progress:.1f}%) - all bytes received. Attempting to save...")
                should_assemble = True
            
            # Only attempt assembly once and if not already saved
            if should_assemble and not transfer_info.get('assembly_attempted', False) and not transfer_info.get('file_saved', False):
                transfer_info['assembly_attempted'] = True
                print(f"🔍 Debug info before assembly:")
                print(f"   - Transfer ID: {transfer_id}")
                print(f"   - Filename: {transfer_info.get('filename', 'UNKNOWN')}")
                print(f"   - Total chunks: {len(transfer_info['chunks'])}")
                print(f"   - Bytes received: {transfer_info['bytes_received']}/{transfer_info['file_size']}")
                print(f"   - Downloads dir: {self.downloads_dir}")
                print(f"   - Downloads dir exists: {self.downloads_dir.exists()}")
                
                # Attempt to assemble and save file with integrity verification
                result = self._assemble_and_save_file(receive_transfer_id)
                print(f"🏁 File assembly result: {'SUCCESS' if result else 'FAILED'}")
                
                if result:
                    transfer_info['file_saved'] = True
                    transfer_info['status'] = 'completed'
                else:
                    # Reset flag to allow retry if needed
                    transfer_info['assembly_attempted'] = False
            elif transfer_info.get('file_saved', False):
                print(f"✅ File already saved successfully for transfer {transfer_id}")
                
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
            
            # Ensure file_path is a Path object
            if not isinstance(file_path, Path):
                file_path = Path(file_path)
            
            print(f"📤 Starting to send file: {file_path.name} ({transfer_info['file_size']} bytes)")
            
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
            
        Returns:
            bool: True if file was successfully assembled and saved, False otherwise
        """
        print(f"🔧 _assemble_and_save_file called for transfer_id: {transfer_id}")
        try:
            if transfer_id not in self.active_transfers:
                print(f"❌ Transfer ID {transfer_id} not found in active transfers!")
                return False
                
            transfer_info = self.active_transfers[transfer_id]
            print(f"✅ Transfer info found: {list(transfer_info.keys())}")
            
            # Check if already saved
            if transfer_info.get('file_saved', False):
                print(f"✅ File already saved for transfer {transfer_id}")
                return True
            
            filename = transfer_info['filename']
            expected_hash = transfer_info['file_hash']
            chunks = transfer_info['chunks']
            expected_size = transfer_info['file_size']
            
            # Validate we have chunks
            if not chunks:
                print(f"❌ No chunks received for transfer {transfer_id}")
                return False
            
            print(f"🔍 Starting file assembly...")
            print(f"   Filename: {filename}")
            print(f"   Expected size: {expected_size} bytes")
            print(f"   Chunks received: {len(chunks)}")
            print(f"   Expected SHA-256: {expected_hash}")
            
            # Sort chunks by index to ensure proper order
            chunks.sort(key=lambda x: x[0])
            print(f"📋 Chunks sorted by index: {[chunk[0] for chunk in chunks[:10]]}{'...' if len(chunks) > 10 else ''}")
            
            # Assemble file data
            file_data = b''.join(chunk[1] for chunk in chunks)
            actual_size = len(file_data)
            
            print(f"� File assembly stats:")
            print(f"   Assembled size: {actual_size} bytes")
            print(f"   Expected size: {expected_size} bytes")
            print(f"   Size match: {'✅' if actual_size == expected_size else '❌'}")
            
            # Verify file integrity using SHA-256 hash comparison
            calculated_hash = self.crypto_manager.calculate_data_hash(file_data)
            print(f"   Calculated SHA-256: {calculated_hash}")
            print(f"   Hash match: {'✅' if calculated_hash == expected_hash else '❌'}")
            
            # Handle hash mismatch
            if calculated_hash != expected_hash:
                print("❌ File integrity check failed! File may be corrupted or tampered with.")
                print(f"   Expected: {expected_hash}")
                print(f"   Got:      {calculated_hash}")
                print(f"   Saving as CORRUPTED file for debugging...")
                
                # Save with CORRUPTED prefix for debugging
                safe_filename = self._sanitize_filename(f"CORRUPTED_{filename}")
                file_path = self.downloads_dir / safe_filename
                
                # Ensure unique filename
                counter = 1
                original_path = file_path
                while file_path.exists():
                    name = original_path.stem
                    suffix = original_path.suffix
                    file_path = original_path.parent / f"{name}_{counter}{suffix}"
                    counter += 1
                
                try:
                    with open(file_path, 'wb') as f:
                        f.write(file_data)
                    print(f"⚠️ Corrupted file saved for debugging: {file_path}")
                    print(f"📊 Corrupted file size: {file_path.stat().st_size} bytes")
                except Exception as save_error:
                    print(f"❌ Failed to save corrupted file: {save_error}")
                
                return False
            
            print("✅ File integrity verified - SHA-256 hashes match")
            
            # Prepare to save file
            print(f"💾 Preparing to save verified file...")
            safe_filename = self._sanitize_filename(filename)
            file_path = self.downloads_dir / safe_filename
            print(f"📁 Target save path: {file_path}")
            
            # Ensure downloads directory exists
            self.downloads_dir.mkdir(parents=True, exist_ok=True)
            print(f"📁 Downloads directory: {self.downloads_dir.absolute()}")
            
            # Ensure unique filename
            counter = 1
            original_path = file_path
            while file_path.exists():
                name = original_path.stem
                suffix = original_path.suffix
                file_path = original_path.parent / f"{name}_{counter}{suffix}"
                counter += 1
                print(f"📁 File exists, trying: {file_path}")
            
            # Write file to disk
            print(f"💾 Writing {len(file_data)} bytes to: {file_path}")
            try:
                with open(file_path, 'wb') as f:
                    f.write(file_data)
                    f.flush()  # Ensure data is written to disk
                    os.fsync(f.fileno())  # Force OS to write to disk
                
                # Verify file was written correctly
                if not file_path.exists():
                    print(f"❌ File was not created: {file_path}")
                    return False
                
                written_size = file_path.stat().st_size
                if written_size != len(file_data):
                    print(f"❌ File size mismatch after write: expected {len(file_data)}, got {written_size}")
                    return False
                
                print(f"✅ File successfully written to disk: {file_path}")
                print(f"📊 Verified file size: {written_size} bytes")
                
                # Sanitize image files
                if self._is_image_file(file_path):
                    print(f"🖼️ Sanitizing image file...")
                    self._sanitize_image(file_path)
                
                print(f"🎉 File transfer completed successfully!")
                print(f"📁 Final location: {file_path.absolute()}")
                print(f"📊 Final file size: {file_path.stat().st_size} bytes")
                
                # Mark as saved in transfer info
                transfer_info['file_saved'] = True
                transfer_info['saved_path'] = str(file_path.absolute())
                transfer_info['completion_time'] = time.time()
                
                # Show completion notification
                if self.notification_manager:
                    self.notification_manager.notify_file_complete(filename, True)
                
                # Notify sender of successful completion
                complete_message = {
                    'transfer_id': transfer_id,
                    'success': True,
                    'file_saved': True
                }
                
                success = self.network_manager.send_message(
                    transfer_info['peer_id'], 'file_complete', complete_message
                )
                
                if success:
                    print(f"📤 Notified sender of successful completion")
                else:
                    print(f"⚠️ Failed to notify sender, but file was saved successfully")
                
                # Schedule cleanup after a short delay to ensure all processing is complete
                def delayed_cleanup():
                    time.sleep(1)  # Wait 1 second
                    if transfer_id in self.active_transfers:
                        print(f"🧹 Cleaning up completed transfer: {transfer_id}")
                        self._cleanup_transfer(transfer_id)
                
                import threading
                cleanup_thread = threading.Thread(target=delayed_cleanup, daemon=True)
                cleanup_thread.start()
                
                return True
                
            except Exception as write_error:
                print(f"❌ Failed to write file to disk: {write_error}")
                import traceback
                traceback.print_exc()
                return False
            
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
        orphaned_senders = []
        
        for transfer_id, transfer_info in self.active_transfers.items():
            # Check if transfer has a start time
            start_time = transfer_info.get('start_time', current_time)
            age = current_time - start_time
            
            # Mark as stale if too old
            if age > max_age_seconds:
                stale_transfers.append(transfer_id)
            
            # Check for orphaned sender transfers (no corresponding receive transfer)
            elif (transfer_info.get('type') == 'send' and 
                  transfer_info.get('status') == 'accepted' and 
                  age > 60):  # Give 1 minute for receive transfer to be created
                
                # Check if there's a corresponding receive transfer
                has_receive_transfer = any(
                    t.get('type') == 'receive' and t.get('sender_transfer_id') == transfer_id
                    for t in self.active_transfers.values()
                )
                
                if not has_receive_transfer:
                    orphaned_senders.append(transfer_id)
        
        # Clean up stale transfers
        for transfer_id in stale_transfers:
            transfer_info = self.active_transfers.get(transfer_id, {})
            filename = transfer_info.get('filename', transfer_info.get('file_path', {}).get('name', 'unknown'))
            if stale_transfers:
                print(f"🧹 Cleaning up stale transfer: {filename} ({transfer_id})")
            self._cleanup_transfer(transfer_id)
        
        # Clean up orphaned sender transfers
        for transfer_id in orphaned_senders:
            transfer_info = self.active_transfers.get(transfer_id, {})
            filename = transfer_info.get('file_path', {}).get('name', 'unknown')
            if orphaned_senders:
                print(f"🧹 Cleaning up orphaned sender transfer: {filename} ({transfer_id})")
            self._cleanup_transfer(transfer_id)
        
        total_cleaned = len(stale_transfers) + len(orphaned_senders)
        if total_cleaned > 0:
            print(f"🧹 Cleaned up {total_cleaned} transfers ({len(stale_transfers)} stale, {len(orphaned_senders)} orphaned)")
    
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
    
    def force_complete_pending_transfers(self):
        """
        Force completion of pending receive transfers that might be stuck.
        This checks for transfers that have received all expected bytes but haven't been saved.
        """
        # Only log if there are actually pending transfers
        pending_count = sum(1 for t in self.active_transfers.values() 
                          if t.get('type') == 'receive' and not t.get('file_saved', False))
        
        if pending_count > 0:
            print(f"🔍 Checking {pending_count} pending transfers for completion...")
        
        for transfer_id, transfer_info in list(self.active_transfers.items()):
            if (transfer_info.get('type') == 'receive' and 
                not transfer_info.get('file_saved', False) and
                not transfer_info.get('assembly_attempted', False)):
                
                bytes_received = transfer_info.get('bytes_received', 0)
                expected_size = transfer_info.get('file_size', 0)
                chunks_count = len(transfer_info.get('chunks', []))
                
                # Check if we have all the expected data
                if bytes_received >= expected_size and expected_size > 0 and chunks_count > 0:
                    print(f"🔧 Force-completing transfer {transfer_id}:")
                    print(f"   Filename: {transfer_info.get('filename', 'unknown')}")
                    print(f"   Bytes: {bytes_received}/{expected_size}")
                    print(f"   Chunks: {chunks_count}")
                    
                    # Mark as attempted and try to save
                    transfer_info['assembly_attempted'] = True
                    result = self._assemble_and_save_file(transfer_id)
                    
                    if result:
                        print(f"✅ Successfully force-completed transfer: {transfer_id}")
                    else:
                        print(f"❌ Failed to force-complete transfer: {transfer_id}")
                        # Reset flag to allow retry
                        transfer_info['assembly_attempted'] = False
    
    def get_transfer_statistics(self):
        """
        Get statistics about current transfers for debugging.
        """
        stats = {
            'total_transfers': len(self.active_transfers),
            'send_transfers': 0,
            'receive_transfers': 0,
            'completed_transfers': 0,
            'files_saved': 0,
            'pending_assembly': 0
        }
        
        for transfer_id, transfer_info in self.active_transfers.items():
            if transfer_info.get('type') == 'send':
                stats['send_transfers'] += 1
            elif transfer_info.get('type') == 'receive':
                stats['receive_transfers'] += 1
            
            if transfer_info.get('status') == 'completed':
                stats['completed_transfers'] += 1
            
            if transfer_info.get('file_saved', False):
                stats['files_saved'] += 1
            
            if (transfer_info.get('type') == 'receive' and 
                not transfer_info.get('file_saved', False) and
                len(transfer_info.get('chunks', [])) > 0):
                stats['pending_assembly'] += 1
        
        return stats
    
    def _start_transfer_monitor(self):
        """
        Start a background thread to monitor transfers and complete stuck ones.
        """
        def monitor_transfers():
            while True:
                try:
                    time.sleep(15)  # Check every 15 seconds instead of 5
                    
                    # Only run monitoring if there are active transfers
                    if self.active_transfers:
                        # Force complete any pending transfers
                        self.force_complete_pending_transfers()
                        
                        # Clean up stale transfers (older than 5 minutes)
                        self.cleanup_stale_transfers(max_age_seconds=300)
                        
                        # Print statistics only if there are issues
                        stats = self.get_transfer_statistics()
                        if stats['pending_assembly'] > 0 or stats['total_transfers'] > 10:
                            print(f"📊 Transfer stats: {stats['pending_assembly']} pending assembly, "
                                  f"{stats['files_saved']} files saved, {stats['total_transfers']} total")
                    
                except Exception as e:
                    print(f"Error in transfer monitor: {e}")
        
        # Start monitor thread
        monitor_thread = threading.Thread(target=monitor_transfers, daemon=True)
        monitor_thread.start()
        # Only print startup message in debug mode
        if self.config.get('debug.verbose_logging', False):
            print("🔄 Transfer monitor started")


class FileTransferError(Exception):
    """Custom exception for file transfer operations."""
    pass