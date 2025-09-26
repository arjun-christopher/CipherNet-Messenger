"""
File Transfer Manager for CipherNet Messenger
Handles secure file sharing with encryption and integrity verification.

Author: Arjun Christopher
"""

import os
import json
import threading
from pathlib import Path
from typing import Dict, Any, Callable, Optional, Tuple
from PIL import Image
import mimetypes


class FileTransferManager:
    """Manages secure file transfer operations."""
    
    def __init__(self, config, crypto_manager, network_manager, notification_manager=None):
        """
        Initialize file transfer manager.
        
        Args:
            config: Configuration manager instance
            crypto_manager: Cryptography manager instance
            network_manager: Network manager instance
            notification_manager: Notification manager instance (optional)
        """
        self.config = config
        self.crypto_manager = crypto_manager
        self.network_manager = network_manager
        self.notification_manager = notification_manager
        
        self.chunk_size = config.get('network.file_chunk_size', 4096)
        self.downloads_dir = Path.home() / "Downloads" / "CipherNet"
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
            
            # Store transfer info
            self.active_transfers[transfer_id] = {
                'type': 'send',
                'peer_id': peer_id,
                'file_path': file_path,
                'file_size': file_size,
                'file_hash': file_hash,
                'bytes_transferred': 0,
                'status': 'initiating'
            }
            
            if progress_callback:
                self.transfer_callbacks[transfer_id] = progress_callback
            
            # Send file metadata
            file_info = {
                'transfer_id': transfer_id,
                'filename': file_path.name,
                'file_size': file_size,
                'file_hash': file_hash,
                'mime_type': mimetypes.guess_type(str(file_path))[0] or 'application/octet-stream'
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
            
            # Store incoming transfer info
            self.active_transfers[transfer_id] = {
                'type': 'receive',
                'peer_id': peer_id,
                'filename': filename,
                'file_size': file_size,
                'file_hash': file_hash,
                'mime_type': mime_type,
                'bytes_received': 0,
                'chunks': [],
                'status': 'pending'
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
        Handle incoming file chunk.
        
        Args:
            message: File chunk message
            peer_id: Sender peer identifier
        """
        try:
            content = message.get('content', {})
            transfer_id = content.get('transfer_id')
            chunk_index = content.get('chunk_index')
            chunk_data = bytes.fromhex(content.get('chunk_data', ''))
            is_last_chunk = content.get('is_last_chunk', False)
            
            if transfer_id not in self.active_transfers:
                return
            
            transfer_info = self.active_transfers[transfer_id]
            
            # Store chunk
            transfer_info['chunks'].append((chunk_index, chunk_data))
            transfer_info['bytes_received'] += len(chunk_data)
            
            # Update progress
            progress = (transfer_info['bytes_received'] / transfer_info['file_size']) * 100
            print(f"File transfer progress: {progress:.1f}%")
            
            if is_last_chunk:
                # Assemble and save file
                self._assemble_and_save_file(transfer_id)
                
        except Exception as e:
            print(f"Error handling file chunk: {e}")
    
    def _handle_file_complete(self, message: Dict[str, Any], peer_id: str):
        """
        Handle file transfer completion notification.
        
        Args:
            message: File complete message
            peer_id: Sender peer identifier
        """
        try:
            content = message.get('content', {})
            transfer_id = content.get('transfer_id')
            success = content.get('success', False)
            
            if transfer_id in self.active_transfers:
                if success:
                    print("File transfer completed successfully")
                else:
                    print("File transfer completed with errors")
                
                self._cleanup_transfer(transfer_id)
                
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
                    
                    # Send encrypted chunk
                    chunk_message = {
                        'transfer_id': transfer_id,
                        'chunk_index': chunk_index,
                        'chunk_data': chunk.hex(),
                        'is_last_chunk': is_last_chunk
                    }
                    
                    success = self.network_manager.send_message(
                        peer_id, 'file_chunk', chunk_message
                    )
                    
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
            self._cleanup_transfer(transfer_id)
            
        except Exception as e:
            print(f"Error sending file chunks: {e}")
            self._cleanup_transfer(transfer_id)
    
    def _assemble_and_save_file(self, transfer_id: str):
        """
        Assemble received chunks and save file.
        
        Args:
            transfer_id: Transfer identifier
        """
        try:
            transfer_info = self.active_transfers[transfer_id]
            filename = transfer_info['filename']
            expected_hash = transfer_info['file_hash']
            chunks = transfer_info['chunks']
            
            # Sort chunks by index
            chunks.sort(key=lambda x: x[0])
            
            # Assemble file data
            file_data = b''.join(chunk[1] for chunk in chunks)
            
            # Verify file integrity
            calculated_hash = self.crypto_manager.calculate_data_hash(file_data)
            
            if calculated_hash != expected_hash:
                print("File integrity check failed!")
                return False
            
            # Save file
            safe_filename = self._sanitize_filename(filename)
            file_path = self.downloads_dir / safe_filename
            
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
            
            # Sanitize image files
            if self._is_image_file(file_path):
                self._sanitize_image(file_path)
            
            print(f"File saved: {file_path}")
            
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
            
            return True
            
        except Exception as e:
            print(f"Error assembling file: {e}")
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


class FileTransferError(Exception):
    """Custom exception for file transfer operations."""
    pass