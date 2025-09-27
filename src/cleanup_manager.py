"""
Cleanup module to remove stale data from Firebase on application exit.
"""

import time

def comprehensive_cleanup(auth_manager, firebase_manager, silent=True):
    """
    Comprehensive cleanup of all stale Firebase data on application exit.
    
    Args:
        auth_manager: AuthManager instance  
        firebase_manager: FirebaseManager instance
        silent: If True, suppress output messages
    
    Returns:
        dict: Cleanup statistics
    """
    try:
        if not silent:
            print("🧹 Performing comprehensive cleanup before exit...")
        
        current_user = auth_manager.get_current_user()
        if not current_user:
            if not silent:
                print("❌ No user logged in for cleanup")
            return {"total_cleaned": 0}
        
        current_uid = current_user['uid']
        stats = {
            "accepted_requests": 0,
            "pending_requests": 0, 
            "stale_chats": 0,
            "own_presence": 0,
            "total_cleaned": 0
        }
        
        # 1. Clean up all accepted requests (sent by current user)
        if not silent:
            print("  🗑️  Cleaning accepted requests...")
        stats["accepted_requests"] = _cleanup_accepted_requests(firebase_manager, current_uid, silent)
        
        # 2. Clean up old pending requests (older than 24 hours)
        if not silent:
            print("  🗑️  Cleaning stale pending requests...")
        stats["pending_requests"] = _cleanup_stale_pending_requests(firebase_manager, current_uid, silent)
        
        # 3. Clean up inactive chat sessions (no activity for 7 days)
        if not silent:
            print("  🗑️  Cleaning inactive chat sessions...")
        stats["stale_chats"] = _cleanup_inactive_chats(firebase_manager, current_uid, silent)
        
        # 4. Remove own presence from lobby (user is logging out)
        if not silent:
            print("  🗑️  Removing presence from lobby...")
        stats["own_presence"] = _cleanup_own_presence(firebase_manager, current_uid, silent)
        
        stats["total_cleaned"] = sum(stats.values()) - stats["total_cleaned"]  # Exclude self-reference
        
        if not silent:
            print(f"🎉 Cleanup complete! Removed {stats['total_cleaned']} items:")
            print(f"  - Accepted requests: {stats['accepted_requests']}")
            print(f"  - Stale pending requests: {stats['pending_requests']}")
            print(f"  - Inactive chats: {stats['stale_chats']}")
            print(f"  - Own presence: {stats['own_presence']}")
        
        return stats
        
    except Exception as e:
        if not silent:
            print(f"❌ Cleanup failed: {e}")
            import traceback
            traceback.print_exc()
        return {"total_cleaned": 0}


def _cleanup_accepted_requests(firebase_manager, current_uid, silent):
    """Clean up all accepted requests sent by current user."""
    cleaned_count = 0
    try:
        accepted_requests = firebase_manager.check_sent_requests_responses()
        
        for request in accepted_requests:
            request_id = request.get('request_id')
            target_uid = request.get('target_uid')
            request_path = f"requests/{target_uid}/{request_id}"
            
            if firebase_manager._delete_data(request_path):
                cleaned_count += 1
                if not silent:
                    print(f"    ✅ Deleted accepted request: {request_id}")
    except Exception as e:
        if not silent:
            print(f"    ❌ Error cleaning accepted requests: {e}")
    
    return cleaned_count


def _cleanup_stale_pending_requests(firebase_manager, current_uid, silent):
    """Clean up pending requests older than 24 hours."""
    cleaned_count = 0
    try:
        current_time = int(time.time() * 1000)
        stale_threshold = 24 * 60 * 60 * 1000  # 24 hours in milliseconds
        
        # Check requests TO current user
        requests_path = f"requests/{current_uid}"
        user_requests = firebase_manager._read_data(requests_path)
        
        if user_requests:
            for request_id, request_data in user_requests.items():
                if isinstance(request_data, dict):
                    request_time = request_data.get('timestamp', 0)
                    status = request_data.get('status', 'pending')
                    
                    # Delete if older than 24 hours and still pending
                    if (status == 'pending' and 
                        current_time - request_time > stale_threshold):
                        
                        request_path = f"requests/{current_uid}/{request_id}"
                        if firebase_manager._delete_data(request_path):
                            cleaned_count += 1
                            if not silent:
                                print(f"    ✅ Deleted stale request: {request_id}")
    
    except Exception as e:
        if not silent:
            print(f"    ❌ Error cleaning stale requests: {e}")
    
    return cleaned_count


def _cleanup_inactive_chats(firebase_manager, current_uid, silent):
    """Clean up chat sessions with no activity for 7 days."""
    cleaned_count = 0
    try:
        current_time = int(time.time() * 1000)
        inactive_threshold = 7 * 24 * 60 * 60 * 1000  # 7 days in milliseconds
        
        # Read all chats
        chats_data = firebase_manager._read_data("chats")
        
        if chats_data:
            for chat_id, chat_data in chats_data.items():
                if isinstance(chat_data, dict):
                    participants = chat_data.get('participants', {})
                    
                    # Only clean chats involving current user
                    if current_uid in participants:
                        created_at = chat_data.get('created_at', 0)
                        last_activity = chat_data.get('last_activity', created_at)
                        
                        # Delete if inactive for more than 7 days
                        if current_time - last_activity > inactive_threshold:
                            chat_path = f"chats/{chat_id}"
                            if firebase_manager._delete_data(chat_path):
                                cleaned_count += 1
                                if not silent:
                                    print(f"    ✅ Deleted inactive chat: {chat_id}")
    
    except Exception as e:
        if not silent:
            print(f"    ❌ Error cleaning inactive chats: {e}")
    
    return cleaned_count


def _cleanup_own_presence(firebase_manager, current_uid, silent):
    """Remove current user's presence from lobby."""
    try:
        presence_path = f"lobby/{current_uid}"
        if firebase_manager._delete_data(presence_path):
            if not silent:
                print(f"    ✅ Removed presence from lobby")
            return 1
    except Exception as e:
        if not silent:
            print(f"    ❌ Error removing presence: {e}")
    
    return 0


def cleanup_old_requests(auth_manager, firebase_manager, silent=True):
    """
    Clean up old accepted chat requests.
    
    Args:
        auth_manager: AuthManager instance
        firebase_manager: FirebaseManager instance
        silent: If True, suppress output messages
    
    Returns:
        int: Number of requests cleaned up
    """
    try:
        if not silent:
            print("🧹 Cleaning up old chat requests...")
        
        current_user = auth_manager.get_current_user()
        if not current_user:
            if not silent:
                print("❌ No user logged in for cleanup")
            return 0
        
        # Get all accepted requests
        accepted_requests = firebase_manager.check_sent_requests_responses()
        
        if not silent and accepted_requests:
            print(f"Found {len(accepted_requests)} old accepted requests to clean up")
        
        cleaned_count = 0
        for request in accepted_requests:
            request_id = request.get('request_id')
            target_uid = request.get('target_uid')
            target_email = request.get('target_email')
            
            # Delete the request
            request_path = f"requests/{target_uid}/{request_id}"
            success = firebase_manager._delete_data(request_path)
            
            if success:
                if not silent:
                    print(f"  ✅ Deleted: {request_id} (to {target_email})")
                cleaned_count += 1
            else:
                if not silent:
                    print(f"  ❌ Failed to delete: {request_id}")
        
        if not silent and cleaned_count > 0:
            print(f"🎉 Cleanup complete! Removed {cleaned_count} old requests.")
        
        return cleaned_count
        
    except Exception as e:
        if not silent:
            print(f"❌ Cleanup failed: {e}")
            import traceback
            traceback.print_exc()
        return 0


def cleanup_old_requests_standalone():
    """Standalone cleanup function for direct execution."""
    import sys
    from pathlib import Path
    
    # Add src directory to path if running standalone
    if __name__ == "__main__":
        sys.path.append(str(Path(__file__).parent))
    
    try:
        from config import Config
        from auth_manager import AuthManager
        from firebase_manager import FirebaseManager
        
        print("🧹 Running standalone cleanup...")
        
        # Initialize components
        config = Config()
        auth_manager = AuthManager(config)
        firebase_manager = FirebaseManager(config, auth_manager)
        
        # Login
        success, message = auth_manager.login_user("abc@gmail.com", "123456")
        if not success:
            print(f"❌ Login failed: {message}")
            return
        
        current_user = auth_manager.get_current_user()
        print(f"✅ Logged in as: {current_user['email']}")
        
        # Run cleanup
        cleaned_count = cleanup_old_requests(auth_manager, firebase_manager, silent=False)
        
        if cleaned_count == 0:
            print("✨ No old requests found to clean up.")
        
    except Exception as e:
        print(f"❌ Standalone cleanup failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    cleanup_old_requests_standalone()