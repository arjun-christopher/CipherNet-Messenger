"""
Cleanup module to remove old accepted chat requests from Firebase.
"""

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