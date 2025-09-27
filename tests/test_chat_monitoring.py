#!/usr/bin/env python3
"""
Test script to simulate chat request acceptance and verify monitoring works.
"""

import sys
from pathlib import Path

# Add src directory to path
sys.path.append(str(Path(__file__).parent.parent / "src"))

def test_chat_monitoring():
    """Test the chat request monitoring system."""
    try:
        from config import Config
        from auth_manager import AuthManager
        from firebase_manager import FirebaseManager
        
        print("🔧 Testing chat request monitoring...")
        
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
        
        # Check for accepted requests
        print("\n📝 Checking for accepted chat requests...")
        accepted_requests = firebase_manager.check_sent_requests_responses()
        
        print(f"Found {len(accepted_requests)} accepted requests:")
        for request in accepted_requests:
            print(f"  - Request ID: {request['request_id']}")
            print(f"  - Target: {request['target_email']}")
            print(f"  - Chat ID: {request['chat_id']}")
            
            chat_info = request.get('chat_info', {})
            participants = chat_info.get('participants', {})
            
            print(f"  - Chat participants:")
            for uid, participant in participants.items():
                email = participant.get('email', 'Unknown')
                ip = participant.get('ip', 'N/A')
                port = participant.get('port', 'N/A')
                print(f"    * {email}: {ip}:{port}")
            print()
        
        if not accepted_requests:
            print("  No accepted requests found.")
            
            # Let's check if there are any requests at all
            print("\n🔍 Checking all requests in database...")
            lobby_data = firebase_manager._read_data("lobby")
            
            if lobby_data:
                for user_uid in lobby_data.keys():
                    if user_uid == current_user['uid']:
                        continue
                    
                    requests_path = f"requests/{user_uid}"
                    user_requests = firebase_manager._read_data(requests_path)
                    
                    if user_requests:
                        print(f"  Requests for user {user_uid}:")
                        for request_id, request_data in user_requests.items():
                            if isinstance(request_data, dict):
                                from_uid = request_data.get('from_uid')
                                status = request_data.get('status', 'unknown')
                                from_email = request_data.get('from_email', 'unknown')
                                print(f"    - {request_id}: from {from_email} ({from_uid}) - {status}")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_chat_monitoring()