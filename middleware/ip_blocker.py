from flask import request, jsonify
from integrations.supabase import supabase
from utils.request_utils import get_request_ip
import logging

logger = logging.getLogger(__name__)

class IPBlockerMiddleware:
    def __init__(self, app):
        self.app = app
        self.init_middleware()

    def init_middleware(self):
        @self.app.before_request
        def check_ip_block():
            if request.method == 'OPTIONS':
                return

            # Skip block check for local dev if needed, or allow it for testing
            # client_ip = get_request_ip()
            
            # For this educational app, we want to see the block working even on localhost
            client_ip = get_request_ip()
            
            # Check if IP is in blocked_ips table
            try:
                # Query Supabase for this IP
                result = supabase.table('blocked_ips').select('*').eq('ip_address', client_ip).execute()
                
                if result.data and len(result.data) > 0:
                    block_info = result.data[0]
                    return jsonify({
                        "error": "Forbidden",
                        "message": "عذراً، تم حظر عنوان الـ IP الخاص بك من الوصول إلى هذا الموقع لأسباب أمنية.",
                        "reason": block_info.get('reason', 'Security threat detected'),
                        "blocked_at": block_info.get('blocked_at'),
                        "ip": client_ip,
                        "status": "blocked"
                    }), 403
            except Exception as e:
                # Log error but don't stop the request
                print(f"IP Blocker Middleware Error: {e}")
                pass
