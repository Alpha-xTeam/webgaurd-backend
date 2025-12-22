from flask import request, jsonify, g
from functools import wraps
import jwt
from config import Config

class AuthGuardMiddleware:
    def __init__(self, app):
        self.app = app
        self.init_middleware()

    def init_middleware(self):
        @self.app.before_request
        def check_auth():
            # Skip auth check for OPTIONS requests (CORS preflight)
            if request.method == 'OPTIONS':
                return

            # Skip auth check for certain endpoints
            public_endpoints = [
                '/',                 # Allow root access for SSRF demos
                '/api/status',
                '/api/register',
                '/api/login',
                '/api/logout',
                '/api/create-admin',
                '/api/admin/users',  # VULNERABILITY: IDOR - Admin endpoint exposed without auth
                '/api/alerts/soc',   # Allow SOC alerts from frontend vulnerabilities
                '/api/logs/security', # Allow security logging from frontend
                '/api/logs/seed',      # Allow seeding logs without auth
                '/api/attacker/capture', # Allow XSS data exfiltration
                '/api/attacker/not-found', # Allow vulnerable endpoints
                '/api/attacker/profile',
                '/api/attacker/gallery',
                '/api/attacker/fetch',
                '/api/attacker/parse-xml',
                '/api/attacker/redirect',
                '/api/attacker/process'
            ]

            if request.path in public_endpoints or \
               request.path.startswith('/api/vulnerable/') or \
               request.path.startswith('/api/attacker/') or \
               request.path == '/api/system-info':  # For SSRF demo
                return

            # Check for authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Missing or invalid authorization header'}), 401

            token = auth_header.split(' ')[1]
            try:
                payload = jwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])
                g.user_id = payload.get('user_id')
                g.user_email = payload.get('email')
                g.user_role = payload.get('role')
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token has expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401

def require_role(role):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'user_role') or g.user_role != role:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not hasattr(g, 'user_id'):
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function