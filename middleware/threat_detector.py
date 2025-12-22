from flask import request, g
from config import Config
import re
import logging

logger = logging.getLogger(__name__)

class ThreatDetectorMiddleware:
    def __init__(self, app):
        self.app = app
        self.init_middleware()

    def init_middleware(self):
        @self.app.before_request
        def detect_threats():
            # Skip threat detection for OPTIONS requests (CORS preflight)
            if request.method == 'OPTIONS':
                return

            if not Config.VULNERABLE_MODE:
                return

            # Basic threat detection patterns
            threats_detected = []

            # SQL Injection patterns
            sql_patterns = [
                r'union\s+select',
                r';\s*drop\s+table',
                r';\s*delete\s+from',
                r'--\s*$',
                r'/\*.*\*/'
            ]

            # XSS patterns
            xss_patterns = [
                r'<script[^>]*>.*?</script>',
                r'javascript:',
                r'on\w+\s*=',
                r'<iframe[^>]*>',
                r'<object[^>]*>'
            ]

            # Path traversal patterns
            path_patterns = [
                r'\.\./',
                r'\.\.\\',
                r'%2e%2e%2f',
                r'%2e%2e%5c'
            ]

            # Check URL path
            path = request.path.lower()
            query = request.query_string.decode('utf-8', errors='ignore').lower()

            # Check for SQL injection
            for pattern in sql_patterns:
                if re.search(pattern, path + query, re.IGNORECASE):
                    threats_detected.append('SQL_INJECTION')

            # Check for XSS
            for pattern in xss_patterns:
                if re.search(pattern, path + query, re.IGNORECASE):
                    threats_detected.append('XSS')

            # Check for path traversal
            for pattern in path_patterns:
                if re.search(pattern, path + query, re.IGNORECASE):
                    threats_detected.append('PATH_TRAVERSAL')

            # Check for suspicious user agents
            user_agent = request.headers.get('User-Agent', '').lower()
            suspicious_agents = ['sqlmap', 'nmap', 'nikto', 'dirbuster']
            for agent in suspicious_agents:
                if agent in user_agent:
                    threats_detected.append('SUSPICIOUS_USER_AGENT')

            # Store threats in global context
            g.threats_detected = threats_detected

            # Log threats if any detected
            if threats_detected:
                logger.warning('Threats detected in request', extra={
                    'threats': threats_detected,
                    'path': request.path,
                    'ip': request.remote_addr,
                    'user_agent': user_agent
                })

def get_detected_threats():
    """Get threats detected in current request"""
    return getattr(g, 'threats_detected', [])