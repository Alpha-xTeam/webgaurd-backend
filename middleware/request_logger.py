import logging
import socket
import time
from pythonjsonlogger import jsonlogger
from flask import request, g
from config import Config
from utils.logger import get_security_logger

# Root logger configuration removed to suppress console output
# logger = logging.getLogger()
# logger.setLevel(logging.INFO)

formatter = jsonlogger.JsonFormatter()

# Logstash handler
class LogstashHandler(logging.Handler):
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port

    def emit(self, record):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))
            log_entry = self.format(record)
            sock.sendall(log_entry.encode('utf-8') + b'\n')
            sock.close()
        except Exception:
            pass  # Ignore errors in logging

# Only add logstash handler if needed, but don't add console handler
# logstash_handler = LogstashHandler(Config.LOGSTASH_HOST, Config.LOGSTASH_PORT)
# logstash_handler.setFormatter(formatter)
# logger.addHandler(logstash_handler)

class RequestLoggerMiddleware:
    def __init__(self, app):
        self.app = app
        self.security_logger = get_security_logger()
        self.init_middleware()

    def init_middleware(self):
        @self.app.before_request
        def log_request_start():
            g.start_time = time.time()
            g.request_logged = False

        @self.app.after_request
        def log_request_end(response):
            if hasattr(g, 'request_logged') and g.request_logged:
                return response

            duration = time.time() - getattr(g, 'start_time', time.time())
            duration_ms = round(duration * 1000, 2)

            # Get user info if available
            user_id = getattr(g, 'user_id', None)
            user_email = getattr(g, 'user_email', None)

            # Log using security logger
            self.security_logger.log_request(
                method=request.method,
                path=request.path,
                status_code=response.status_code,
                user_id=user_id,
                ip=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                duration=duration_ms
            )

            # Mark as logged
            g.request_logged = True

            return response

def log_request(endpoint, data):
    """Legacy function for backward compatibility"""
    security_logger = get_security_logger()
    security_logger.log_vulnerable_access(
        vulnerability_type=endpoint,
        details=data,
        ip=request.remote_addr
    )