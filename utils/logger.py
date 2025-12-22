import logging
import logging.handlers
import os
import json
from datetime import datetime
from config import Config

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""

    def format(self, record):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }

        # Add extra fields if present
        if hasattr(record, 'extra_fields'):
            log_entry.update(record.extra_fields)

        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)

        return json.dumps(log_entry)

class SecurityLogger:
    """Security-focused logger for WebGuard-IR"""

    def __init__(self):
        self.logger = logging.getLogger('webguard_security')
        self.logger.setLevel(getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO))

        # Remove existing handlers to avoid duplicates
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)

        # Console handler REMOVED to suppress output
        # console_handler = logging.StreamHandler()
        # console_handler.setFormatter(JSONFormatter())
        # self.logger.addHandler(console_handler)

        # File handler for security events
        if not os.path.exists('logs'):
            os.makedirs('logs')

        file_handler = logging.handlers.RotatingFileHandler(
            'logs/security.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(JSONFormatter())
        file_handler.setLevel(logging.WARNING)  # Only warnings and above to file
        self.logger.addHandler(file_handler)

    def log_request(self, method, path, status_code, user_id=None, ip=None, user_agent=None, duration=None):
        """Log HTTP request"""
        extra_fields = {
            'event_type': 'http_request',
            'method': method,
            'path': path,
            'status_code': status_code,
            'user_id': user_id,
            'ip_address': ip,
            'user_agent': user_agent,
            'duration_ms': duration
        }

        if status_code >= 400:
            self.logger.warning(f'HTTP {status_code}: {method} {path}', extra={'extra_fields': extra_fields})
        else:
            self.logger.info(f'HTTP {status_code}: {method} {path}', extra={'extra_fields': extra_fields})

    def log_auth_event(self, event_type, user_email=None, user_id=None, ip=None, success=True):
        """Log authentication events"""
        extra_fields = {
            'event_type': 'auth',
            'auth_event': event_type,
            'user_email': user_email,
            'user_id': user_id,
            'ip_address': ip,
            'success': success
        }

        if success:
            self.logger.info(f'Auth {event_type}: {user_email or "unknown"}', extra={'extra_fields': extra_fields})
        else:
            self.logger.warning(f'Auth {event_type} failed: {user_email or "unknown"}', extra={'extra_fields': extra_fields})

    def log_security_event(self, event_type, severity='medium', details=None, user_id=None, ip=None):
        """Log security events (threats, vulnerabilities, etc.)"""
        extra_fields = {
            'event_type': 'security',
            'security_event': event_type,
            'severity': severity,
            'details': details or {},
            'user_id': user_id,
            'ip_address': ip
        }

        severity_levels = {
            'low': logging.INFO,
            'medium': logging.WARNING,
            'high': logging.ERROR,
            'critical': logging.CRITICAL
        }

        level = severity_levels.get(severity.lower(), logging.WARNING)
        self.logger.log(level, f'Security event: {event_type}', extra={'extra_fields': extra_fields})

    def log_vulnerable_access(self, vulnerability_type, details=None, user_id=None, ip=None):
        """Log access to vulnerable endpoints"""
        self.log_security_event(
            'vulnerable_endpoint_access',
            severity='high',
            details={'vulnerability': vulnerability_type, **(details or {})},
            user_id=user_id,
            ip=ip
        )

    def log_file_upload(self, filename, file_size, mime_type, user_id=None, ip=None):
        """Log file upload events"""
        extra_fields = {
            'event_type': 'file_upload',
            'filename': filename,
            'file_size': file_size,
            'mime_type': mime_type,
            'user_id': user_id,
            'ip_address': ip
        }

        self.logger.info(f'File uploaded: {filename}', extra={'extra_fields': extra_fields})

    def log_incident_response(self, incident_id, action, user_id=None, details=None):
        """Log incident response actions"""
        extra_fields = {
            'event_type': 'incident_response',
            'incident_id': incident_id,
            'action': action,
            'user_id': user_id,
            'details': details or {}
        }

        self.logger.info(f'Incident response: {action} on {incident_id}', extra={'extra_fields': extra_fields})

# Global security logger instance
security_logger = SecurityLogger()

def get_security_logger():
    """Get the global security logger instance"""
    return security_logger

def setup_logger(name, level=None):
    """Setup a logger with JSON formatting"""
    logger = logging.getLogger(name)
    if level:
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Avoid duplicate handlers
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)

    return logger

def get_logger(name):
    """Get or create a logger"""
    return logging.getLogger(name)