import re
import os
from config import Config

def validate_email(email):
    """Validate email format"""
    if not email or not isinstance(email, str):
        return False

    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email.strip()) is not None

def validate_password(password):
    """Validate password strength"""
    if not password or not isinstance(password, str):
        return False

    # Minimum requirements
    min_length = 8
    if len(password) < min_length:
        return False

    # Check for at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return False

    # Check for at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return False

    # Check for at least one digit
    if not re.search(r'\d', password):
        return False

    # Check for at least one special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False

    return True

def validate_username(username):
    """Validate username format"""
    if not username or not isinstance(username, str):
        return False

    # Allow alphanumeric characters, underscores, and hyphens
    # Length between 3-30 characters
    pattern = r'^[a-zA-Z0-9_-]{3,30}$'
    return re.match(pattern, username.strip()) is not None

def validate_file_extension(filename, allowed_extensions=None):
    """Validate file extension"""
    if not filename or not isinstance(filename, str):
        return False

    if allowed_extensions is None:
        allowed_extensions = Config.ALLOWED_EXTENSIONS

    if '.' not in filename:
        return False

    extension = filename.rsplit('.', 1)[1].lower()
    return extension in allowed_extensions

def validate_file_size(file_size, max_size=None):
    """Validate file size"""
    if max_size is None:
        max_size = Config.MAX_CONTENT_LENGTH

    return isinstance(file_size, int) and 0 < file_size <= max_size

def validate_url(url):
    """Validate URL format"""
    if not url or not isinstance(url, str):
        return False

    # Basic URL pattern
    pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    return re.match(pattern, url.strip()) is not None

def validate_ip_address(ip):
    """Validate IP address format"""
    if not ip or not isinstance(ip, str):
        return False

    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, ip):
        # Check if each octet is between 0-255
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)

    return False

def validate_sql_input(input_string):
    """Check for potential SQL injection patterns"""
    if not input_string or not isinstance(input_string, str):
        return True  # Empty input is safe

    # Common SQL injection patterns
    dangerous_patterns = [
        r';\s*drop\s+table',
        r';\s*delete\s+from',
        r'union\s+select',
        r';\s*exec',
        r';\s*execute',
        r'--\s*$',
        r'/\*.*\*/',
        r';\s*shutdown'
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return False

    return True

def validate_xss_input(input_string):
    """Check for potential XSS patterns"""
    if not input_string or not isinstance(input_string, str):
        return True  # Empty input is safe

    # Common XSS patterns
    dangerous_patterns = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe[^>]*>',
        r'<object[^>]*>',
        r'<embed[^>]*>',
        r'vbscript:',
        r'data:text/html'
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return False

    return True

def sanitize_filename(filename):
    """Sanitize filename to prevent path traversal"""
    if not filename or not isinstance(filename, str):
        return None

    # Remove path separators
    filename = filename.replace('/', '').replace('\\', '')

    # Remove dangerous characters
    filename = re.sub(r'[<>:"|?*]', '', filename)

    # Ensure filename is not empty and doesn't start with dot
    if not filename or filename.startswith('.'):
        filename = 'file_' + filename.lstrip('.')

    return filename

def validate_uuid(uuid_string):
    """Validate UUID format"""
    if not uuid_string or not isinstance(uuid_string, str):
        return False

    pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    return re.match(pattern, uuid_string.lower()) is not None