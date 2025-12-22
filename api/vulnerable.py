from flask import Blueprint, request, jsonify, send_file, redirect
import os
import logging
import pickle
import xml.etree.ElementTree as ET
from config import Config
from models.alert import create_alert
from utils.request_utils import get_request_ip

api_bp = Blueprint('vulnerable', __name__)

# Setup logging
logger = logging.getLogger(__name__)

def log_vulnerable_request(endpoint, data):
    """Log vulnerable endpoint access and notify SOC team"""
    client_ip = get_request_ip()
    # Log to application logger
    logger.warning(f'Vulnerable endpoint accessed: {endpoint}', extra={
        'endpoint': endpoint,
        'data': data,
        'ip': client_ip,
        'user_agent': request.headers.get('User-Agent')
    })

    # Create alert for SOC team
    try:
        message = f"Security Alert: Vulnerable '{endpoint}' endpoint accessed by {client_ip}"
        if endpoint == 'upload':
            filename = data.get('filename', 'unknown')
            message = f"CRITICAL: Unrestricted File Upload detected! File: {filename} uploaded from {client_ip}"
        
        create_alert(
            message=message,
            severity='high',
            source='vulnerable_api'
        )
    except Exception as e:
        logger.error(f"Failed to create SOC alert: {e}")

# ============ PERSISTENT PATCH STATUS ============
# File path for storing patch status
import json
PATCH_STATUS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'patch_status.json')

# Default status (all vulnerabilities open by default)
DEFAULT_PATCH_STATUS = {
    'download': False,      # Path Traversal (File Download)
    'ssrf': False,          # SSRF
    'upload': False,        # Unrestricted File Upload
    'path_traversal': False, # Path Traversal (File Read)
    'xss': False,           # XSS
    'sqli': False,          # SQL Injection
    'xxe': False,           # XXE
    'deserialization': False, # Insecure Deserialization
    'open_redirect': False, # Open Redirect
    'idor': False,          # IDOR
    'rce': False,           # RCE
    'system_info': False    # Info Disclosure
}

def load_patch_status():
    """Load patch status from JSON file, or return defaults if file doesn't exist"""
    try:
        if os.path.exists(PATCH_STATUS_FILE):
            with open(PATCH_STATUS_FILE, 'r') as f:
                loaded = json.load(f)
                # Merge with defaults to handle any new vulnerabilities added later
                merged = DEFAULT_PATCH_STATUS.copy()
                merged.update(loaded)
                return merged
    except Exception as e:
        logger.error(f"Failed to load patch status: {e}")
    return DEFAULT_PATCH_STATUS.copy()

def save_patch_status():
    """Save current patch status to JSON file"""
    try:
        os.makedirs(os.path.dirname(PATCH_STATUS_FILE), exist_ok=True)
        with open(PATCH_STATUS_FILE, 'w') as f:
            json.dump(PATCH_STATUS, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Failed to save patch status: {e}")
        return False

try:
    PATCH_STATUS = load_patch_status()
except Exception as e:
    logger.error(f"Failed to initialize PATCH_STATUS: {e}")
    PATCH_STATUS = DEFAULT_PATCH_STATUS.copy()

def check_patch(vuln_type):
    """Check if a vulnerability is patched"""
    if PATCH_STATUS.get(vuln_type, False):
        return True
    return False

@api_bp.route('/vulnerable/status', methods=['GET'])
def get_patch_status():
    """Get status of all vulnerabilities"""
    return jsonify(PATCH_STATUS), 200

@api_bp.route('/vulnerable/patch', methods=['POST'])
def patch_vulnerability():
    """Toggle patch status for a vulnerability (PERSISTENT)"""
    global PATCH_STATUS
    data = request.get_json()
    vuln_type = data.get('vuln_type')
    action = data.get('action') # 'patch' or 'unpatch'
    
    if vuln_type in PATCH_STATUS:
        PATCH_STATUS[vuln_type] = (action == 'patch')
        
        # SAVE TO FILE FOR PERSISTENCE
        save_patch_status()
        
        status_msg = "patched" if action == 'patch' else "re-opened"
        logger.warning(f"Security Update: {vuln_type} vulnerability has been {status_msg}.")
        return jsonify({
            'success': True,
            'message': f"Vulnerability {vuln_type} {status_msg}",
            'status': PATCH_STATUS
        }), 200
    
    return jsonify({'error': 'Invalid vulnerability type'}), 400

@api_bp.route('/vulnerable/download')
def download():
    """Path Traversal - File Download"""
    if check_patch('download'):
        return jsonify({'error': 'Security Exception: Path Traversal vulnerability has been patched.'}), 403
        
    filename = request.args.get('file', '')
    log_vulnerable_request('download', {'file': filename})

    try:
        file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
        return send_file(file_path, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/vulnerable/ssrf')
def ssrf():
    """Server-Side Request Forgery"""
    if check_patch('ssrf'):
        return jsonify({'error': 'Security Exception: SSRF protection enabled.'}), 403

    url = request.args.get('url', '')
    log_vulnerable_request('ssrf', {'url': url})

    try:
        import requests
        response = requests.get(url, timeout=10)
        return jsonify({
            'url': url,
            'status_code': response.status_code,
            'content_length': len(response.text),
            'content': response.text[:500] 
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/vulnerable/upload', methods=['POST'])
def upload():
    """Unrestricted File Upload"""
    if check_patch('upload'):
        return jsonify({'error': 'Security Exception: File type validation enabled. Malicious file rejected.'}), 403

    file = request.files.get('file')
    if file:
        filename = file.filename
        file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
        file.save(file_path)
        log_vulnerable_request('upload', {'filename': filename, 'path': file_path})
        return jsonify({
            'message': 'File uploaded successfully',
            'filename': filename,
            'path': file_path
        }), 200
    return jsonify({'error': 'No file provided'}), 400

@api_bp.route('/vulnerable/path')
def vulnerable_path():
    """Path Traversal - File Reading"""
    if check_patch('path_traversal'):
        return jsonify({'error': 'Security Exception: Directory traversal detected and blocked.'}), 403

    path = request.args.get('path', '')
    log_vulnerable_request('path_traversal', {'path': path})

    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return jsonify({'content': content}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@api_bp.route('/vulnerable/xss', methods=['POST'])
def vulnerable_xss():
    """Cross-Site Scripting (XSS)"""
    if check_patch('xss'):
        return jsonify({'error': 'Security Exception: XSS payload detected and sanitized.'}), 403

    data = request.get_json()
    comment = data.get('comment', '')
    log_vulnerable_request('xss', {'comment': comment})

    return jsonify({
        'message': 'Comment posted',
        'comment': comment,
        'html_comment': f'<div>{comment}</div>'
    }), 200

@api_bp.route('/vulnerable/sqli')
def vulnerable_sqli():
    """SQL Injection"""
    if check_patch('sqli'):
        return jsonify({'error': 'Security Exception: SQL Injection detected. Query blocked by WAF.'}), 403

    query = request.args.get('query', '')
    log_vulnerable_request('sqli', {'query': query})

    return jsonify({
        'result': f'Executed query: {query}',
        'note': 'This endpoint simulates SQL injection vulnerability'
    }), 200

@api_bp.route('/vulnerable/xxe', methods=['POST'])
def vulnerable_xxe():
    """XML External Entity (XXE)"""
    if check_patch('xxe'):
        return jsonify({'error': 'Security Exception: XXE processing disabled.'}), 403

    xml_data = request.data.decode('utf-8')
    log_vulnerable_request('xxe', {'xml_length': len(xml_data)})

    try:
        root = ET.fromstring(xml_data)
        result = {}
        for child in root:
            result[child.tag] = child.text
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@api_bp.route('/vulnerable/deserialize', methods=['POST'])
def vulnerable_deserialize():
    """Insecure Deserialization"""
    if check_patch('deserialization'):
        return jsonify({'error': 'Security Exception: Insecure deserialization blocked.'}), 403

    data = request.get_data()
    log_vulnerable_request('deserialization', {'data_length': len(data)})

    try:
        obj = pickle.loads(data)
        return jsonify({
            'message': 'Object deserialized successfully',
            'type': str(type(obj)),
            'result': str(obj)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@api_bp.route('/vulnerable/redirect')
def vulnerable_redirect():
    """Open Redirect"""
    if check_patch('open_redirect'):
        return jsonify({'error': 'Security Exception: Open redirect validation enabled.'}), 403

    url = request.args.get('url', '')
    log_vulnerable_request('open_redirect', {'url': url})

    if url:
        return redirect(url)
    return jsonify({'error': 'No URL provided'}), 400

@api_bp.route('/vulnerable/idor')
def vulnerable_idor():
    """IDOR - Insecure Direct Object Reference"""
    if check_patch('idor'):
        return jsonify({'error': 'Security Exception: Unauthorized object access attempt.'}), 403

    user_id = request.args.get('id', '')
    log_vulnerable_request('idor', {'user_id': user_id})

    try:
        from models.user import get_user_by_id
        user_result = get_user_by_id(user_id)
        if user_result.data:
            user = user_result.data[0]
            return jsonify({
                'id': user['id'],
                'email': user['email'],
                'role': user.get('role', 'user'),
                'warning': 'This endpoint is vulnerable to IDOR'
            }), 200
        else:
            return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Honeypot endpoints
@api_bp.route('/admin-secret.php')
def honeypot_admin():
    """Honeypot - Fake admin panel"""
    log_vulnerable_request('honeypot_admin', {})
    return jsonify({
        'error': 'Access denied',
        'message': 'This is a honeypot endpoint'
    }), 403

@api_bp.route('/.env')
def honeypot_env():
    """Honeypot - Fake .env file"""
    log_vulnerable_request('honeypot_env', {})
    return jsonify({
        'SECRET_KEY': 'fake-secret-key',
        'DATABASE_URL': 'fake-db-url',
        'message': 'This is a honeypot endpoint'
    }), 200

@api_bp.route('/wp-admin')
def honeypot_wpadmin():
    """Honeypot - Fake WordPress admin"""
    log_vulnerable_request('honeypot_wpadmin', {})
    return jsonify({
        'error': 'WordPress not installed',
        'message': 'This is a honeypot endpoint'
    }), 404

@api_bp.route('/vulnerable/rce', methods=['POST'])
def vulnerable_rce():
    """Remote Code Execution (RCE) - Command Injection"""
    if check_patch('rce'):
        return jsonify({'error': 'Security Exception: Command Injection blocked by RASP.'}), 403

    data = request.get_json() or {}
    command = data.get('command', '')
    log_vulnerable_request('rce', {'command': command})

    try:
        import subprocess
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        
        return jsonify({
            'command': command,
            'exit_code': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'warning': 'This endpoint is vulnerable to RCE'
        }), 200
    except subprocess.TimeoutExpired:
        return jsonify({
            'error': 'Command execution timeout',
            'command': command
        }), 408
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/vulnerable/system-info')
def vulnerable_system_info():
    """System Information Disclosure"""
    if check_patch('system_info'):
        return jsonify({'error': 'Security Exception: Sensitive system info handling enabled.'}), 403

    log_vulnerable_request('system_info', {})
    
    try:
        import platform
        import socket
        import os
        
        info = {
            'hostname': socket.gethostname(),
            'platform': platform.platform(),
            'architecture': platform.architecture(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'current_directory': os.getcwd(),
            'environment_variables': dict(os.environ),
            'network_interfaces': socket.getaddrinfo(socket.gethostname(), None)
        }
        
        return jsonify({
            'system_info': info,
            'warning': 'This endpoint exposes sensitive system information'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500