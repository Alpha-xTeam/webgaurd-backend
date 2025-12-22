from flask import Blueprint, request, jsonify
from models.honeypot_log import create_honeypot_log
from utils.logger import get_security_logger
from config import Config

api_bp = Blueprint('honeypot', __name__)

security_logger = get_security_logger()

@api_bp.route('/honeypot/trap')
def honeypot_trap():
    """Basic honeypot trap endpoint"""
    # Log the access attempt
    log_honeypot_access('basic_trap', {
        'method': request.method,
        'path': request.path,
        'user_agent': request.headers.get('User-Agent'),
        'ip': request.remote_addr
    })

    return jsonify({
        'error': 'Access denied',
        'message': 'This is a restricted area'
    }), 403

@api_bp.route('/admin-panel')
def fake_admin_panel():
    """Fake admin panel honeypot"""
    log_honeypot_access('fake_admin_panel', {
        'method': request.method,
        'path': request.path,
        'user_agent': request.headers.get('User-Agent'),
        'ip': request.remote_addr,
        'query_params': dict(request.args)
    })

    return jsonify({
        'error': 'Authentication required',
        'login_url': '/fake-login',
        'message': 'Please log in to access admin panel'
    }), 401

@api_bp.route('/fake-login', methods=['GET', 'POST'])
def fake_login():
    """Fake login page honeypot"""
    if request.method == 'POST':
        data = request.get_json() or {}
        username = data.get('username', '')
        password = data.get('password', '')

        log_honeypot_access('fake_login_attempt', {
            'username': username,
            'password_length': len(password),
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent')
        })

        return jsonify({
            'error': 'Invalid credentials',
            'message': 'Login failed'
        }), 401

    return jsonify({
        'message': 'Fake login page',
        'note': 'This is a honeypot'
    }), 200

@api_bp.route('/api/v1/admin/users')
def fake_api_users():
    """Fake API endpoint honeypot"""
    log_honeypot_access('fake_api_users', {
        'method': request.method,
        'headers': dict(request.headers),
        'ip': request.remote_addr
    })

    return jsonify({
        'error': 'Unauthorized',
        'message': 'API access denied',
        'users': []  # Empty array to look like a real API
    }), 401

@api_bp.route('/.git/config')
def fake_git_config():
    """Fake .git/config honeypot"""
    log_honeypot_access('fake_git_config', {
        'method': request.method,
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent')
    })

    fake_config = """[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true
[remote "origin"]
    url = https://github.com/fake/repo.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
    remote = origin
    merge = refs/heads/main
"""

    return fake_config, 200, {'Content-Type': 'text/plain'}

@api_bp.route('/backup.sql')
def fake_backup():
    """Fake database backup honeypot"""
    log_honeypot_access('fake_backup', {
        'method': request.method,
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent')
    })

    fake_backup = """-- Fake database backup
-- This is a honeypot file

CREATE TABLE fake_users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(100)
);

INSERT INTO fake_users VALUES (1, 'admin', 'fake_password_hash');
INSERT INTO fake_users VALUES (2, 'user', 'another_fake_hash');
"""

    return fake_backup, 200, {'Content-Type': 'application/sql'}

@api_bp.route('/server-status')
def fake_server_status():
    """Fake server status honeypot"""
    log_honeypot_access('fake_server_status', {
        'method': request.method,
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent')
    })

    return jsonify({
        'server': 'Apache/2.4.41 (Ubuntu)',
        'uptime': '123 days',
        'load_average': [0.12, 0.08, 0.05],
        'memory': {
            'total': '8GB',
            'used': '2.1GB',
            'free': '5.9GB'
        },
        'note': 'This is a honeypot response'
    }), 200

def log_honeypot_access(trap_name, request_data):
    """Log honeypot access attempts"""
    try:
        # Save to database
        create_honeypot_log(trap_name, request_data)

        # Log security event
        security_logger.log_security_event(
            'honeypot_access',
            severity='high',
            details={
                'trap_name': trap_name,
                'request_data': request_data
            },
            ip=request_data.get('ip')
        )

    except Exception as e:
        # Log error but don't expose it
        security_logger.logger.error(f'Failed to log honeypot access: {str(e)}')

# Additional honeypot endpoints can be added here
# These endpoints are designed to attract and detect malicious activity