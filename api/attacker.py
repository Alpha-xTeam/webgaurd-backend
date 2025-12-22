from flask import Blueprint, request, jsonify, redirect, Response
from models.attack import log_attack, get_all_attacks, get_active_attacks, mitigate_all_attacks
from models.alert import create_alert
from models.incident import create_incident
from integrations.supabase import supabase
import json
import requests
import os
import subprocess
import platform
import re
import datetime
import jwt
from utils.request_utils import get_request_ip

from config import Config

api_bp = Blueprint('attacker', __name__)


def _email_from_jwt(token: str):
    if not token or '.' not in token:
        return None
    try:
        payload = jwt.decode(
            token,
            Config.SECRET_KEY,
            algorithms=['HS256'],
            options={'verify_exp': False},
        )
        return payload.get('email')
    except Exception:
        return None


def get_request_user_email():
    """Best-effort email attribution for logs/alerts.

    Preference order:
    1) Verified JWT from JSON body field 'token' (e.g., XSS exfil payload)
    2) Verified JWT from Authorization: Bearer <token>
    3) Flask g context user_email (from auth middleware)
    4) Client-provided X-User-Email header
    5) anonymous fallback
    """
    body = request.get_json(silent=True) or {}
    email = _email_from_jwt(body.get('token'))
    if email:
        return email

    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        email = _email_from_jwt(auth_header.split(' ', 1)[1].strip())
        if email:
            return email

    # Check Flask g context for user email (set by middleware)
    from flask import g
    if hasattr(g, 'user_email') and g.user_email:
        return g.user_email

    return request.headers.get('X-User-Email') or 'anonymous@attacker.com'


def is_patched(vuln_name):
    """Check if a vulnerability is patched - reads from shared PATCH_STATUS"""
    try:
        # Import from vulnerable.py to use the same in-memory status
        from api.vulnerable import PATCH_STATUS
        return PATCH_STATUS.get(vuln_name, False)
    except ImportError:
        # Fallback to reading file if import fails
        try:
            patch_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'patch_status.json')
            with open(patch_file, 'r') as f:
                patches = json.load(f)
            return patches.get(vuln_name, False)
        except Exception as e:
            print(f"Error checking patch status: {e}")
            return False

# GLOBAL STORAGE FOR STORED XSS (THE TRAP)
STORED_SEARCHES = []
# GLOBAL STORAGE FOR STOLEN CREDENTIALS
STOLEN_DATA = []

def safe_create_alert(*args, **kwargs):
    try:
        create_alert(*args, **kwargs)
    except Exception as e:
        print(f"Failed to create alert: {e}")

def safe_create_incident(*args, **kwargs):
    try:
        create_incident(*args, **kwargs)
    except Exception as e:
        print(f"Failed to create incident: {e}")

# Endpoint to capture stolen data from client-side XSS
@api_bp.route('/capture', methods=['POST'])
def capture_stolen_data():
    """Capture data exfiltrated via XSS"""
    try:
        data = request.get_json() or {}
        attacker_ip = get_request_ip()
        attacker_email = get_request_user_email()
        
        stolen_data = {
            'type': 'XSS Exfiltration',
            'cookies': data.get('cookies'),
            'token': data.get('token'),
            'localStorage': data.get('localStorage'),
            'session': data.get('session'),
            'url': data.get('url'),
            'payload': data.get('payload'),
            'stolen_server_data': data.get('stolen_server_data'),
            'timestamp': datetime.datetime.now().isoformat(),
            'victim_ip': attacker_ip
        }
        
        # Store for attacker dashboard
        STOLEN_DATA.append(stolen_data)
        
        log_attack(
            attack_type='XSS Data Theft',
            attacker_ip=attacker_ip,
            attacker_email=attacker_email,
            stolen_data=json.dumps(stolen_data),
            target_url=data.get('url', request.url),
            user_agent=request.headers.get('User-Agent')
        )
        
        safe_create_alert(
            message=f'Data Exfiltration Detected from {attacker_ip}',
            severity='critical',
            source='XSS Monitor'
        )
        
        return jsonify({'status': 'captured'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/stolen-data', methods=['GET'])
def get_stolen_data():
    """Return all stolen data for attacker dashboard"""
    return jsonify(STOLEN_DATA), 200

@api_bp.route('/clear-stolen-data', methods=['POST'])
def clear_stolen_data():
    """Clear all stolen data"""
    global STOLEN_DATA
    STOLEN_DATA = []
    return jsonify({'message': 'Stolen data cleared', 'success': True}), 200

# -------------------------------------------------------------------------
# REAL VULNERABILITIES (ACTUAL EXECUTION)
# -------------------------------------------------------------------------

@api_bp.route('/recent-searches', methods=['GET'])
def get_recent_searches():
    """Return stored searches (Stored XSS Source)"""
    # Return last 5 searches
    return jsonify(STORED_SEARCHES[-5:]), 200

@api_bp.route('/not-found')
def vulnerable_404():
    """Simulated 404 page with XSS vulnerability + Storing for Stored XSS"""
    try:
        # Check if XSS is patched
        if is_patched('xss'):
            user_input = request.args.get('page', '')
            # Sanitize input when patched
            import html
            safe_input = html.escape(user_input)
            return jsonify({
                'error': 'Page not found',
                'message': f'The requested page "{safe_input}" does not exist',
                'patched': True,
                'detected': False
            }), 404
        
        user_input = request.args.get('page', '')
        attacker_ip = get_request_ip()
        
        # STORE THE TRAP (STORED XSS)
        if user_input and user_input not in STORED_SEARCHES:
            STORED_SEARCHES.append(user_input)
        
        xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(', 'document.cookie']
        is_xss = any(pattern.lower() in user_input.lower() for pattern in xss_patterns)
        
        if is_xss:
            attacker_email = get_request_user_email()
            stolen_data = {
                'type': 'XSS',
                'payload': user_input,
                'cookies': request.cookies.to_dict(),
                'headers': dict(request.headers)
            }
            
            log_attack(
                attack_type='XSS',
                attacker_ip=attacker_ip,
                attacker_email=attacker_email,
                stolen_data=json.dumps(stolen_data),
                target_url=request.url,
                user_agent=request.headers.get('User-Agent')
            )
            
            safe_create_alert(
                message=f'XSS Attack detected from {attacker_ip}',
                severity='critical',
                source='Vulnerability Scanner'
            )
        
        return jsonify({
            'error': 'Page not found',
            'message': 'The requested page does not exist',
            'detected': is_xss
        }), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/profile')
def vulnerable_idor():
    """Real IDOR: Returns ACTUAL data from the 'users' table in Supabase"""
    try:
        # Check if IDOR is patched
        if is_patched('idor'):
            return jsonify({
                'error': 'Access Denied',
                'message': 'IDOR vulnerability has been patched. Access controls are enforced.',
                'patched': True
            }), 403
            
        user_id = request.args.get('id', '')
        attacker_ip = get_request_ip()
        attacker_email = get_request_user_email()
        
        if not user_id:
            return jsonify({'error': 'User ID required'}), 400

        # REAL DATABASE QUERY
        response = supabase.table('users').select('*').eq('id', user_id).execute()
        
        if response.data and len(response.data) > 0:
            user_data = response.data[0]
            
            log_attack(
                attack_type='IDOR',
                attacker_ip=attacker_ip,
                attacker_email=attacker_email,
                stolen_data=json.dumps({'accessed_id': user_id, 'leaked_data': user_data}),
                target_url=request.url
            )
            # Create high-severity alert for SOC Tier 1
            safe_create_alert(
                message=f'🔴 IDOR Attack Detected: Unauthorized access to user profile ID {user_id} from IP {attacker_ip}',
                severity='high',
                source='Access Control'
            )
            
            # Create security incident
            safe_create_incident(
                title=f'IDOR Attack - User Data Exposure',
                description=f'Unauthorized access to user profile data via IDOR vulnerability. Target ID: {user_id}, Source IP: {attacker_ip}',
                severity='high',
                category='Data Breach'
            )

            return jsonify(user_data), 200
        else:
            return jsonify({'error': 'User not found in database'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/gallery')
def vulnerable_path_traversal():
    """Real Path Traversal: Reads ACTUAL files from the server filesystem"""
    try:
        # Check if Path Traversal is patched
        if is_patched('path_traversal'):
            return jsonify({
                'error': 'Access Denied',
                'message': 'Path traversal vulnerability has been patched. File access is restricted.',
                'patched': True
            }), 403
        
        file_path = request.args.get('file', '')
        attacker_ip = get_request_ip()
        attacker_email = get_request_user_email()
        
        if not file_path:
            return jsonify({'error': 'File path required'}), 400

        base_dir = os.getcwd()
        
        try:
            # Normalize path but allow traversal for demonstration
            if file_path.startswith('/') or file_path.startswith('\\') or ':' in file_path:
                 target_abs_path = os.path.abspath(file_path)
            else:
                 target_abs_path = os.path.abspath(os.path.join(base_dir, file_path))
            
            if os.path.exists(target_abs_path) and os.path.isfile(target_abs_path):
                with open(target_abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                log_attack(
                    attack_type='Path Traversal',
                    attacker_ip=attacker_ip,
                    attacker_email=attacker_email,
                    stolen_data=json.dumps({'file': target_abs_path, 'content_preview': content[:100]}),
                    target_url=request.url
                )
                safe_create_alert(message=f'Path Traversal: Real file {target_abs_path} accessed', severity='critical', source='File Monitor')
                
                return Response(content, mimetype='text/plain')
            else:
                return jsonify({'error': f'File not found: {target_abs_path}'}), 404
                
        except Exception as e:
            return jsonify({'error': f'Access denied or error: {str(e)}'}), 403

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/fetch', methods=['POST'])
def vulnerable_ssrf():
    """Real SSRF: Fetches external/internal URLs"""
    try:
        # Check if SSRF is patched
        if is_patched('ssrf'):
            return jsonify({
                'error': 'Access Denied',
                'message': 'SSRF vulnerability has been patched. External URL fetching is disabled.',
                'patched': True
            }), 403
        
        data = request.get_json() or {}
        url = data.get('url', '')
        attacker_ip = get_request_ip()
        attacker_email = get_request_user_email()
        
        if not url:
            return jsonify({'error': 'URL required'}), 400

        log_attack(
            attack_type='SSRF',
            attacker_ip=attacker_ip,
            attacker_email=attacker_email,
            stolen_data=json.dumps({'target': url}),
            target_url=request.url
        )
        safe_create_alert(message=f'SSRF: Request to {url}', severity='high', source='Network Monitor')

        try:
            # Real request
            resp = requests.get(url, timeout=5)
            return jsonify({
                'status': resp.status_code,
                'headers': dict(resp.headers),
                'body': resp.text[:2000] # Limit response size
            }), 200
        except Exception as fetch_err:
            return jsonify({'error': f'Fetch failed: {str(fetch_err)}'}), 502

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/parse-xml', methods=['POST'])
def vulnerable_xxe():
    """Real XXE (Simulated execution for safety, but allows some real reads if possible)"""
    try:
        # Check if XXE is patched
        if is_patched('xxe'):
            return jsonify({
                'error': 'Access Denied',
                'message': 'XXE vulnerability has been patched. External entities are disabled.',
                'patched': True
            }), 403
        
        xml_data = request.data.decode('utf-8')
        attacker_ip = get_request_ip()
        attacker_email = get_request_user_email()
        
        log_attack(
            attack_type='XXE',
            attacker_ip=attacker_ip,
            attacker_email=attacker_email,
            stolen_data=json.dumps({'payload': xml_data[:200]}),
            target_url=request.url
        )
        safe_create_alert(message=f'XXE Attack from {attacker_ip}', severity='high', source='XML Parser')

        # REAL XXE: Extract file path and read it
        
        # Regex to capture file paths in XML entities: SYSTEM "file://..." or SYSTEM "..."
        # We look for: SYSTEM ["'](file://)?(.*?)["']
        match = re.search(r'SYSTEM\s+["\'](?:file:///?|)(.*?)["\']', xml_data, re.IGNORECASE)
        
        response_content = "XML Parsed Successfully (No external entity found)"
        
        if match:
            extracted_path = match.group(1)
            # Fix windows mix-ups if needed (e.g. /c:/windows...)
            if ':' in extracted_path and extracted_path.startswith('/'):
                 extracted_path = extracted_path.lstrip('/')
                 
            try:
                if os.path.exists(extracted_path) and os.path.isfile(extracted_path):
                    with open(extracted_path, 'r', encoding='utf-8', errors='ignore') as f:
                        response_content = f.read()
                else:
                    response_content = f"Error: File not found on server: {extracted_path}"
            except Exception as read_err:
                 # Be specific about the error
                 response_content = f"Error reading file {extracted_path}: {str(read_err)}"
        elif 'test' in xml_data:
             response_content = "Test Entity Processed"

        return jsonify({
            'message': 'XML Processed',
            'result': response_content
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/rce', methods=['POST'])
def vulnerable_rce():
    """REAL RCE: Executes ACTUAL system commands"""
    try:
        # Check if RCE is patched
        if is_patched('rce'):
            return jsonify({
                'error': 'Access Denied',
                'message': 'RCE vulnerability has been patched. Command execution is disabled.',
                'patched': True
            }), 403
        
        data = request.get_json() or {}
        command = data.get('command', '')
        attacker_ip = get_request_ip()
        
        if not command:
            return jsonify({'error': 'Command required'}), 400

        log_attack(
            attack_type='Remote Code Execution',
            attacker_ip=attacker_ip,
            attacker_email=get_request_user_email(),
            stolen_data=json.dumps({'command': command}),
            target_url=request.url
        )
        safe_create_alert(message=f'RCE Detected: {command}', severity='critical', source='Server OS')

        # DANGEROUS: EXECUTE COMMAND
        try:
            # Using subprocess to run the command and capture output
            # capture_output=True requires Python 3.7+
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            
            output = result.stdout + result.stderr
            if not output:
                output = "Command executed successfully (No output)"
                
            return jsonify({
                'status': 'executed',
                'output': output
            }), 200
            
        except subprocess.TimeoutExpired:
            return jsonify({'error': 'Command timed out'}), 504
        except Exception as exec_err:
            return jsonify({'error': f'Execution failed: {str(exec_err)}'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/process', methods=['POST'])
def vulnerable_deserialization():
    """Real Deserialization (Simulated for safety)"""
    try:
        # Check if Deserialization is patched
        if is_patched('deserialization'):
            return jsonify({
                'error': 'Access Denied',
                'message': 'Insecure deserialization vulnerability has been patched.',
                'patched': True
            }), 403
        
        data = request.get_json() or {}
        serialized_obj = data.get('object', '')
        attacker_ip = get_request_ip()
        
        log_attack(
            attack_type='Insecure Deserialization',
            attacker_ip=attacker_ip,
            attacker_email=get_request_user_email(),
            stolen_data=json.dumps({'payload': serialized_obj}),
            target_url=request.url
        )
        safe_create_alert(message=f'Deserialization Attack from {attacker_ip}', severity='critical', source='App Logic')

        output = "Object processed."
        
        # REAL EXECUTION (Dangerous!)
        # In a real Deserialization attack, the attacker sends a serialized object 
        # that executes code upon deserialization. Here we simulate the payload structure
        # but actually EXECUTE the intent.
        
        command_to_run = None
            
        if 'os.system' in serialized_obj:
            # Extract command from os.system('command')
            import re
            match = re.search(r"os\.system\(['\"](.*?)['\"]\)", serialized_obj)
            if match:
                command_to_run = match.group(1)
        elif 'subprocess' in serialized_obj:
             match = re.search(r"\(['\"](.*?)['\"]\)", serialized_obj)
             if match:
                command_to_run = match.group(1)
        elif '"object":' in serialized_obj:
            # Try to interpret simple JSON payload {"object": "whoami"}
            try:
                cmd_json = json.loads(serialized_obj)
                command_to_run = cmd_json.get('object')
            except:
                pass

        if command_to_run:
            try:
                result = subprocess.run(
                    command_to_run, 
                    shell=True, 
                    capture_output=True, 
                    text=True, 
                    timeout=3
                )
                output = result.stdout + result.stderr
                if not output: output = "Command executed (No output)"
            except Exception as e:
                output = f"Execution Error: {str(e)}"

        return jsonify({
            'status': 'processed',
            'execution_output': output
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/redirect')
def vulnerable_open_redirect():
    """Real Open Redirect"""
    try:
        # Check if Open Redirect is patched
        if is_patched('open_redirect'):
            return jsonify({
                'error': 'Access Denied',
                'message': 'Open redirect vulnerability has been patched. External redirects are disabled.',
                'patched': True
            }), 403
        
        redirect_url = request.args.get('url', '')
        attacker_ip = get_request_ip()
        
        if redirect_url:
            log_attack(
                attack_type='Open Redirect',
                attacker_ip=attacker_ip,
                attacker_email=get_request_user_email(),
                stolen_data=json.dumps({'target': redirect_url}),
                target_url=request.url
            )
            safe_create_alert(message=f'Open Redirect to {redirect_url}', severity='medium', source='Redirector')
            return redirect(redirect_url)
            
        return jsonify({'error': 'No URL provided'}), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/system-info')
def vulnerable_system_info():
    """Leak System Info"""
    try:
        # Check if System Info disclosure is patched
        if is_patched('system_info'):
            return jsonify({
                'error': 'Access Denied',
                'message': 'System information disclosure vulnerability has been patched.',
                'patched': True
            }), 403
        
        attacker_ip = get_request_ip()
        log_attack(
            attack_type='System Info Leak',
            attacker_ip=attacker_ip,
            attacker_email=get_request_user_email(),
            stolen_data=json.dumps({'env': dict(os.environ)}),
            target_url=request.url
        )
        safe_create_alert(message='System Info Dumped', severity='high', source='Configuration')
        
        return jsonify({
            'os': platform.system(),
            'platform': platform.platform(),
            'node': platform.node(),
            'env': dict(os.environ)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Honeypot endpoints
@api_bp.route('/admin-secret.php')
@api_bp.route('/.env')
@api_bp.route('/config.php')
@api_bp.route('/backup.sql')
def honeypot():
    """Honeypot detection"""
    try:
        attacker_ip = get_request_ip()
        log_attack(
            attack_type='Honeypot Detection',
            attacker_ip=attacker_ip,
            attacker_email=get_request_user_email(),
            stolen_data=json.dumps({'file': request.path}),
            target_url=request.url
        )
        safe_create_alert(message=f'Honeypot Triggered: {request.path}', severity='critical', source='Honeypot')
        return jsonify({'error': 'Access denied', 'ip_logged': True}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# API endpoints for attack management
@api_bp.route('/attacks', methods=['GET'])
def get_attacks():
    """Get all attacks"""
    try:
        attacks = get_all_attacks()
        return jsonify(attacks.data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/attacks/active', methods=['GET'])
def get_active():
    """Get active attacks"""
    try:
        attacks = get_active_attacks()
        return jsonify(attacks.data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/attacks/mitigate-all', methods=['POST'])
def mitigate_attacks():
    """Mitigate all attacks and block attackers"""
    try:
        result = mitigate_all_attacks()
        safe_create_incident(
            title='Mass Mitigation',
            description=f'Mitigated {result.get("mitigated_attacks", 0)} attacks. Blocked {result.get("blocked_users", 0)} users.',
            severity='high'
        )
        return jsonify({'success': True, **result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/attacks/<attack_id>/resolve', methods=['POST'])
def resolve_attack(attack_id):
    """Resolve a specific attack (used by SOC Tier 1)"""
    try:
        data = request.get_json() or {}
        resolution = data.get('resolution', 'resolved')
        notes = data.get('notes', '')
        analyst = data.get('analyst', 'Unknown')
        
        print(f"🔒 Attack {attack_id} marked as {resolution} by {analyst}")
        print(f"   Notes: {notes}")
        
        # In real system, this would update the database
        # For now, just acknowledge the resolution
        return jsonify({
            'success': True,
            'message': f'Attack {attack_id} resolved successfully',
            'resolution': resolution,
            'analyst': analyst
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
