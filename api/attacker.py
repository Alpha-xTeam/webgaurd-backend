from flask import Blueprint, request, jsonify, redirect, Response
from models.attack import log_attack, get_all_attacks, get_active_attacks, mitigate_all_attacks, update_attack_status, clear_all_attacker_data
from models.alert import create_alert
from models.incident import create_incident
from integrations.supabase import supabase
import json
import uuid
import requests
import os
import subprocess
import platform
import re
import datetime
from datetime import timedelta
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

# GLOBAL BLOCKLIST STORAGE
BLOCKED_IPS = []
BLOCKED_HOSTS = []

def get_baghdad_time():
    """Returns current time in Baghdad (UTC+3) with proper offset"""
    from datetime import timezone
    tz = timezone(timedelta(hours=3))
    return datetime.datetime.now(tz).isoformat()

def safe_create_alert(*args, **kwargs):
    try:
        create_alert(*args, **kwargs)
    except Exception:
        pass

def safe_create_incident(*args, **kwargs):
    try:
        create_incident(*args, **kwargs)
    except Exception:
        pass

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
            'stolen_server_data': data.get('stolen_server_data')
        }
        
        # Log attack directly which will handle DB insertion or fallback
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
            source='XSS Monitor',
            created_at=get_baghdad_time()
        )
        
        return jsonify({'status': 'captured'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/stolen-data', methods=['GET'])
def get_stolen_data():
    """Return all stolen data for attacker dashboard (Fetched from DB)"""
    try:
        # Fetch attacks of type 'XSS Data Theft' or 'XSS'
        attacks_response = get_all_attacks()
        
        # Handle case where get_all_attacks might return list or response object
        all_attacks = attacks_response.data if hasattr(attacks_response, 'data') else attacks_response
        
        if not isinstance(all_attacks, list):
            return jsonify([]), 200
            
        xss_attacks = [a for a in all_attacks if 'XSS' in str(a.get('attack_type', ''))]
        
        # Transform for dashboard compatibility
        formatted_data = []
        for attack in xss_attacks:
            try:
                stolen = json.loads(attack.get('stolen_data', '{}'))
                formatted_data.append({
                    'timestamp': attack.get('detected_at'),
                    'victim_ip': attack.get('attacker_ip'),
                    'victim_email': attack.get('attacker_email'),
                    'url': attack.get('target_url'),
                    **stolen
                })
            except:
                continue
                
        return jsonify(formatted_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/clear-stolen-data', methods=['POST'])
def clear_stolen_data():
    """Clear all stolen data (DB + Local + Searches)"""
    global STOLEN_DATA, STORED_SEARCHES
    STOLEN_DATA = []
    STORED_SEARCHES = []
    
    # Persistent delete from models (DB + Fallback)
    clear_all_attacker_data()
    
    return jsonify({'message': 'Stolen data and trap searches cleared persistentely', 'success': True}), 200

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
                source='Vulnerability Scanner',
                created_at=get_baghdad_time()
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
                category='Data Breach',
                created_at=get_baghdad_time()
            )

            # Include attacker email in response for realism
            user_data['accessed_by'] = attacker_email
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
                    stolen_data=json.dumps({'file': target_abs_path, 'content': content}),
                    target_url=request.url
                )
                safe_create_alert(
                    message=f'🔴 CRITICAL: Path Traversal! File {target_abs_path} leaked',
                    severity='critical',
                    source='File Monitor'
                )
                
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

        try:
            # Real request
            resp = requests.get(url, timeout=5)
            result_data = {
                'status': resp.status_code,
                'headers': dict(resp.headers),
                'body': resp.text[:2000]
            }
            
            log_attack(
                attack_type='SSRF',
                attacker_ip=attacker_ip,
                attacker_email=attacker_email,
                stolen_data=json.dumps({'target': url, 'response': result_data}),
                target_url=request.url
            )
            safe_create_alert(message=f'🔴 SSRF Attack: Request to internal/external service {url} leaked data', severity='high', source='Network Monitor')

            return jsonify(result_data), 200
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
        
        response_content = "XML Processed Successfully"
        extracted_path = "Unknown"
        
        # Check for XXE pattern
        # Match: <!ENTITY name SYSTEM "file:///path">
        xxe_match = re.search(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+["\']file://(.*?)["\']\s*>', xml_data)
        
        if xxe_match:
            extracted_path = xxe_match.group(2)
            # Fix windows mix-ups if needed (e.g. /c:/windows...)
            if extracted_path.startswith('/'):
                 if len(extracted_path) > 3 and extracted_path[2] == ':':
                     extracted_path = extracted_path.lstrip('/')
                 
            try:
                # TRY REAL FILE READ FIRST
                if os.path.exists(extracted_path) and os.path.isfile(extracted_path):
                    with open(extracted_path, 'r', encoding='utf-8', errors='ignore') as f:
                        response_content = f.read()
                else:
                    # HIGH FIDELITY SIMULATED DUMP (PREMIUM FORENSIC OUTPUT)
                    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    response_content = f"""
================================================================================
[EXFILTRATED SYSTEM DATA - XXE ATTACK SUCCESSFUL]
================================================================================
Target Entity: {extracted_path}
Capture Time: {current_time}
Host Context: webguard-internal-node-01 (Ubuntu 22.04.3 LTS)
--------------------------------------------------------------------------------

[+] SYSTEM IDENTIFICATION
    ID: {str(uuid.uuid4()).upper()}
    Node: Mainframe-PROD-01
    Kernel: 5.15.0-89-generic #99-Ubuntu SMP
    Uptime: 12 days, 04:22:11

[+] INTERNAL NETWORK DISCOVERY
    Local IP: 10.0.52.12
    Gateway: 10.0.52.1
    DNS: 1.1.1.1, 8.8.8.8
    Listening Ports: 22(SSH), 80(HTTP), 443(HTTPS), 5432(Postgres), 6379(Redis)

[+] IDENTIFIED SENSITIVE FILES (PENDING EXFILTRATION)
    - /root/.ssh/id_rsa (RSA Private Key - FOUND)
    - /etc/shadow (System Hashes - ACCESS GRANTED)
    - /var/www/html/.env (Web Credentials - FOUND)
    - /etc/kubernetes/pki/ca.key (K8s Root Key - ACCESSIBLE)

[+] DUMPING SENSITIVE CREDENTIALS (SAMPLED)
    DB_USER: webguard_admin
    DB_PASS: SupaSafe_P@ss_2024_!
    AWS_ACCESS_KEY: AKIAJSB192837465Z (EXPOSED)
    SMTP_SERVER: smtp.internal.webguard.ir

[+] RECENT SYSTEM LOGS
    [2025-12-27 11:20:15] auth.info: root login on tty1
    [2025-12-27 11:35:02] security.audit: policy_check_bypass triggered by SYSTEM_ENTITY
    [2025-12-27 11:48:19] app.error: XML External Entity resolution attempted

================================================================================
END OF DATA DUMP - WEBG-ID: {os.getpid()}
================================================================================
"""
            except Exception as read_err:
                response_content = f"Error reading file {extracted_path}: {str(read_err)}"
        
        elif 'test' in xml_data:
             response_content = "Test Entity Processed"

        log_attack(
            attack_type='XXE',
            attacker_ip=attacker_ip,
            attacker_email=attacker_email,
            stolen_data=json.dumps({'payload': xml_data, 'result': response_content}),
            target_url=request.url
        )
        
        safe_create_alert(
            message=f'🔴 XXE Attack: External entity injected, leaked content from {extracted_path}', 
            severity='high', 
            source='XML Parser'
        )

        return jsonify({
            'message': 'XML Processed (SYSTEM ENTITY RESOLVED)',
            'result': response_content,
            'real_data_captured': True
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

        # DANGEROUS: EXECUTE COMMAND
        try:
            # Using subprocess to run the command and capture output
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
                
            log_attack(
                attack_type='Remote Code Execution',
                attacker_ip=attacker_ip,
                attacker_email=get_request_user_email(),
                stolen_data=json.dumps({'command': command, 'output': output}),
                target_url=request.url
            )
            safe_create_alert(message=f'🔴 CRITICAL: RCE Exploited! Command "{command}" executed successfully', severity='critical', source='Server OS')

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
        safe_create_alert(message=f'🔴 CRITICAL: Insecure Deserialization Attack from {attacker_ip}', severity='critical', source='App Logic')

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

@api_bp.route('/sqli')
def vulnerable_sqli():
    """Real SQL Injection: Returns results from the database based on query input"""
    try:
        # Check if SQLi is patched
        if is_patched('sqli'):
            return jsonify({
                'error': 'Access Denied',
                'message': 'SQL Injection vulnerability has been patched. Database queries are safe.',
                'patched': True
            }), 403
            
        sql_query = request.args.get('query', '')
        attacker_ip = get_request_ip()
        attacker_email = get_request_user_email()
        
        if not sql_query:
            return jsonify({'error': 'SQL Query/Pattern required'}), 400

        # Create alert for SOC Tier 1
        safe_create_alert(
            message=f'🟠 SQL Injection Attempt Detected from {attacker_ip}',
            severity='high',
            source='Database Monitor'
        )

        # Log the initial attempt for the auditor
        log_attack(
            attack_type='SQL Injection Attempt',
            attacker_ip=attacker_ip,
            attacker_email=attacker_email,
            stolen_data=json.dumps({'query': sql_query}),
            target_url=request.url
        )

        # SIMULATE REAL SQL INJECTION RESULT
        # In a real system, this would actually run a raw SQL query.
        # Since we use Supabase (PostgREST), we simulate the behavior:
        # If the user provides a 'union' or 'select', we return leaked data.
        
        low_query = sql_query.lower()
        if 'select' in low_query or 'union' in low_query or '1=1' in low_query:
            # Leak real user data to simulate a successful SQLi
            response = supabase.table('users').select('id,email,role').execute()
            leaked_data = response.data
            
            # Log the successful data theft
            log_attack(
                attack_type='SQL Injection (Successful)',
                attacker_ip=attacker_ip,
                attacker_email=attacker_email,
                stolen_data=json.dumps({'query': sql_query, 'leaked_records_count': len(leaked_data), 'data': leaked_data}),
                target_url=request.url
            )
            safe_create_alert(
                message=f'🔴 CRITICAL: SQL Injection Successful! {len(leaked_data)} user records leaked',
                severity='critical',
                source='Database Monitor'
            )

            return jsonify({
                'status': 'success',
                'message': 'Query executed successfully',
                'explanation': 'The application executed your malicious SQL query directly and leaked data.',
                'results': leaked_data
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': f'SQL Syntax Error near "{sql_query.split()[0] if sql_query else ""}"',
                'results': []
            }), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
        
        # Attack resolution logged internally
        
        # Use centralized update function (DB + Fallback)
        update_attack_status(
            attack_id=attack_id,
            status=resolution,
            notes=notes,
            mitigated_at=get_baghdad_time()
        )
            
        return jsonify({'success': True, 'message': f'Attack {resolution}'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/attacks/<attack_id>', methods=['DELETE'])
def delete_attack(attack_id):
    """Delete a specific attack (Mark as deleted/inactive)"""
    try:
        # Use status update to mark as deleted (DB + Fallback)
        update_attack_status(attack_id, 'deleted')
        return jsonify({'success': True, 'message': 'Attack deleted'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# -------------------------------------------------------------------------
# BLOCKLIST MANAGEMENT
# -------------------------------------------------------------------------

@api_bp.route('/blocklist', methods=['GET'])
def get_blocklist():
    """Return current blocked IPs and Hosts"""
    return jsonify({
        'ips': BLOCKED_IPS,
        'hosts': BLOCKED_HOSTS
    }), 200

@api_bp.route('/blocklist/add', methods=['POST'])
def add_to_blocklist():
    """Add an IP or Host to blocklist"""
    data = request.get_json() or {}
    ip = data.get('ip')
    host = data.get('host')
    
    if ip and ip not in BLOCKED_IPS:
        BLOCKED_IPS.append(ip)
    if host and host not in BLOCKED_HOSTS:
        BLOCKED_HOSTS.append(host)
        
    return jsonify({'success': True, 'ips': BLOCKED_IPS, 'hosts': BLOCKED_HOSTS}), 200

@api_bp.route('/blocklist/remove', methods=['POST'])
def remove_from_blocklist():
    """Remove an IP or Host from blocklist"""
    data = request.get_json() or {}
    ip = data.get('ip')
    host = data.get('host')
    
    if ip and ip in BLOCKED_IPS:
        BLOCKED_IPS.remove(ip)
    if host and host in BLOCKED_HOSTS:
        BLOCKED_HOSTS.remove(host)
        
    return jsonify({'success': True, 'ips': BLOCKED_IPS, 'hosts': BLOCKED_HOSTS}), 200
