from flask import Blueprint, request, jsonify
from models.incident import get_incidents, update_incident_status
from models.alert import get_alerts, acknowledge_alert, update_alert_status
from models.user import get_user_by_id, get_all_users, update_user_role, delete_user_by_id
from models.log import get_logs
from models.upload import get_uploads
from models.detection_rule import get_detection_rules, create_detection_rule
import jwt
import os
from config import Config
from integrations.supabase import supabase
from utils.request_utils import get_request_ip

api_bp = Blueprint('admin', __name__)

@api_bp.route('/dashboard')
def admin_dashboard():
    incidents = get_incidents().data
    alerts = get_alerts().data
    logs = get_logs(10).data
    uploads = get_uploads().data
    rules = get_detection_rules().data

    return jsonify({
        'incidents_count': len(incidents),
        'alerts_count': len(alerts),
        'rules_count': len(rules),
        'recent_logs': logs,
        'uploads': uploads
    }), 200

@api_bp.route('/system-status')
def system_status():
    """Check system services status"""
    services = []
    
    # 1. API Status (Self)
    services.append({
        'id': 1,
        'name': 'API Server',
        'status': 'active',
        'uptime': '99.9%' # Placeholder for now, hard to calculate without persistence
    })

    # 2. Database Status (Supabase)
    try:
        supabase.table('users').select('count', count='exact').limit(1).execute()
        db_status = 'active'
    except:
        db_status = 'inactive'
    
    services.append({
        'id': 2,
        'name': 'Database (Supabase)',
        'status': db_status,
        'uptime': '99.9%'
    })

    # 3. File System (Uploads)
    upload_folder = Config.UPLOAD_FOLDER
    fs_status = 'active' if os.path.exists(upload_folder) and os.access(upload_folder, os.W_OK) else 'inactive'
    
    services.append({
        'id': 3,
        'name': 'File Storage',
        'status': fs_status,
        'uptime': '100%'
    })

    # 4. Threat Detection Engine (Mock for now as it's middleware)
    services.append({
        'id': 4,
        'name': 'Threat Detection Engine',
        'status': 'active',
        'uptime': '99.5%'
    })

    return jsonify(services), 200

@api_bp.route('/rules', methods=['GET'])
def get_rules_endpoint():
    try:
        rules = get_detection_rules().data
        return jsonify(rules), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/rules', methods=['POST'])
def create_rule_endpoint():
    try:
        data = request.get_json()
        name = data.get('name')
        pattern = data.get('pattern')
        severity = data.get('severity', 'medium')
        
        if not name or not pattern:
            return jsonify({'error': 'Name and pattern are required'}), 400
            
        result = create_detection_rule(name, pattern, severity)
        return jsonify({'message': 'Rule created successfully', 'data': result.data}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/incidents')
def get_all_incidents():
    incidents = get_incidents().data
    return jsonify(incidents), 200

@api_bp.route('/incidents/<uuid:incident_id>', methods=['PUT'])
def update_incident(incident_id):
    data = request.get_json()
    status = data.get('status')
    assigned_to = data.get('assigned_to')

    update_incident_status(str(incident_id), status, assigned_to)
    return jsonify({'message': 'Incident updated'}), 200

@api_bp.route('/alerts')
def get_all_alerts():
    alerts = get_alerts().data
    return jsonify(alerts), 200

@api_bp.route('/alerts/<uuid:alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert_endpoint(alert_id):
    data = request.get_json()
    acknowledged_by = data.get('acknowledged_by')

    acknowledge_alert(str(alert_id), acknowledged_by)
    return jsonify({'message': 'Alert acknowledged'}), 200

@api_bp.route('/alerts/<uuid:alert_id>/escalate', methods=['POST'])
def escalate_alert_endpoint(alert_id):
    data = request.get_json()
    notes = data.get('notes')
    analyst = data.get('analyst')
    
    # Update alert status to escalated
    update_alert_status(str(alert_id), 'escalated', notes, analyst)
    
    return jsonify({'message': 'Alert escalated to Tier 2'}), 200

@api_bp.route('/alerts/<uuid:alert_id>/resolve', methods=['POST'])
def resolve_alert_endpoint(alert_id):
    data = request.get_json()
    notes = data.get('notes')
    analyst = data.get('analyst')
    status = data.get('status', 'resolved') # resolved or false_positive
    
    update_alert_status(str(alert_id), status, notes, analyst)
    return jsonify({'message': f'Alert marked as {status}'}), 200

@api_bp.route('/logs')
def get_all_logs():
    logs = get_logs().data
    return jsonify(logs), 200

@api_bp.route('/users')
def get_users_endpoint():
    """Get all users for admin/owner dashboard - IDOR VULNERABLE only for unauthenticated requests"""
    try:
        # Check if request has valid authentication (admin/owner)
        auth_header = request.headers.get('Authorization', '')
        has_valid_auth = auth_header.startswith('Bearer ') and len(auth_header) > 10
        attacker_ip = get_request_ip()
        
        # CHECK IF IDOR VULNERABILITY IS PATCHED - only block unauthenticated requests
        from api.vulnerable import PATCH_STATUS
        if PATCH_STATUS.get('idor', False) and not has_valid_auth:
            return jsonify({
                'error': 'Access Denied',
                'message': 'IDOR vulnerability has been patched. Unauthorized access blocked.',
                'security_status': 'PROTECTED'
            }), 403
        
        users = get_all_users().data
        
        # If this is an unauthenticated request, log it as IDOR attack
        if not has_valid_auth:
            from models.attack import log_attack
            from models.alert import create_alert
            from models.incident import create_incident
            import json
            
            # Log the attack
            try:
                log_attack(
                    attack_type='IDOR',
                    attacker_ip=attacker_ip,
                    attacker_email='anonymous@attacker.com',
                    stolen_data=json.dumps({'endpoint': '/api/admin/users', 'users_count': len(users)}),
                    target_url=request.url
                )
                
                # Create high-severity alert for SOC Tier 1
                create_alert(
                    message=f'🔴 IDOR Attack Detected: Unauthorized access to users endpoint from IP {attacker_ip}',
                    severity='high',
                    source='Access Control'
                )
                
                # Create security incident
                create_incident(
                    title=f'IDOR Attack - Admin Users Endpoint',
                    description=f'Unauthorized access to /api/admin/users endpoint. Source IP: {attacker_ip}. {len(users)} user records accessed.',
                    severity='high',
                    category='Data Breach'
                )
                
            except Exception as log_error:
                print(f"Failed to log IDOR attack: {log_error}")
        
        return jsonify(users), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/users/<user_id>/role', methods=['PUT'])
def update_user_role_endpoint(user_id):
    """Update user role (owner only)"""
    try:
        data = request.get_json()
        new_role = data.get('role')

        if not new_role:
            return jsonify({'error': 'Role is required'}), 400

        # Validate role
        valid_roles = ['user', 'security_team', 'admin', 'owner']
        if new_role not in valid_roles:
            return jsonify({'error': 'Invalid role'}), 400

        result = update_user_role(user_id, new_role)
        if result.success:
            return jsonify({'message': 'User role updated successfully'}), 200
        else:
            return jsonify({'error': 'Failed to update user role'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Delete user (owner only)"""
    try:
        result = delete_user_by_id(user_id)
        if result.success:
            return jsonify({'message': 'User deleted successfully'}), 200
        else:
            return jsonify({'error': 'Failed to delete user'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500