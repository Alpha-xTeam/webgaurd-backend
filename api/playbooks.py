"""
Playbook Execution API Endpoints
Real security playbooks for WebGuard-IR
"""

from flask import Blueprint, jsonify, request
from middleware.auth_guard import require_auth
from incident_response.playbooks import execute_playbook
from integrations.supabase import supabase
import logging

api_bp = Blueprint('playbooks', __name__)
logger = logging.getLogger(__name__)

@api_bp.route('/execute/ip-blacklist', methods=['POST'])
@require_auth
def execute_ip_blacklist():
    """Execute IP blacklisting playbook"""
    try:
        data = request.get_json()
        target_ip = data.get('target_ip')
        severity = data.get('severity', 'high')
        
        if not target_ip:
            return jsonify({
                "success": False,
                "error": "target_ip is required"
            }), 400
        
        # Log the execution request
        logger.warning(f"IP BLACKLIST REQUEST: {target_ip} by user")
        
        # Execute the playbook
        result = execute_playbook("ip_blacklist", target_ip, severity=severity)
        
        if result.get('success'):
            return jsonify({
                "success": True,
                "message": f"IP {target_ip} blacklisted successfully",
                "details": result
            }), 200
        else:
            return jsonify({
                "success": False,
                "error": result.get('error', 'Unknown error'),
                "details": result
            }), 500
            
    except Exception as e:
        logger.error(f"IP blacklist execution error: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/execute/user-isolation', methods=['POST'])
@require_auth
def execute_user_isolation():
    """Execute user isolation playbook"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        user_email = data.get('user_email')
        severity = data.get('severity', 'high')
        
        if not user_id or not user_email:
            return jsonify({
                "success": False,
                "error": "user_id and user_email are required"
            }), 400
        
        # Log the execution request
        logger.warning(f"USER ISOLATION REQUEST: {user_email} ({user_id}) by user")
        
        # Execute the playbook
        result = execute_playbook("user_isolation", user_id, 
                                user_email=user_email, severity=severity)
        
        if result.get('success'):
            return jsonify({
                "success": True,
                "message": f"User {user_email} isolated successfully",
                "details": result
            }), 200
        else:
            return jsonify({
                "success": False,
                "error": result.get('error', 'Unknown error'),
                "details": result
            }), 500
            
    except Exception as e:
        logger.error(f"User isolation execution error: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/execute/process-termination', methods=['POST'])
@require_auth
def execute_process_termination():
    """Execute process termination playbook"""
    try:
        data = request.get_json()
        process_name = data.get('process_name')
        pid = data.get('pid')
        severity = data.get('severity', 'critical')
        
        if not process_name:
            return jsonify({
                "success": False,
                "error": "process_name is required"
            }), 400
        
        # Log the execution request
        logger.warning(f"PROCESS TERMINATION REQUEST: {process_name} (PID: {pid}) by user")
        
        # Execute the playbook
        result = execute_playbook("process_termination", process_name, 
                                pid=pid, severity=severity)
        
        if result.get('success'):
            return jsonify({
                "success": True,
                "message": f"Process {process_name} terminated successfully",
                "details": result
            }), 200
        else:
            return jsonify({
                "success": False,
                "error": result.get('error', 'Unknown error'),
                "details": result
            }), 500
            
    except Exception as e:
        logger.error(f"Process termination execution error: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/executions', methods=['GET'])
@require_auth
def get_playbook_executions():
    """Get recent playbook executions"""
    try:
        # Get recent executions from database
        result = supabase.table('playbook_executions')\
            .select('*')\
            .order('start_time', desc=True)\
            .limit(50)\
            .execute()
        
        return jsonify({
            "success": True,
            "executions": result.data if result.data else []
        }), 200
        
    except Exception as e:
        logger.error(f"Failed to get playbook executions: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/blocked-ips', methods=['GET'])
@require_auth
def get_blocked_ips():
    """Get list of blocked IPs"""
    try:
        # Get IP blacklist executions
        result = supabase.table('playbook_executions')\
            .select('*')\
            .eq('playbook_type', 'DomainIPBlacklistPlaybook')\
            .eq('status', 'completed')\
            .order('start_time', desc=True)\
            .limit(100)\
            .execute()
        
        # Extract unique IPs
        blocked_ips = list(set([execution['target'] for execution in result.data if result.data]))
        
        return jsonify({
            "success": True,
            "blocked_ips": blocked_ips,
            "total_count": len(blocked_ips)
        }), 200
        
    except Exception as e:
        logger.error(f"Failed to get blocked IPs: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/isolated-users', methods=['GET'])
@require_auth
def get_isolated_users():
    """Get list of isolated users"""
    try:
        # Get user isolation executions
        result = supabase.table('playbook_executions')\
            .select('*')\
            .eq('playbook_type', 'UserIsolationPlaybook')\
            .eq('status', 'completed')\
            .order('start_time', desc=True)\
            .limit(100)\
            .execute()
        
        # Extract unique users
        isolated_users = list(set([execution['target'] for execution in result.data if result.data]))
        
        return jsonify({
            "success": True,
            "isolated_users": isolated_users,
            "total_count": len(isolated_users)
        }), 200
        
    except Exception as e:
        logger.error(f"Failed to get isolated users: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/auto-isolate-suspicious', methods=['POST'])
@require_auth
def auto_isolate_suspicious_users():
    """Automatically isolate users with suspicious activity"""
    try:
        data = request.get_json()
        threshold_hours = data.get('threshold_hours', 24)
        
        # Get users with multiple security alerts in the last N hours
        from datetime import datetime, timedelta
        
        cutoff_time = (datetime.utcnow() - timedelta(hours=threshold_hours)).isoformat()
        
        # Get recent security alerts
        alerts_result = supabase.table('security_alerts')\
            .select('*')\
            .gte('created_at', cutoff_time)\
            .eq('status', 'new')\
            .execute()
        
        if not alerts_result.data:
            return jsonify({
                "success": True,
                "message": "No suspicious users found",
                "isolated_count": 0
            }), 200
        
        # Count alerts per user
        user_alert_counts = {}
        for alert in alerts_result.data:
            user_id = alert.get('user_id')
            if user_id:
                user_alert_counts[user_id] = user_alert_counts.get(user_id, 0) + 1
        
        # Isolate users with more than 3 alerts
        isolated_count = 0
        for user_id, alert_count in user_alert_counts.items():
            if alert_count >= 3:
                # Get user details
                user_result = supabase.table('users')\
                    .select('*')\
                    .eq('id', user_id)\
                    .execute()
                
                if user_result.data:
                    user_email = user_result.data[0]['email']
                    
                    # Execute user isolation playbook
                    result = execute_playbook("user_isolation", user_id, 
                                            user_email=user_email, severity="high")
                    
                    if result.get('success'):
                        isolated_count += 1
                        logger.info(f"Auto-isolated user: {user_email} ({alert_count} alerts)")
        
        return jsonify({
            "success": True,
            "message": f"Auto-isolated {isolated_count} suspicious users",
            "isolated_count": isolated_count,
            "total_suspicious": len([u for u, c in user_alert_counts.items() if c >= 3])
        }), 200
        
    except Exception as e:
        logger.error(f"Auto-isolation error: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500
