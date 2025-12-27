from flask import Blueprint, jsonify, request
from middleware.auth_guard import require_auth
from api.attacker import BLOCKED_IPS, BLOCKED_HOSTS
import datetime
import subprocess
import os
import platform
import shlex

api_bp = Blueprint('security', __name__)

# Storage for escalated alerts to Tier 2
TIER2_ESCALATIONS = []

@api_bp.route('/escalate-to-tier2', methods=['POST'])
@require_auth
def escalate_to_tier2():
    """Receive escalation from Tier 1 and notify Tier 2"""
    try:
        data = request.get_json()
        
        escalation = {
            'id': f"ESC-{len(TIER2_ESCALATIONS) + 1}",
            'alert_id': data.get('alert_id'),
            'attack_type': data.get('attack_type'),
            'severity': data.get('severity'),
            'source_ip': data.get('source_ip'),
            'target_url': data.get('target_url'),
            'analyst_notes': data.get('analyst_notes'),
            'analyst_name': data.get('analyst_name'),
            'playbook_completion': data.get('playbook_completion', 0),
            'escalated_at': data.get('escalated_at'),
            'status': 'pending_tier2_review',
            'raw_data': data.get('raw_data')
        }
        
        TIER2_ESCALATIONS.append(escalation)
        
        # Escalation logged internally
        
        return jsonify({
            "success": True,
            "message": "Alert escalated to Tier 2 successfully",
            "escalation_id": escalation['id']
        }), 200
        
    except Exception as e:
        print(f"Escalation error: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/tier2/escalations', methods=['GET'])
@require_auth
def get_tier2_escalations():
    """Get all pending escalations for Tier 2"""
    try:
        return jsonify({
            "success": True,
            "escalations": TIER2_ESCALATIONS
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# Storage for escalated alerts to Tier 3 (CSIRT)
TIER3_ESCALATIONS = []

@api_bp.route('/escalate-to-tier3', methods=['POST'])
@require_auth
def escalate_to_tier3():
    """Receive escalation from Tier 2 and notify Tier 3 (CSIRT)"""
    try:
        data = request.get_json()
        
        escalation = {
            'id': f"CSIRT-{len(TIER3_ESCALATIONS) + 1}",
            'tier2_case_id': data.get('case_id'),
            'attack_type': data.get('attack_type'),
            'severity': data.get('severity'),
            'source_ip': data.get('source_ip'),
            'analyst_notes_tier1': data.get('notes_tier1'),
            'analyst_notes_tier2': data.get('notes_tier2'),
            'tier2_analyst': data.get('analyst_name'),
            'forensics_data': data.get('forensics_data'),
            'escalated_at': datetime.datetime.utcnow().isoformat(),
            'status': 'pending_csirt_review',
            'raw_data': data.get('raw_data')
        }
        
        TIER3_ESCALATIONS.append(escalation)
        
        # Escalation to CSIRT logged internally
        
        # Remove from Tier 2 list (optional, assuming we move it)
        # In a real DB we would just update the status_id
        
        return jsonify({
            "success": True,
            "message": "Case escalated to CSIRT (Tier 3) successfully",
            "escalation_id": escalation['id']
        }), 200
        
    except Exception as e:
        print(f"Tier 3 Escalation error: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/tier3/escalations', methods=['GET'])
@require_auth
def get_tier3_escalations():
    """Get all pending escalations for Tier 3"""
    try:
        return jsonify({
            "success": True,
            "escalations": TIER3_ESCALATIONS
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# Mock security alerts data
MOCK_ALERTS_LEVEL1 = [
    {
        "id": 1,
        "type": "suspicious_login",
        "severity": "medium",
        "source": "login_system",
        "description": "Multiple failed login attempts from IP 192.168.1.100",
        "timestamp": "2025-01-15T10:30:00Z",
        "status": "new",
        "userId": "user123"
    },
    {
        "id": 2,
        "type": "unusual_activity",
        "severity": "low",
        "source": "user_profile",
        "description": "User accessed profile page 50 times in 5 minutes",
        "timestamp": "2025-01-15T09:15:00Z",
        "status": "investigating",
        "userId": "user456"
    }
]

MOCK_ALERTS_LEVEL2 = [
    {
        "id": 3,
        "type": "sql_injection",
        "severity": "high",
        "source": "sports_news_search",
        "description": "SQL injection attempt detected in sports news search",
        "timestamp": "2025-01-15T11:45:00Z",
        "status": "new",
        "userId": "attacker@example.com"
    },
    {
        "id": 4,
        "type": "xss_attempt",
        "severity": "high",
        "source": "sports_news_comments",
        "description": "Cross-site scripting attempt in article comments",
        "timestamp": "2025-01-15T10:20:00Z",
        "status": "escalated",
        "userId": "hacker@test.com"
    }
]

MOCK_ALERTS_LEVEL3 = [
    {
        "id": 5,
        "type": "data_breach",
        "severity": "critical",
        "source": "database_server",
        "description": "Potential data breach detected - unauthorized database access",
        "timestamp": "2025-01-15T12:00:00Z",
        "status": "new",
        "userId": "system"
    }
]

MOCK_INCIDENTS = [
    {
        "id": 1,
        "title": "SQL Injection Attack Campaign",
        "severity": "major",
        "status": "active",
        "assignedTo": "sec_team_lead",
        "createdAt": "2025-01-15T08:00:00Z",
        "description": "Coordinated SQL injection attacks targeting multiple endpoints",
        "timeline": [
            {"timestamp": "2025-01-15T08:00:00Z", "description": "Initial detection"},
            {"timestamp": "2025-01-15T09:30:00Z", "description": "Pattern analysis completed"},
            {"timestamp": "2025-01-15T11:00:00Z", "description": "Escalated to Level 3"}
        ]
    }
]

@api_bp.route('/alerts/level1', methods=['GET'])
@require_auth
def get_level1_alerts():
    """Get alerts for Level 1 security operations"""
    try:
        return jsonify({
            "success": True,
            "alerts": MOCK_ALERTS_LEVEL1
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/alerts/level2', methods=['GET'])
@require_auth
def get_level2_alerts():
    """Get alerts for Level 2 security operations"""
    try:
        return jsonify({
            "success": True,
            "alerts": MOCK_ALERTS_LEVEL2
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/alerts/level3', methods=['GET'])
@require_auth
def get_level3_alerts():
    """Get alerts for Level 3 security operations"""
    try:
        return jsonify({
            "success": True,
            "alerts": MOCK_ALERTS_LEVEL3
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/alerts/<int:alert_id>/action', methods=['POST'])
@require_auth
def handle_alert_action(alert_id):
    """Handle alert actions (investigate, escalate, resolve)"""
    try:
        data = request.get_json()
        action = data.get('action')

        if action not in ['investigate', 'escalate', 'resolve', 'analyze']:
            return jsonify({"success": False, "error": "Invalid action"}), 400

        # In a real system, this would update the alert status in database
        return jsonify({
            "success": True,
            "message": f"Alert {alert_id} {action} action completed"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/stats/level1', methods=['GET'])
@require_auth
def get_level1_stats():
    """Get statistics for Level 1 security operations"""
    try:
        return jsonify({
            "success": True,
            "stats": {
                "totalAlerts": 15,
                "criticalAlerts": 2,
                "resolvedAlerts": 8,
                "escalatedAlerts": 3
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/stats/level2', methods=['GET'])
@require_auth
def get_level2_stats():
    """Get statistics for Level 2 security operations"""
    try:
        return jsonify({
            "success": True,
            "stats": {
                "totalAlerts": 8,
                "criticalAlerts": 3,
                "resolvedAlerts": 4,
                "escalatedAlerts": 2
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/stats/level3', methods=['GET'])
@require_auth
def get_level3_stats():
    """Get statistics for Level 3 security operations"""
    try:
        return jsonify({
            "success": True,
            "stats": {
                "totalAlerts": 3,
                "criticalAlerts": 2,
                "resolvedAlerts": 1,
                "escalatedAlerts": 0,
                "activeIncidents": 1
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/incidents', methods=['GET'])
@require_auth
def get_incidents():
    """Get active security incidents"""
    try:
        return jsonify({
            "success": True,
            "incidents": MOCK_INCIDENTS
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/incidents/<int:incident_id>/action', methods=['POST'])
@require_auth
def handle_incident_action(incident_id):
    """Handle incident actions (escalate, resolve)"""
    try:
        data = request.get_json()
        action = data.get('action')

        if action not in ['escalate', 'resolve']:
            return jsonify({"success": False, "error": "Invalid action"}), 400

        # In a real system, this would update the incident status in database
        return jsonify({
            "success": True,
            "message": f"Incident {incident_id} {action} action completed"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/alerts', methods=['POST'])
@require_auth
def create_alert():
    """Create new security alert (called by frontend attack detection)"""
    try:
        data = request.get_json()

        # Alert logged successfully

        return jsonify({
            "success": True,
            "message": "Alert logged successfully"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/terminal/execute', methods=['POST'])
@require_auth
def terminal_execute():
    """Execute analysis commands (Real OS Execution)"""
    try:
        data = request.get_json()
        command = data.get('command', '').strip()
        
        if not command:
            return jsonify({"success": False, "error": "No command provided"}), 400
        
        # Mapping common Unix commands to Windows equivalents if needed
        # But user wants "real", so we let the shell handle it.
        # If on Windows, we'll try to use powershell if available, else cmd.
        
        is_windows = platform.system() == "Windows"
        
        try:
            if is_windows:
                # Use powershell for better command compatibility (ls, pwd, etc work in PS)
                process = subprocess.Popen(
                    ["powershell", "-Command", command],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=True
                )
            else:
                # Unix/Linux
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=True
                )
            
            stdout, stderr = process.communicate(timeout=10)
            
            output = stdout if stdout else stderr
            if not output and process.returncode == 0:
                output = "[Command executed successfully with no output]"
            elif not output and process.returncode != 0:
                output = f"[Command failed with exit code {process.returncode}]"
                
            return jsonify({
                "success": True, 
                "output": output,
                "returncode": process.returncode
            })
            
        except subprocess.TimeoutExpired:
            process.kill()
            return jsonify({"success": True, "output": "Error: Command timed out (10s limit)"})
        except Exception as e:
            return jsonify({"success": True, "output": f"Error: {str(e)}"})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@api_bp.route('/blocklist', methods=['GET'])
@require_auth
def get_soc_blocklist():
    """Get the current global blocklist for SOC management"""
    return jsonify({
        "success": True,
        "ips": BLOCKED_IPS,
        "hosts": BLOCKED_HOSTS
    })

@api_bp.route('/blocklist/add', methods=['POST'])
@require_auth
def add_to_blocklist():
    """Add an IP or Host to the blocklist"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        host = data.get('host')
        
        if ip and ip not in BLOCKED_IPS:
            BLOCKED_IPS.append(ip)
        if host and host not in BLOCKED_HOSTS:
            BLOCKED_HOSTS.append(host)
            
        return jsonify({
            "success": True, 
            "message": "Successfully added to blocklist",
            "ips": BLOCKED_IPS,
            "hosts": BLOCKED_HOSTS
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@api_bp.route('/blocklist/remove', methods=['POST'])
@require_auth
def remove_from_blocklist():
    """Remove an IP or Host from the blocklist"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        host = data.get('host')
        
        removed = False
        if ip and ip in BLOCKED_IPS:
            BLOCKED_IPS.remove(ip)
            removed = True
        if host and host in BLOCKED_HOSTS:
            BLOCKED_HOSTS.remove(host)
            removed = True
            
        if removed:
            return jsonify({"success": True, "message": "Successfully removed from blocklist"})
        else:
            return jsonify({"success": False, "error": "Item not found in blocklist"})
            
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
