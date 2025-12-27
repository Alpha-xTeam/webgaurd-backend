from flask import Blueprint, jsonify, request
from middleware.auth_guard import require_auth
from api.attacker import BLOCKED_IPS, BLOCKED_HOSTS
from models.incident import get_incidents, create_incident, update_incident_status
from models.incident_response import create_incident_response
from integrations.supabase import supabase
import datetime
import subprocess
import os
import platform
import shlex

api_bp = Blueprint('security', __name__)

@api_bp.route('/escalate-to-tier2', methods=['POST'])
@require_auth
def escalate_to_tier2():
    """Receive escalation from Tier 1 and notify Tier 2 (Saves to Incidents)"""
    try:
        data = request.get_json()
        incident_id = data.get('incident_id')
        item_type = data.get('type', 'incident') # 'alert' or 'incident'
        
        if item_type == 'incident' or not item_type:
            if incident_id:
                # Update existing incident
                update_incident_status(incident_id, 'pending_tier2')
                return jsonify({
                    "success": True,
                    "message": "Incident moved to Tier 2"
                }), 200
        
        # If it's an alert or if incident update failed/didn't exist, create a new one
        # Also mark the alert as acknowledged if it's an alert
        if item_type == 'alert' and incident_id:
            try:
                supabase.table('alerts').update({'acknowledged': True}).eq('id', incident_id).execute()
            except Exception as e:
                print(f"Failed to acknowledge alert: {e}")

        incident_data = {
            'title': f"Escalated: {data.get('attack_type', 'Security Alert')}",
            'description': f"Source IP: {data.get('source_ip')}\nAnalyst Notes: {data.get('analyst_notes', 'No notes provided.')}",
            'severity': data.get('severity', 'high'),
            'status': 'pending_tier2',
            'created_at': datetime.datetime.utcnow().isoformat()
        }
        
        res = create_incident(
            title=incident_data['title'],
            description=incident_data['description'],
            severity=incident_data['severity'],
            created_at=incident_data['created_at']
        )
        
        return jsonify({
            "success": True,
            "message": "Alert escalated to Tier 2 (Incident Created)",
            "incident": res.data[0] if res.data else None
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
    """Get all pending escalations for Tier 2 from Incidents table"""
    try:
        # Fetch from incidents table where status like tier2
        res = supabase.table('incidents').select('*').or_('status.eq.pending_tier2,status.eq.investigating').execute()
        return jsonify({
            "success": True,
            "escalations": res.data
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/escalate-to-tier3', methods=['POST'])
@require_auth
def escalate_to_tier3():
    """Receive escalation from Tier 2 and notify Tier 3 (Saves to Incidents)"""
    try:
        data = request.get_json()
        case_id = data.get('case_id') or data.get('incident_id')
        
        if not case_id:
            return jsonify({"success": False, "error": "Case ID required"}), 400

        # Update incident status to tier3
        update_incident_status(case_id, 'pending_tier3')
        
        return jsonify({
            "success": True,
            "message": "Case escalated to CSIRT (Tier 3) successfully"
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
    """Get all pending escalations for Tier 3 from Incidents table"""
    try:
        res = supabase.table('incidents').select('*').eq('status', 'pending_tier3').execute()
        return jsonify({
            "success": True,
            "escalations": res.data
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/alerts/level1', methods=['GET'])
@require_auth
def get_level1_alerts():
    """Get alerts for Level 1 - Fetches from ALERTS table (where attacks are logged)"""
    try:
        # Fetch unacknowledged alerts (these are the actual attack notifications)
        alerts_res = supabase.table('alerts').select('*').eq('acknowledged', False).order('created_at', desc=True).limit(50).execute()
        
        # Also fetch new incidents if any
        incidents_res = supabase.table('incidents').select('*').eq('status', 'new').order('created_at', desc=True).limit(50).execute()
        
        # Transform alerts to match the expected format for Tier 1
        formatted_alerts = []
        
        for alert in (alerts_res.data or []):
            formatted_alerts.append({
                'id': alert.get('id'),
                'title': alert.get('message', 'Security Alert'),
                'description': f"Source: {alert.get('source', 'Unknown')}\nSeverity: {alert.get('severity', 'medium')}",
                'severity': alert.get('severity', 'medium'),
                'status': 'new' if not alert.get('acknowledged') else 'acknowledged',
                'created_at': alert.get('created_at'),
                'source': alert.get('source'),
                'type': 'alert'
            })
        
        # Also add incidents
        for inc in (incidents_res.data or []):
            formatted_alerts.append({
                'id': inc.get('id'),
                'title': inc.get('title', 'Security Incident'),
                'description': inc.get('description', ''),
                'severity': inc.get('severity', 'medium'),
                'status': inc.get('status', 'new'),
                'created_at': inc.get('created_at'),
                'source': 'Incident',
                'type': 'incident'
            })
        
        # Sort by created_at descending
        formatted_alerts.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        return jsonify({
            "success": True,
            "alerts": formatted_alerts
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/alerts/<alert_id>/action', methods=['POST'])
@require_auth
def handle_alert_action(alert_id):
    """Handle alert actions (investigate, escalate, resolve)"""
    try:
        data = request.get_json()
        action = data.get('action')

        if action == 'resolve':
            update_incident_status(alert_id, 'resolved')
            # Log to incident_responses
            create_incident_response(alert_id, 'Resolved by Analyst', 'SOC-Analyst')
        elif action == 'escalate':
            update_incident_status(alert_id, 'pending_tier2')
        
        return jsonify({
            "success": True,
            "message": f"Alert {alert_id} {action} action completed"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/incidents', methods=['GET'])
@require_auth
def get_all_incidents():
    """Get active security incidents from Supabase"""
    try:
        res = get_incidents()
        return jsonify({
            "success": True,
            "incidents": res.data
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/incidents/<incident_id>/action', methods=['POST'])
@require_auth
def handle_incident_action(incident_id):
    """Handle incident actions (resolve, move to response table)"""
    try:
        data = request.get_json()
        action = data.get('action')

        if action == 'resolve':
            # 1. Add to incident_responses
            create_incident_response(incident_id, 'Resolution Confirmed', 'Lead-Analyst')
            # 2. Update incident status
            update_incident_status(incident_id, 'resolved')
            # 3. Optional: Delete from incidents if user wants 'deletion from list'
            # supabase.table('incidents').delete().eq('id', incident_id).execute()
        
        return jsonify({
            "success": True,
            "message": f"Incident {incident_id} {action} action completed"
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
        
        is_windows = platform.system() == "Windows"
        
        try:
            if is_windows:
                process = subprocess.Popen(
                    ["powershell", "-Command", command],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=True
                )
            else:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=True
                )
            
            stdout, stderr = process.communicate(timeout=10)
            output = stdout if stdout else stderr
            
            return jsonify({
                "success": True, 
                "output": output or "[Success]",
                "returncode": process.returncode
            })
            
        except subprocess.TimeoutExpired:
            process.kill()
            return jsonify({"success": True, "output": "Error: Command timed out"})
        except Exception as e:
            return jsonify({"success": True, "output": f"Error: {str(e)}"})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@api_bp.route('/blocklist', methods=['GET'])
@require_auth
def get_soc_blocklist():
    """Get the current global blocklist from memory/cache (sync with DB if possible)"""
    return jsonify({
        "success": True,
        "ips": BLOCKED_IPS,
        "hosts": BLOCKED_HOSTS
    })

@api_bp.route('/blocklist/add', methods=['POST'])
@require_auth
def add_to_blocklist():
    """Add to blocklist and persist in DB"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        host = data.get('host')
        
        if ip:
            if ip not in BLOCKED_IPS: BLOCKED_IPS.append(ip)
            supabase.table('blocked_ips').upsert({'ip_address': ip, 'reason': 'Manual SOC blocking'}).execute()
        if host and host not in BLOCKED_HOSTS:
            BLOCKED_HOSTS.append(host)
            
        return jsonify({"success": True, "message": "Added to blocklist"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@api_bp.route('/blocklist/remove', methods=['POST'])
@require_auth
def remove_from_blocklist():
    """Remove from blocklist"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        if ip and ip in BLOCKED_IPS:
            BLOCKED_IPS.remove(ip)
            supabase.table('blocked_ips').delete().eq('ip_address', ip).execute()
        return jsonify({"success": True, "message": "Removed from blocklist"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
