from flask import Blueprint, jsonify, request
from integrations.supabase import supabase
from utils.logger import security_logger
import json
from datetime import datetime
from utils.request_utils import get_request_ip

api_bp = Blueprint('alerts', __name__)

@api_bp.route('', methods=['GET'])
def get_alerts():
    """Get all alerts for dashboard"""
    try:
        result = supabase.table('alerts').select('*').order('created_at', desc=True).execute()
        return jsonify(result.data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/soc', methods=['POST'])
def create_soc_alert():
    """Create high-priority SOC alert from frontend vulnerability exploitation"""
    try:
        data = request.get_json()
        
        # Use real IP from frontend if provided, fallback to request utility
        client_ip = get_request_ip()

        # Create alert in database using existing schema
        alert_message = f"CRITICAL SECURITY ALERT: {data.get('title', 'Security Alert')} - {data.get('details', {}).get('vulnerability', 'Unknown vulnerability')} exploited from {data.get('source', 'frontend')} (IP: {client_ip})"
        
        alert_data = {
            'message': alert_message,
            'severity': 'high',
            'source': data.get('source', 'frontend'),
            'acknowledged': False
        }
        
        result = supabase.table('alerts').insert(alert_data).execute()
        
        # Log the critical security event
        security_logger.log_security_event(
            event_type='soc_alert_generated',
            severity='critical',
            details={
                'alert_id': str(result.data[0]['id']),
                'title': data.get('title'),
                'category': data.get('category'),
                'source': data.get('source'),
                'ip_address': client_ip,
                'full_details': data.get('details', {})
            }
        )
        
        return jsonify({
            "success": True,
            "message": "SOC alert created successfully",
            "alertId": str(result.data[0]['id'])
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/<alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    try:
        data = request.get_json()
        acknowledged_by = data.get('acknowledged_by', 'system')
        
        result = supabase.table('alerts').update({
            'status': 'acknowledged',
            'acknowledged_by': acknowledged_by,
            'acknowledged_at': datetime.utcnow().isoformat()
        }).eq('id', alert_id).execute()
        
        return jsonify({
            "success": True,
            "message": "Alert acknowledged successfully"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500