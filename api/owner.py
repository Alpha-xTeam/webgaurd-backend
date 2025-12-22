from flask import Blueprint, jsonify
from models.incident import get_incidents
from models.alert import get_alerts
from datetime import datetime
import statistics

api_bp = Blueprint('owner', __name__)

import json
import os

@api_bp.route('/kpis')
def get_kpis():
    try:
        incidents = get_incidents().data
        alerts = get_alerts().data
        
        # Calculate TP/FP
        true_positives = len([a for a in alerts if a.get('status') == 'resolved'])
        false_positives = len([a for a in alerts if a.get('status') == 'false_positive'])
        total_resolved = true_positives + false_positives
        tp_fp_ratio = round(true_positives / total_resolved * 100, 1) if total_resolved > 0 else 0

        # Calculate MTTR (Mean Time To Respond/Resolve)
        # Time from Incident Creation -> Incident Closed
        resolved_incidents = [i for i in incidents if i.get('status') == 'closed']
        if resolved_incidents:
            response_times = []
            for inc in resolved_incidents:
                created = datetime.fromisoformat(inc['created_at'].replace('Z', '+00:00'))
                updated = datetime.fromisoformat(inc['updated_at'].replace('Z', '+00:00')) if inc.get('updated_at') else datetime.now()
                response_times.append((updated - created).total_seconds() / 3600) # Hours
            
            mttr_hours = round(statistics.mean(response_times), 1)
        else:
            mttr_hours = 0

        # Calculate MTTA (Mean Time To Acknowledge)
        # Time from Alert Creation -> Alert Acknowledged
        acknowledged_alerts = [a for a in alerts if a.get('acknowledged_at')]
        if acknowledged_alerts:
            ack_times = []
            for alert in acknowledged_alerts:
                created = datetime.fromisoformat(alert['created_at'].replace('Z', '+00:00'))
                acked = datetime.fromisoformat(alert['acknowledged_at'].replace('Z', '+00:00'))
                ack_times.append((acked - created).total_seconds() / 60) # Minutes
            
            mtta_minutes = round(statistics.mean(ack_times), 1)
        else:
            mtta_minutes = 0

        return jsonify({
            'mttd': f"{mtta_minutes} min", # Sending MTTA as MTTD for frontend compatibility or we can rename in frontend
            'mttr': f"{mttr_hours} hrs",
            'tp_fp_ratio': f"{true_positives}/{false_positives}",
            'detection_accuracy': f"{tp_fp_ratio}%",
            'active_incidents': len([i for i in incidents if i.get('status') != 'closed']),
            'critical_alerts': len([a for a in alerts if a.get('severity') == 'critical'])
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/subscription')
def get_subscription():
    try:
        file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'subscription.json')
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                data = json.load(f)
            return jsonify(data), 200
        else:
            # Fallback if file doesn't exist
            return jsonify({
                'plan': 'Standard',
                'status': 'active',
                'renewal_date': '2025-12-31',
                'licenses_used': 0,
                'licenses_total': 10,
                'features': ['Basic Protection']
            }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
