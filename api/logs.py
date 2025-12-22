from flask import Blueprint, jsonify, request
from middleware.auth_guard import require_auth
import json
from datetime import datetime, timedelta
from integrations.supabase import supabase
from utils.request_utils import get_request_ip

api_bp = Blueprint('logs', __name__)

@api_bp.route('', methods=['GET'])
@require_auth
def get_logs():
    """Get system logs with filtering and pagination"""
    try:
        # Get query parameters
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 50))
        level = request.args.get('level', 'all')
        log_type = request.args.get('type', 'all')
        date_from = request.args.get('dateFrom', '')
        date_to = request.args.get('dateTo', '')
        search = request.args.get('search', '')

        # Build query
        query = supabase.table('logs').select('*', count='exact')

        # Apply filters
        if level != 'all':
            query = query.eq('level', level)

        if log_type != 'all':
            query = query.eq('source', log_type)

        if date_from:
            query = query.gte('created_at', date_from)

        if date_to:
            query = query.lte('created_at', date_to + 'T23:59:59Z')

        if search:
            query = query.ilike('message', f'%{search}%')

        # Order by created_at desc
        query = query.order('created_at', desc=True)

        # Get total count
        total_result = query.execute()
        total_logs = total_result.count

        # Apply pagination
        offset = (page - 1) * limit
        query = query.range(offset, offset + limit - 1)

        # Execute query
        result = query.execute()
        logs = result.data

        # Format logs for frontend
        formatted_logs = []
        for log in logs:
            # Determine user display name
            user_display = log.get('user_id')
            if not user_display:
                # Fallback logic for demo/system logs
                if "User 'admin'" in log['message']:
                    user_display = "admin"
                elif log.get('source') in ['system', 'monitor', 'backup', 'firewall']:
                    user_display = "System"
                else:
                    user_display = "Unknown"

            formatted_logs.append({
                "id": str(log['id']),
                "timestamp": log['created_at'],
                "level": log['level'],
                "type": log.get('source', 'system'),
                "user": user_display,
                "ipAddress": str(log.get('ip_address', '')) if log.get('ip_address') else 'N/A',
                "message": log['message'],
                "details": {
                    "userAgent": log.get('user_agent', ''),
                    "source": log.get('source', '')
                }
            })

        total_pages = (total_logs + limit - 1) // limit

        return jsonify({
            "success": True,
            "logs": formatted_logs,
            "totalPages": total_pages,
            "currentPage": page,
            "totalLogs": total_logs
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/stats', methods=['GET'])
@require_auth
def get_log_stats():
    """Get log statistics"""
    try:
        # Get all logs for stats
        result = supabase.table('logs').select('level, source').execute()
        logs = result.data

        total_logs = len(logs)
        error_count = len([log for log in logs if log['level'] == 'error'])
        warn_count = len([log for log in logs if log['level'] == 'warn'])
        info_count = len([log for log in logs if log['level'] == 'info'])
        debug_count = len([log for log in logs if log['level'] == 'debug'])

        security_logs = len([log for log in logs if log.get('source') == 'security'])
        auth_logs = len([log for log in logs if log.get('source') == 'auth'])
        api_logs = len([log for log in logs if log.get('source') == 'api'])
        user_logs = len([log for log in logs if log.get('source') == 'user'])
        system_logs = len([log for log in logs if log.get('source') == 'system'])

        return jsonify({
            "success": True,
            "stats": {
                "totalLogs": total_logs,
                "byLevel": {
                    "error": error_count,
                    "warn": warn_count,
                    "info": info_count,
                    "debug": debug_count
                },
                "byType": {
                    "security": security_logs,
                    "auth": auth_logs,
                    "api": api_logs,
                    "user": user_logs,
                    "system": system_logs
                }
            }
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/fix', methods=['POST'])
@require_auth
def log_vulnerability_fix():
    """Log vulnerability fix attempts"""
    try:
        data = request.get_json()

        # Insert into database
        result = supabase.table('logs').insert({
            'level': 'info',
            'message': f"Vulnerability auto-fix: {data.get('description', 'Unknown fix')}",
            'source': 'security',
            'user_id': None,  # or get from auth
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent')
        }).execute()

        return jsonify({
            "success": True,
            "message": "Vulnerability fix logged successfully",
            "logId": str(result.data[0]['id'])
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/security', methods=['POST'])
def log_security_event():
    """Log security events from frontend (vulnerability exploitation, etc.)"""
    try:
        data = request.get_json()
        # Use real IP from frontend if provided, fallback to request utility
        client_ip = get_request_ip()

        # Log the security event
        from utils.logger import security_logger
        security_logger.log_security_event(
            event_type=data.get('event_type', 'unknown_security_event'),
            severity=data.get('severity', 'medium'),
            details=data.get('details', {}),
            ip=client_ip
        )
        
        # Also store in database for dashboard
        result = supabase.table('logs').insert({
            'level': 'warning' if data.get('severity') == 'medium' else 'error',
            'message': f"Security Event: {data.get('event_type', 'unknown')} - {data.get('details', {})}",
            'source': 'security_frontend',
            'user_id': None,
            'ip_address': client_ip,
            'user_agent': request.headers.get('User-Agent')
        }).execute()
        
        return jsonify({
            "success": True,
            "message": "Security event logged successfully",
            "logId": str(result.data[0]['id'])
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@api_bp.route('/seed', methods=['POST'])
def seed_logs():
    """Seed database with sample logs for demonstration"""
    try:
        # Check if logs already exist
        check = supabase.table('logs').select('id', count='exact').limit(1).execute()
        if check.count > 0:
            return jsonify({"success": True, "message": "Logs already exist", "count": check.count})

        sample_logs = [
            {
                "level": "info",
                "message": "System startup sequence initiated",
                "source": "system",
                "user_id": None,
                "ip_address": "127.0.0.1",
                "created_at": (datetime.now() - timedelta(hours=2)).isoformat()
            },
            {
                "level": "info",
                "message": "Database connection established successfully",
                "source": "system",
                "user_id": None,
                "ip_address": "127.0.0.1",
                "created_at": (datetime.now() - timedelta(hours=1, minutes=59)).isoformat()
            },
            {
                "level": "warn",
                "message": "High memory usage detected (85%)",
                "source": "monitor",
                "user_id": None,
                "ip_address": "192.168.1.5",
                "created_at": (datetime.now() - timedelta(hours=1, minutes=30)).isoformat()
            },
            {
                "level": "info",
                "message": "User login successful",
                "source": "auth",
                "user_id": None,
                "ip_address": "192.168.1.10",
                "created_at": (datetime.now() - timedelta(minutes=45)).isoformat()
            },
            {
                "level": "error",
                "message": "Failed login attempt: Invalid password",
                "source": "auth",
                "user_id": None,
                "ip_address": "203.0.113.42",
                "created_at": (datetime.now() - timedelta(minutes=40)).isoformat()
            },
            {
                "level": "error",
                "message": "Failed login attempt: Invalid password (Repeated)",
                "source": "auth",
                "user_id": None,
                "ip_address": "203.0.113.42",
                "created_at": (datetime.now() - timedelta(minutes=39)).isoformat()
            },
            {
                "level": "warn",
                "message": "Potential Brute Force detected from 203.0.113.42",
                "source": "security",
                "user_id": None,
                "ip_address": "203.0.113.42",
                "created_at": (datetime.now() - timedelta(minutes=38)).isoformat()
            },
            {
                "level": "info",
                "message": "IP 203.0.113.42 has been temporarily blocked",
                "source": "firewall",
                "user_id": None,
                "ip_address": "127.0.0.1",
                "created_at": (datetime.now() - timedelta(minutes=38)).isoformat()
            },
            {
                "level": "info",
                "message": "Scheduled backup completed successfully",
                "source": "backup",
                "user_id": None,
                "ip_address": "127.0.0.1",
                "created_at": (datetime.now() - timedelta(minutes=15)).isoformat()
            },
            {
                "level": "info",
                "message": "User 'admin' viewed Audit Logs",
                "source": "audit",
                "user_id": None,
                "ip_address": "192.168.1.10",
                "created_at": datetime.now().isoformat()
            }
        ]

        for log in sample_logs:
            supabase.table('logs').insert(log).execute()

        return jsonify({
            "success": True,
            "message": f"Successfully seeded {len(sample_logs)} logs"
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500