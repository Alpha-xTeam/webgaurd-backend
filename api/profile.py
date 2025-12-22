from flask import Blueprint, request, jsonify
from models.user import get_user_by_id, get_all_users
from api.auth import token_required

api_bp = Blueprint('profile', __name__)

@api_bp.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    """Get current user profile"""
    try:
        user_data = get_user_by_id(current_user['user_id'])
        if not user_data.data:
            return jsonify({'error': 'User not found'}), 404
            
        user = user_data.data[0]
        
        # Remove sensitive data
        profile_data = {
            'id': user['id'],
            'email': user['email'],
            'role': user['role'],
            'firstName': user.get('first_name', 'مستخدم'), # Fallback if not set
            'lastName': user.get('last_name', 'جديد'),
            'createdAt': user['created_at'],
            'twoFactorEnabled': user.get('two_factor_enabled', False)
        }
        
        return jsonify({'profile': profile_data}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

from utils.session_store import is_user_active

@api_bp.route('/users', methods=['GET'])
@token_required
def list_users(current_user):
    """List all users (Admin/SOC/Owner only)"""
    if current_user['role'] not in ['admin', 'soc_team', 'owner']:
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        users_data = get_all_users()
        users = []
        for u in users_data.data:
            is_active = is_user_active(u['id'])
            users.append({
                'id': u['id'],
                'email': u['email'],
                'role': u['role'],
                'name': f"{u.get('first_name', 'مستخدم')} {u.get('last_name', '')}",
                'status': 'active' if is_active else 'offline',
                'lastActive': u['created_at'] # We could improve this if we stored last_seen in DB too
            })
            
        return jsonify({'users': users}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
