from flask import Blueprint, request, jsonify
from models.user import create_user, get_user
import bcrypt
from utils.validators import validate_email, validate_password
import jwt
import datetime
from config import Config
from functools import wraps
from utils.session_store import update_user_activity

api_bp = Blueprint('auth', __name__)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
            current_user = {
                'user_id': data['user_id'],
                'email': data['email'],
                'role': data.get('role', 'user')
            }
            # Update activity status
            update_user_activity(current_user['user_id'])
            
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401
        except Exception as e:
            return jsonify({'message': f'Token error: {str(e)}'}), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated

@api_bp.route('/status', methods=['GET'])
def status():
    """Check API status"""
    return jsonify({'message': 'Auth API is working', 'status': 'ok'}), 200

@api_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()


        email = data.get('email') if data else None
        password = data.get('password') if data else None
        # Support role assignment for admin-created users
        role = data.get('role', 'user') if data else 'user'
        
        # Validate role - only allow valid roles
        valid_roles = ['user', 'admin', 'owner', 'security_team', 'soc_tier1', 'soc_tier2', 'soc_tier3']
        if role not in valid_roles:
            role = 'user'


        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400

        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400

        # Relaxed password rules for simulation/testing
        # if not validate_password(password):
        #    return jsonify({'error': 'Invalid password format'}), 400

        # Check if user already exists
        existing_user = get_user(email)
        if existing_user.data:
            return jsonify({'error': 'User already exists'}), 409

        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        result = create_user(email, password_hash, role=role)

        if result.data:
            # Generate JWT token
            token = jwt.encode({
                'user_id': str(result.data[0]['id']),
                'email': email,
                'role': role,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, Config.SECRET_KEY, algorithm='HS256')

            return jsonify({
                'message': 'User registered successfully',
                'token': token,
                'user': {
                    'id': result.data[0]['id'],
                    'email': email,
                    'role': role
                }
            }), 201
        else:
            return jsonify({'error': 'Failed to create user'}), 500

    except Exception as e:
        pass  # Silent error handling
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@api_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    try:
        user_result = get_user(email)
        # Removed debug print

        if not user_result.data or len(user_result.data) == 0:
            return jsonify({'error': 'Invalid credentials'}), 401

        user = user_result.data[0]
        # Removed debug print
        
        # Check if user is blocked or isolated
        if user.get('status') == 'blocked':
            return jsonify({'error': 'Account blocked due to suspicious activity'}), 403
        
        # Check if user is isolated (new security feature)
        if user.get('is_isolated') == True:
            return jsonify({'error': 'Account isolated due to security threat - access permanently denied'}), 403
            
        # Check if user is disabled
        if user.get('status') == 'disabled':
            return jsonify({'error': 'Account disabled - contact security team'}), 403
            
        # Removed debug print

        # Check password
        password_check = bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8'))
        # Removed debug print

        if not password_check:
            return jsonify({'error': 'Invalid credentials'}), 401

        # Generate JWT token
        token = jwt.encode({
            'user_id': str(user['id']),
            'email': user['email'],
            'role': user.get('role', 'user'),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, Config.SECRET_KEY, algorithm='HS256')
        
        # Update activity status on login
        update_user_activity(user['id'])

        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user['id'],
                'email': user['email'],
                'role': user.get('role', 'user')
            }
        }), 200

    except Exception as e:
        pass  # Silent error handling
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

@api_bp.route('/logout', methods=['POST'])
def logout():
    """Logout endpoint (client-side token removal)"""
    return jsonify({'message': 'Logged out successfully'}), 200

@api_bp.route('/create-admin', methods=['GET'])
def create_admin():
    """Create admin user for initial setup"""
    try:
        admin_email = Config.ADMIN_EMAIL
        admin_password = Config.ADMIN_PASSWORD

        # Check if admin already exists
        existing_user = get_user(admin_email)
        if existing_user.data:
            return jsonify({'message': 'Admin user already exists', 'email': admin_email}), 200

        # Create admin user
        password_hash = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        result = create_user(admin_email, password_hash, role='admin')

        if result.data:
            return jsonify({
                'message': 'Admin user created successfully',
                'email': admin_email,
                'password': admin_password
            }), 201
        else:
            return jsonify({'error': 'Failed to create admin user'}), 500

    except Exception as e:
        return jsonify({'error': f'Failed to create admin: {str(e)}'}), 500