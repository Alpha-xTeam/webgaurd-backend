from flask import Flask, request, make_response
from flask_cors import CORS
from config import Config
from api.auth import api_bp as auth_bp
from api.admin import api_bp as admin_bp
from api.upload import api_bp as upload_bp
from api.vulnerable import api_bp as vulnerable_bp
from api.news import api_bp as news_bp
from api.security import api_bp as security_bp
from api.logs import api_bp as logs_bp
from api.alerts import api_bp as alerts_bp
from api.profile import api_bp as profile_bp
from api.owner import api_bp as owner_bp
from api.attacker import api_bp as attacker_bp
from api.playbooks import api_bp as playbooks_bp
from api.memory_dump import api_bp as memory_dump_bp
from middleware.request_logger import RequestLoggerMiddleware
from middleware.auth_guard import AuthGuardMiddleware
from middleware.threat_detector import ThreatDetectorMiddleware
from middleware.suspicious_activity_detector import SuspiciousActivityDetectorMiddleware
from middleware.ip_blocker import IPBlockerMiddleware
import os

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Super permissive CORS globally
    CORS(app, resources={r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        "allow_headers": ["Content-Type", "Authorization", "X-User-Email"],
        "supports_credentials": True
    }})

    @app.after_request
    def add_cors_headers(response):
        origin = request.headers.get('Origin')
        if origin:
            response.headers['Access-Control-Allow-Origin'] = origin
        else:
            response.headers['Access-Control-Allow-Origin'] = '*'
            
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-User-Email'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response

    @app.before_request
    def handle_preflight():
        if request.method == 'OPTIONS':
            res = make_response()
            res.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
            res.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH'
            res.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-User-Email'
            res.headers['Access-Control-Allow-Credentials'] = 'true'
            return res, 200

    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/api')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    app.register_blueprint(upload_bp, url_prefix='/api')
    app.register_blueprint(vulnerable_bp, url_prefix='/api')
    app.register_blueprint(news_bp, url_prefix='/api')
    app.register_blueprint(security_bp, url_prefix='/api/security')
    app.register_blueprint(logs_bp, url_prefix='/api/logs')
    app.register_blueprint(alerts_bp, url_prefix='/api/alerts')
    app.register_blueprint(profile_bp, url_prefix='/api')
    app.register_blueprint(owner_bp, url_prefix='/api/owner')
    app.register_blueprint(attacker_bp, url_prefix='/api/attacker')
    app.register_blueprint(playbooks_bp, url_prefix='/api/playbooks')
    app.register_blueprint(memory_dump_bp, url_prefix='/api/memory-dump')

    # Initialize middleware
    RequestLoggerMiddleware(app)
    IPBlockerMiddleware(app)
    AuthGuardMiddleware(app)
    ThreatDetectorMiddleware(app)
    SuspiciousActivityDetectorMiddleware(app)

    # Create upload directory
    upload_folder = app.config.get('UPLOAD_FOLDER', os.path.join(os.getcwd(), 'uploads'))
    os.makedirs(upload_folder, exist_ok=True)

    @app.route('/')
    def index():
        return {"message": "Welcome to WebGuard-IR Internal API (Live on PythonAnywhere)", "status": "active"}

    @app.route('/favicon.ico')
    def favicon():
        return '', 204

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)