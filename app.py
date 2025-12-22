from flask import Flask
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

    # Enable CORS with full support for all HTTP methods
    CORS(app, 
         origins=app.config['CORS_ORIGINS'],
         allow_headers=['Content-Type', 'Authorization'],
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'])

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

    # Create upload directory if it doesn't exist
    upload_folder = app.config.get('UPLOAD_FOLDER')
    if not upload_folder:
        upload_folder = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
        app.config['UPLOAD_FOLDER'] = upload_folder
    
    os.makedirs(upload_folder, exist_ok=True)

    @app.route('/')
    def index():
        return {"message": "Welcome to WebGuard-IR Internal API", "status": "active", "access": "granted"}

    @app.route('/favicon.ico')
    def favicon():
        from flask import send_from_directory
        import os
        # Return a simple 204 No Content for favicon to avoid errors
        return '', 204

    return app

if __name__ == '__main__':
    # Suppress Flask/Werkzeug logging
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    # Suppress other loggers
    logging.getLogger('urllib3').setLevel(logging.ERROR)
    logging.getLogger('requests').setLevel(logging.ERROR)

    app = create_app()
    
    # Custom startup message - only print in the reloader process or if debug is off
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or not app.config['DEBUG']:
        print("\n" + "="*50)
        print("  WebGuard-IR Backend Server")
        print("  Status: Running")
        print("  URL: http://127.0.0.1:5000")
        print("="*50 + "\n")

    app.run(
        debug=app.config['DEBUG'],
        host='0.0.0.0',
        port=5000,
        threaded=True
    )