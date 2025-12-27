"""
Suspicious Activity Detection Middleware
Real-time detection of suspicious user behavior for automatic isolation
"""

import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Set
from flask import request, g
from collections import defaultdict
from integrations.supabase import supabase
from incident_response.playbooks import execute_playbook

logger = logging.getLogger(__name__)

class SuspiciousActivityDetector:
    """Real-time suspicious activity detection and response"""
    
    def __init__(self, app=None):
        self.app = app
        self.user_activity = defaultdict(list)  # Track user activities
        self.ip_activity = defaultdict(list)     # Track IP activities
        self.failed_logins = defaultdict(int)    # Track failed login attempts
        self.blocked_ips = set()                # Currently blocked IPs
        self.isolated_users = set()              # Currently isolated users
        
        # Detection thresholds
        self.thresholds = {
            'max_requests_per_minute': 100,      # Max requests per minute per user
            'max_failed_logins': 5,              # Max failed logins before lockout
            'max_different_ips_per_hour': 10,    # Max different IPs per hour per user
            'suspicious_patterns': [             # Suspicious request patterns
                'sql_injection',
                'xss_attempt',
                'path_traversal',
                'ssrf_attempt',
                'command_injection'
            ]
        }
    
    def init_app(self, app):
        """Initialize with Flask app"""
        self.app = app
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        
        # Start background monitoring thread
        self.start_monitoring()
    
    def before_request(self):
        """Run before each request"""
        if request.endpoint and (request.endpoint.startswith('static') or request.path == '/favicon.ico'):
            return  # Skip static files and favicon
        
        # Get user and IP info
        user_email = getattr(g, 'user_email', None)
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        endpoint = request.endpoint
        method = request.method
        
        # Record activity
        timestamp = time.time()
        
        if user_email:
            self.user_activity[user_email].append({
                'timestamp': timestamp,
                'ip': ip_address,
                'endpoint': endpoint,
                'method': method,
                'user_agent': user_agent
            })
        
        self.ip_activity[ip_address].append({
            'timestamp': timestamp,
            'user_email': user_email,
            'endpoint': endpoint,
            'method': method,
            'user_agent': user_agent
        })
        
        # Check for suspicious activity
        self.check_suspicious_activity(user_email, ip_address, request)
    
    def after_request(self, response):
        """Run after each request"""
        # Check for attack patterns in response
        if response.status_code == 200:
            try:
                # Only check JSON if the request actually has JSON content
                if request.is_json:
                    self.check_attack_patterns(request)
            except Exception as e:
                logger.error(f"Error in after_request: {e}")
        
        return response
    
    def check_suspicious_activity(self, user_email: str, ip_address: str, req):
        """Check for suspicious activity patterns"""
        current_time = time.time()
        
        # Check 1: Rate limiting per user
        if user_email:
            recent_requests = [
                activity for activity in self.user_activity[user_email]
                if current_time - activity['timestamp'] <= 60  # Last minute
            ]
            
            if len(recent_requests) > self.thresholds['max_requests_per_minute']:
                self.handle_high_rate_requests(user_email, len(recent_requests))
        
        # Check 2: Multiple IPs for same user
        if user_email:
            recent_activities = [
                activity for activity in self.user_activity[user_email]
                if current_time - activity['timestamp'] <= 3600  # Last hour
            ]
            
            unique_ips = set(activity['ip'] for activity in recent_activities)
            if len(unique_ips) > self.thresholds['max_different_ips_per_hour']:
                self.handle_multiple_ips(user_email, unique_ips)
        
        # Check 3: High activity from single IP
        recent_ip_requests = [
            activity for activity in self.ip_activity[ip_address]
            if current_time - activity['timestamp'] <= 300  # Last 5 minutes
        ]
        
        if len(recent_ip_requests) > 50:  # More than 50 requests in 5 minutes
            self.handle_high_ip_activity(ip_address, len(recent_ip_requests))
    
    def check_attack_patterns(self, req):
        """Check for attack patterns in request"""
        user_email = getattr(g, 'user_email', None)
        ip_address = req.remote_addr
        
        suspicious_patterns = {
            'sql_injection': r"(?i)(union|select|insert|update|delete|drop|exec|script)",
            'xss_attempt': r"(?i)(<script|javascript:|onload=|onerror=)",
            'path_traversal': r"(?i)(\.\./|\.\.\\|%2e%2e%2f)",
            'ssrf_attempt': r"(?i)(http://|https://|ftp://).+@(localhost|127\.0\.0\.1|169\.254\.|192\.168\.|10\.)",
            'command_injection': r"(?i)(;|\||&|`|\$\(|nc |netcat|wget |curl )"
        }
        
        # Check URL parameters
        for param, value in req.args.items():
            for pattern_name, pattern in suspicious_patterns.items():
                import re
                if re.search(pattern, str(value)):
                    self.handle_attack_detected(pattern_name, user_email, ip_address, req.url)
        
        # Check JSON body if present
        if hasattr(req, 'json') and req.json:
            for key, value in req.json.items():
                if isinstance(value, str):
                    for pattern_name, pattern in suspicious_patterns.items():
                        import re
                        if re.search(pattern, value):
                            self.handle_attack_detected(pattern_name, user_email, ip_address, req.url)
    
    def handle_high_rate_requests(self, user_email: str, request_count: int):
        """Handle user making too many requests"""
        # Monitoring logged internally
        
        # Create security alert
        self.create_security_alert(
            'high_rate_requests',
            'medium',
            f'High rate requests: {user_email}',
            f'User {user_email} made {request_count} requests in the last minute',
            user_email
        )
        
        # Auto-isolate if very high rate
        if request_count > 200:
            self.auto_isolate_user(user_email, 'Very high request rate')
    
    def handle_multiple_ips(self, user_email: str, unique_ips: Set[str]):
        """Handle user accessing from multiple IPs"""
        # Monitoring logged internally
        
        # Create security alert
        self.create_security_alert(
            'multiple_ips',
            'medium',
            f'Multiple IPs: {user_email}',
            f'User {user_email} accessed from {len(unique_ips)} different IPs: {list(unique_ips)}',
            user_email
        )
        
        # Auto-isolate if too many IPs
        if len(unique_ips) > 20:
            self.auto_isolate_user(user_email, 'Suspicious multiple IP access')
    
    def handle_high_ip_activity(self, ip_address: str, request_count: int):
        """Handle high activity from single IP"""
        # Monitoring logged internally
        
        # Create security alert
        self.create_security_alert(
            'high_ip_activity',
            'high',
            f'High IP activity: {ip_address}',
            f'IP {ip_address} made {request_count} requests in the last 5 minutes',
            None,
            ip_address
        )
        
        # Auto-block IP if very high activity
        if request_count > 100:
            self.auto_block_ip(ip_address, 'Very high activity')
    
    def handle_attack_detected(self, attack_type: str, user_email: str, ip_address: str, url: str):
        """Handle detected attack pattern"""
        # Attack logged internally
        
        # Create high-priority security alert
        alert_id = self.create_security_alert(
            attack_type,
            'critical',
            f'Attack detected: {attack_type}',
            f'{attack_type} attack detected from {ip_address} at {url}',
            user_email,
            ip_address,
            url
        )
        
        # Immediate auto-isolation for attacks
        if user_email:
            self.auto_isolate_user(user_email, f'{attack_type} attack detected')
        
        # Auto-block IP for attacks
        self.auto_block_ip(ip_address, f'{attack_type} attack detected')
    
    def auto_isolate_user(self, user_email: str, reason: str):
        """Automatically isolate a user"""
        if user_email in self.isolated_users:
            return  # Already isolated
        
        try:
            # Get user ID
            user_result = supabase.table('users').select('id').eq('email', user_email).execute()
            if not user_result.data:
                return
            
            user_id = user_result.data[0]['id']
            
            # Execute user isolation playbook
            result = execute_playbook("user_isolation", user_id, 
                                    user_email=user_email, severity="critical")
            
            if result.get('success'):
                self.isolated_users.add(user_email)
                logger.critical(f"Auto-isolated user: {user_email} - {reason}")
            else:
                logger.error(f"Failed to auto-isolate user {user_email}: {result.get('error')}")
                
        except Exception as e:
            logger.error(f"Error auto-isolating user {user_email}: {e}")
    
    def auto_block_ip(self, ip_address: str, reason: str):
        """Automatically block an IP address"""
        if ip_address in self.blocked_ips:
            return  # Already blocked
        
        try:
            # Execute IP blacklist playbook
            result = execute_playbook("ip_blacklist", ip_address, severity="critical")
            
            if result.get('success'):
                self.blocked_ips.add(ip_address)
                logger.critical(f"Auto-blocked IP: {ip_address} - {reason}")
            else:
                logger.error(f"Failed to auto-block IP {ip_address}: {result.get('error')}")
                
        except Exception as e:
            logger.error(f"Error auto-blocking IP {ip_address}: {e}")
    
    def create_security_alert(self, alert_type: str, severity: str, title: str, 
                           description: str, user_email: str = None, 
                           source_ip: str = None, target_url: str = None) -> str:
        """Create a security alert in the database"""
        try:
            alert_data = {
                'type': alert_type,
                'severity': severity,
                'title': title,
                'description': description,
                'user_email': user_email,
                'source_ip': source_ip,
                'target_url': target_url,
                'created_at': datetime.utcnow().isoformat(),
                'status': 'new'
            }
            
            result = supabase.table('security_alerts').insert(alert_data).execute()
            
            if result.data:
                return result.data[0]['id']
            return None
            
        except Exception:
            # Silent failure for console cleanup
            return None
    
    def start_monitoring(self):
        """Start background monitoring thread"""
        import threading
        
        def monitor():
            while True:
                try:
                    # Clean old activity data
                    current_time = time.time()
                    cutoff_time = current_time - 3600  # Keep only last hour
                    
                    # Clean user activity
                    for user_email in list(self.user_activity.keys()):
                        self.user_activity[user_email] = [
                            activity for activity in self.user_activity[user_email]
                            if activity['timestamp'] > cutoff_time
                        ]
                        if not self.user_activity[user_email]:
                            del self.user_activity[user_email]
                    
                    # Clean IP activity
                    for ip_address in list(self.ip_activity.keys()):
                        self.ip_activity[ip_address] = [
                            activity for activity in self.ip_activity[ip_address]
                            if activity['timestamp'] > cutoff_time
                        ]
                        if not self.ip_activity[ip_address]:
                            del self.ip_activity[ip_address]
                    
                    # Sleep for 5 minutes
                    time.sleep(300)
                    
                except Exception as e:
                    logger.error(f"Monitoring thread error: {e}")
                    time.sleep(60)  # Wait 1 minute before retrying
        
        # Start daemon thread
        monitor_thread = threading.Thread(target=monitor, daemon=True)
        monitor_thread.start()
        logger.info("Suspicious activity monitoring started")
    
    def get_suspicious_users(self, hours: int = 24) -> List[Dict]:
        """Get list of suspicious users in the last N hours"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        try:
            result = supabase.table('security_alerts')\
                .select('*')\
                .gte('created_at', cutoff_time.isoformat())\
                .not_('user_email', 'is', None)\
                .execute()
            
            # Count alerts per user
            user_alert_counts = defaultdict(int)
            for alert in result.data or []:
                user_alert_counts[alert['user_email']] += 1
            
            # Return users with multiple alerts
            suspicious_users = [
                {'user_email': email, 'alert_count': count}
                for email, count in user_alert_counts.items()
                if count >= 3
            ]
            
            return sorted(suspicious_users, key=lambda x: x['alert_count'], reverse=True)
            
        except Exception as e:
            logger.error(f"Failed to get suspicious users: {e}")
            return []
    
    def get_suspicious_ips(self, hours: int = 24) -> List[Dict]:
        """Get list of suspicious IPs in the last N hours"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        try:
            result = supabase.table('security_alerts')\
                .select('*')\
                .gte('created_at', cutoff_time.isoformat())\
                .not_('source_ip', 'is', None)\
                .execute()
            
            # Count alerts per IP
            ip_alert_counts = defaultdict(int)
            for alert in result.data or []:
                ip_alert_counts[alert['source_ip']] += 1
            
            # Return IPs with multiple alerts
            suspicious_ips = [
                {'ip_address': ip, 'alert_count': count}
                for ip, count in ip_alert_counts.items()
                if count >= 2
            ]
            
            return sorted(suspicious_ips, key=lambda x: x['alert_count'], reverse=True)
            
        except Exception as e:
            logger.error(f"Failed to get suspicious IPs: {e}")
            return []

# Flask middleware integration
detector = SuspiciousActivityDetector()

def SuspiciousActivityDetectorMiddleware(app):
    """Initialize suspicious activity detector middleware"""
    detector.init_app(app)
    return detector
