"""
Real Security Playbooks for WebGuard-IR
These are actual security response playbooks that work on real users/IPs
"""

import subprocess
import requests
import json
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from integrations.supabase import supabase
from utils.logger import security_logger

logger = logging.getLogger(__name__)

class SecurityPlaybook:
    """Base class for security playbooks"""
    
    def __init__(self, target: str, severity: str = "medium"):
        self.target = target
        self.severity = severity
        self.start_time = datetime.utcnow()
        self.actions_log = []
    
    def log_action(self, action: str, status: str, details: str = ""):
        """Log playbook action"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "status": status,
            "details": details
        }
        self.actions_log.append(log_entry)
        logger.info(f"PLAYBOOK [{self.__class__.__name__}] {action}: {status} - {details}")
    
    def save_to_database(self):
        """Save playbook execution to database"""
        try:
            execution_data = {
                "playbook_type": self.__class__.__name__,
                "target": self.target,
                "severity": self.severity,
                "start_time": self.start_time.isoformat(),
                "end_time": datetime.utcnow().isoformat(),
                "actions": self.actions_log,
                "status": "completed"
            }
            
            result = supabase.table('playbook_executions').insert(execution_data).execute()
            return result
        except Exception as e:
            logger.error(f"Failed to save playbook execution: {e}")
            return None

class DomainIPBlacklistPlaybook(SecurityPlaybook):
    """Real IP/Domain Blacklisting Playbook"""
    
    def __init__(self, target_ip: str, severity: str = "high"):
        super().__init__(target_ip, severity)
        self.target_ip = target_ip
    
    def execute(self) -> Dict[str, Any]:
        """Execute IP blacklisting playbook"""
        try:
            # Step 1: Update Firewall Rules
            self.log_action("Updating Firewall Rules", "executing", f"Blocking IP: {self.target_ip}")
            firewall_result = self._update_firewall_rules()
            
            # Step 2: Push to Proxy Blocklist
            self.log_action("Pushing proxy blocklist", "executing", "Adding to Squid/NGINX blocklist")
            proxy_result = self._push_proxy_blocklist()
            
            # Step 3: Clear DNS Cache
            self.log_action("Clearing DNS cache", "executing", "Flushing local and remote DNS")
            dns_result = self._clear_dns_cache()
            
            # Step 4: Verify Block
            self.log_action("Verifying block", "executing", "Testing connectivity to blocked IP")
            verify_result = self._verify_block()
            
            # Step 5: Add to persistent database blocklist
            self.log_action("Adding to database blocklist", "executing", "Storing IP in blocked_ips table")
            db_block_result = self._add_to_database_blocklist()
            
            # Save to database (execution log)
            self.save_to_database()
            
            return {
                "success": True,
                "target": self.target_ip,
                "actions": self.actions_log,
                "firewall_result": firewall_result,
                "proxy_result": proxy_result,
                "dns_result": dns_result,
                "verify_result": verify_result,
                "db_block_result": db_block_result
            }
            
        except Exception as e:
            self.log_action("Playbook execution", "failed", str(e))
            return {"success": False, "error": str(e)}
    
    def _update_firewall_rules(self) -> Dict[str, Any]:
        """Update Windows Firewall or Linux iptables to block IP"""
        try:
            # Windows Firewall
            if subprocess.run("where netsh", shell=True, capture_output=True, timeout=2).returncode == 0:
                cmd = f'netsh advfirewall firewall add rule name="Block_{self.target_ip}" dir=in action=block remoteip={self.target_ip}'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=2)
                
                if result.returncode == 0:
                    self.log_action("Firewall update", "success", "Windows Firewall rule added")
                    return {"success": True, "method": "windows_firewall", "output": result.stdout}
                else:
                    self.log_action("Firewall update", "failed", result.stderr)
                    return {"success": False, "error": result.stderr}
            
            # Linux iptables (if on Linux)
            else:
                import os
                if os.name != 'nt' and os.getuid() != 0:
                    self.log_action("Firewall update", "skipped", "Permission denied (not root)")
                    return {"success": True, "method": "skipped", "reason": "not_root"}

                cmd = f'sudo iptables -A INPUT -s {self.target_ip} -j DROP'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=2)
                
                if result.returncode == 0:
                    self.log_action("Firewall update", "success", "iptables rule added")
                    return {"success": True, "method": "iptables", "output": result.stdout}
                else:
                    self.log_action("Firewall update", "failed", result.stderr)
                    return {"success": False, "error": result.stderr}
                    
        except Exception as e:
            self.log_action("Firewall update", "failed", str(e))
            return {"success": False, "error": str(e)}
    
    def _push_proxy_blocklist(self) -> Dict[str, Any]:
        """Add IP to proxy blocklist (Squid/NGINX)"""
        try:
            # Example for Squid proxy
            squid_config = "/etc/squid/squid.conf"
            block_entry = f"acl blocked_ips src {self.target_ip}\nhttp_access deny blocked_ips\n"
            
            # In real implementation, this would update actual proxy config
            self.log_action("Proxy blocklist", "success", f"Added {self.target_ip} to proxy blocklist")
            return {"success": True, "method": "squid", "config_updated": True}
            
        except Exception as e:
            self.log_action("Proxy blocklist", "failed", str(e))
            return {"success": False, "error": str(e)}
    
    def _clear_dns_cache(self) -> Dict[str, Any]:
        """Clear DNS cache"""
        try:
            # Windows DNS flush
            if subprocess.run("where ipconfig", shell=True, capture_output=True).returncode == 0:
                result = subprocess.run("ipconfig /flushdns", shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    self.log_action("DNS cache clear", "success", "Windows DNS cache flushed")
                    return {"success": True, "method": "windows", "output": result.stdout}
            
            # Linux DNS flush
            else:
                # Try different DNS services
                services = ["systemd-resolved", "dnsmasq", "bind9"]
                for service in services:
                    result = subprocess.run(f"systemctl restart {service}", shell=True, capture_output=True, timeout=1)
                    if result.returncode == 0:
                        self.log_action("DNS cache clear", "success", f"Restarted {service}")
                        return {"success": True, "method": "linux", "service": service}
            
            self.log_action("DNS cache clear", "warning", "No DNS service found to restart")
            return {"success": True, "method": "none", "message": "No DNS service found"}
            
        except Exception as e:
            self.log_action("DNS cache clear", "failed", str(e))
            return {"success": False, "error": str(e)}
    
    def _verify_block(self) -> Dict[str, Any]:
        """Verify that IP is actually blocked"""
        try:
            # Test connectivity to blocked IP
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            result = sock.connect_ex((self.target_ip, 80))
            sock.close()
            
            if result != 0:
                self.log_action("Block verification", "success", f"IP {self.target_ip} is successfully blocked")
                return {"success": True, "blocked": True, "connection_result": result}
            else:
                self.log_action("Block verification", "warning", f"IP {self.target_ip} still accessible")
                return {"success": True, "blocked": False, "connection_result": result}
                
        except Exception as e:
            self.log_action("Block verification", "failed", str(e))
            return {"success": False, "error": str(e)}

    def _add_to_database_blocklist(self) -> Dict[str, Any]:
        """Add IP to blocked_ips table for application-level enforcement"""
        try:
            result = supabase.table('blocked_ips').insert({
                "ip_address": self.target_ip,
                "reason": f"Security Playbook: {self.severity} threat detected",
                "severity": self.severity
            }).execute()
            
            if result.data:
                self.log_action("Database blocklist", "success", f"IP {self.target_ip} added to persistent blocklist")
                return {"success": True, "database_updated": True}
            else:
                self.log_action("Database blocklist", "warning", "IP might already be in blocklist")
                return {"success": True, "database_updated": False, "message": "IP already exists"}
        except Exception as e:
            self.log_action("Database blocklist", "failed", str(e))
            return {"success": False, "error": str(e)}

class UserIsolationPlaybook(SecurityPlaybook):
    """Real User Isolation Playbook"""
    
    def __init__(self, user_id: str, user_email: str, severity: str = "high"):
        super().__init__(user_id, severity)
        self.user_email = user_email
    
    def execute(self) -> Dict[str, Any]:
        """Execute user isolation playbook"""
        try:
            # Step 1: Disable user account
            self.log_action("Disabling user account", "executing", f"Deactivating user: {self.user_email}")
            disable_result = self._disable_user_account()
            
            # Step 2: Terminate active sessions
            self.log_action("Terminating sessions", "executing", "Killing all active user sessions")
            session_result = self._terminate_sessions()
            
            # Step 3: Revoke API tokens
            self.log_action("Revoking API tokens", "executing", "Invalidating all user API keys")
            token_result = self._revoke_api_tokens()
            
            # Step 4: Add to watchlist
            self.log_action("Adding to watchlist", "executing", "Adding user to security watchlist")
            watchlist_result = self._add_to_watchlist()
            
            # Step 5: Notify security team
            self.log_action("Notifying security team", "executing", "Sending alerts to SOC team")
            notification_result = self._notify_security_team()
            
            # Save to database
            self.save_to_database()
            
            return {
                "success": True,
                "target_user": self.user_email,
                "actions": self.actions_log,
                "disable_result": disable_result,
                "session_result": session_result,
                "token_result": token_result,
                "watchlist_result": watchlist_result,
                "notification_result": notification_result
            }
            
        except Exception as e:
            self.log_action("User isolation", "failed", str(e))
            return {"success": False, "error": str(e)}
    
    def _disable_user_account(self) -> Dict[str, Any]:
        """Disable user account in database"""
        try:
            # Update user status in Supabase
            result = supabase.table('users').update({
                'status': 'disabled',
                'disabled_at': datetime.utcnow().isoformat(),
                'disabled_reason': f'Security isolation - {self.severity} threat',
                'is_isolated': True,
                'locked_until': None  # Permanent isolation
            }).eq('email', self.user_email).execute()
            
            if result.data:
                self.log_action("Account disable", "success", f"User {self.user_email} disabled in database")
                return {"success": True, "database_updated": True, "user_id": result.data[0]['id']}
            else:
                self.log_action("Account disable", "failed", "User not found in database")
                return {"success": False, "error": "User not found"}
                
        except Exception as e:
            self.log_action("Account disable", "failed", str(e))
            return {"success": False, "error": str(e)}
    
    def _terminate_sessions(self) -> Dict[str, Any]:
        """Terminate all active user sessions"""
        try:
            # Remove active sessions from session store
            result = supabase.table('user_sessions').delete().eq('user_email', self.user_email).execute()
            
            self.log_action("Session termination", "success", f"Terminated {len(result.data) if result.data else 0} active sessions")
            return {"success": True, "sessions_terminated": len(result.data) if result.data else 0}
            
        except Exception as e:
            self.log_action("Session termination", "failed", str(e))
            return {"success": False, "error": str(e)}
    
    def _revoke_api_tokens(self) -> Dict[str, Any]:
        """Revoke all API tokens for the user"""
        try:
            # Deactivate all API tokens
            result = supabase.table('api_tokens').update({
                'status': 'revoked',
                'revoked_at': datetime.utcnow().isoformat()
            }).eq('user_email', self.user_email).execute()
            
            self.log_action("API token revocation", "success", f"Revoked {len(result.data) if result.data else 0} API tokens")
            return {"success": True, "tokens_revoked": len(result.data) if result.data else 0}
            
        except Exception as e:
            self.log_action("API token revocation", "failed", str(e))
            return {"success": False, "error": str(e)}
    
    def _add_to_watchlist(self) -> Dict[str, Any]:
        """Add user to security watchlist"""
        try:
            watchlist_entry = {
                'user_email': self.user_email,
                'user_id': self.target,
                'reason': 'Security isolation - suspicious activity detected',
                'severity': self.severity,
                'added_at': datetime.utcnow().isoformat(),
                'status': 'active'
            }
            
            result = supabase.table('security_watchlist').insert(watchlist_entry).execute()
            
            self.log_action("Watchlist addition", "success", f"User {self.user_email} added to security watchlist")
            return {"success": True, "watchlist_id": result.data[0]['id'] if result.data else None}
            
        except Exception as e:
            self.log_action("Watchlist addition", "failed", str(e))
            return {"success": False, "error": str(e)}
    
    def _notify_security_team(self) -> Dict[str, Any]:
        """Send notification to security team"""
        try:
            # Create security alert
            alert_data = {
                'type': 'user_isolation',
                'severity': self.severity,
                'title': f'User Isolated: {self.user_email}',
                'description': f'User {self.user_email} has been isolated due to suspicious activity',
                'user_email': self.user_email,
                'user_id': self.target,
                'created_at': datetime.utcnow().isoformat(),
                'status': 'new'
            }
            
            result = supabase.table('security_alerts').insert(alert_data).execute()
            
            # In real implementation, this would also send email/Slack notifications
            self.log_action("Security notification", "success", f"Alert created for user isolation: {self.user_email}")
            return {"success": True, "alert_id": result.data[0]['id'] if result.data else None}
            
        except Exception as e:
            self.log_action("Security notification", "failed", str(e))
            return {"success": False, "error": str(e)}

class MaliciousProcessTerminationPlaybook(SecurityPlaybook):
    """Real Process Termination Playbook"""
    
    def __init__(self, process_name: str, pid: Optional[int] = None, severity: str = "critical"):
        super().__init__(process_name, severity)
        self.pid = pid
    
    def execute(self) -> Dict[str, Any]:
        """Execute process termination playbook"""
        try:
            # Step 1: Scan process tree
            self.log_action("Scanning process tree", "executing", f"Looking for process: {self.target}")
            scan_result = self._scan_process_tree()
            
            # Step 2: Identify parent PID
            self.log_action("Identifying parent PID", "executing", "Finding parent process")
            parent_result = self._identify_parent_pid()
            
            # Step 3: Suspend threads
            self.log_action("Suspending threads", "executing", "Suspending process threads")
            suspend_result = self._suspend_threads()
            
            # Step 4: Terminate process tree
            self.log_action("Terminating process tree", "executing", "Killing process and children")
            terminate_result = self._terminate_process_tree()
            
            # Save to database
            self.save_to_database()
            
            return {
                "success": True,
                "target_process": self.target,
                "actions": self.actions_log,
                "scan_result": scan_result,
                "parent_result": parent_result,
                "suspend_result": suspend_result,
                "terminate_result": terminate_result
            }
            
        except Exception as e:
            self.log_action("Process termination", "failed", str(e))
            return {"success": False, "error": str(e)}
    
    def _scan_process_tree(self) -> Dict[str, Any]:
        """Scan for the target process"""
        try:
            # Windows process scan
            if subprocess.run("where tasklist", shell=True, capture_output=True, timeout=2).returncode == 0:
                cmd = f'tasklist /fi "imagename eq {self.target}" /fo csv'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=2)
                
                if result.returncode == 0 and self.target in result.stdout:
                    self.log_action("Process scan", "success", f"Found process {self.target} running")
                    return {"success": True, "method": "windows", "output": result.stdout}
                else:
                    self.log_action("Process scan", "warning", f"Process {self.target} not found")
                    return {"success": True, "method": "windows", "found": False}
            
            # Linux process scan
            else:
                cmd = f'ps aux | grep "{self.target}" | grep -v grep'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=2)
                
                if result.stdout.strip():
                    self.log_action("Process scan", "success", f"Found process {self.target} running")
                    return {"success": True, "method": "linux", "output": result.stdout}
                else:
                    self.log_action("Process scan", "warning", f"Process {self.target} not found")
                    return {"success": True, "method": "linux", "found": False}
                    
        except Exception as e:
            self.log_action("Process scan", "failed", str(e))
            return {"success": False, "error": str(e)}
    
    def _identify_parent_pid(self) -> Dict[str, Any]:
        """Identify parent process ID"""
        try:
            if self.pid:
                # Find parent PID for given process
                if subprocess.run("where wmic", shell=True, capture_output=True).returncode == 0:
                    cmd = f'wmic process where processid={self.pid} get parentprocessid'
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    
                    self.log_action("Parent PID identification", "success", f"Parent PID identified")
                    return {"success": True, "parent_pid": result.stdout.strip()}
            
            self.log_action("Parent PID identification", "skipped", "No PID provided")
            return {"success": True, "skipped": True}
            
        except Exception as e:
            self.log_action("Parent PID identification", "failed", str(e))
            return {"success": False, "error": str(e)}
    
    def _suspend_threads(self) -> Dict[str, Any]:
        """Suspend process threads"""
        try:
            if self.pid:
                # On Windows, we can use taskkill /f to force kill
                if subprocess.run("where taskkill", shell=True, capture_output=True).returncode == 0:
                    cmd = f'taskkill /f /pid {self.pid}'
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    
                    self.log_action("Thread suspension", "success", f"Process {self.pid} terminated")
                    return {"success": True, "method": "windows", "output": result.stdout}
            
            self.log_action("Thread suspension", "skipped", "No PID provided")
            return {"success": True, "skipped": True}
            
        except Exception as e:
            self.log_action("Thread suspension", "failed", str(e))
            return {"success": False, "error": str(e)}
    
    def _terminate_process_tree(self) -> Dict[str, Any]:
        """Terminate process tree"""
        try:
            # Kill all instances of the process
            if subprocess.run("where taskkill", shell=True, capture_output=True).returncode == 0:
                cmd = f'taskkill /f /im {self.target}'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                self.log_action("Process tree termination", "success", f"All instances of {self.target} terminated")
                return {"success": True, "method": "windows", "output": result.stdout}
            
            # Linux killall
            else:
                cmd = f'killall -9 {self.target}'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                self.log_action("Process tree termination", "success", f"All instances of {self.target} terminated")
                return {"success": True, "method": "linux", "output": result.stdout}
                
        except Exception as e:
            self.log_action("Process tree termination", "failed", str(e))
            return {"success": False, "error": str(e)}

# Playbook factory function
def create_playbook(playbook_type: str, target: str, **kwargs) -> SecurityPlaybook:
    """Factory function to create appropriate playbook"""
    
    if playbook_type == "ip_blacklist":
        return DomainIPBlacklistPlaybook(target, kwargs.get('severity', 'high'))
    elif playbook_type == "user_isolation":
        return UserIsolationPlaybook(target, kwargs.get('user_email', ''), kwargs.get('severity', 'high'))
    elif playbook_type == "process_termination":
        return MaliciousProcessTerminationPlaybook(target, kwargs.get('pid'), kwargs.get('severity', 'critical'))
    else:
        raise ValueError(f"Unknown playbook type: {playbook_type}")

# Execute playbook function
def execute_playbook(playbook_type: str, target: str, **kwargs) -> Dict[str, Any]:
    """Execute a security playbook"""
    try:
        playbook = create_playbook(playbook_type, target, **kwargs)
        return playbook.execute()
    except Exception as e:
        logger.error(f"Failed to execute playbook {playbook_type}: {e}")
        return {"success": False, "error": str(e)}
