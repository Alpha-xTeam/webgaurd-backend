"""
Memory Dump API Endpoint
For forensic memory dump functionality
"""

from flask import Blueprint, jsonify, request
from middleware.auth_guard import require_auth
import logging
import subprocess
import os
from datetime import datetime

api_bp = Blueprint('memory_dump', __name__)
logger = logging.getLogger(__name__)

@api_bp.route('/execute/memory-dump', methods=['POST'])
@require_auth
def execute_memory_dump():
    """Execute memory dump for forensic analysis"""
    try:
        data = request.get_json()
        target_pid = data.get('target_pid')  # Process ID to dump
        dump_path = data.get('dump_path', f'/tmp/memory_dump_{datetime.now().strftime("%Y%m%d_%H%M%S")}.dmp')
        
        if not target_pid:
            return jsonify({
                "success": False,
                "error": "target_pid is required"
            }), 400
        
        # Log the execution request
        logger.warning(f"MEMORY DUMP REQUEST: PID {target_pid} by user")
        
        # Check if process exists
        try:
            result = subprocess.run(['tasklist', '/FI', f'PID eq {target_pid}'], 
                              capture_output=True, text=True, shell=True)
            if target_pid not in result.stdout:
                return jsonify({
                    "success": False,
                    "error": f"Process with PID {target_pid} not found"
                }), 404
        except Exception as e:
            logger.error(f"Failed to check process: {e}")
        
        # Execute memory dump using Windows tools
        try:
            # Create dump directory if it doesn't exist
            os.makedirs(os.path.dirname(dump_path) if os.path.dirname(dump_path) else '/tmp', exist_ok=True)
            
            # Use procdump (part of Sysinternals) or Windows built-in tools
            dump_command = f'procdump.exe -ma {target_pid} "{dump_path}"'
            
            # Fallback to Windows built-in if procdump not available
            try:
                result = subprocess.run(dump_command, shell=True, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    dump_size = os.path.getsize(dump_path) if os.path.exists(dump_path) else 0
                    
                    # Log to database
                    log_memory_dump(target_pid, dump_path, dump_size, success=True)
                    
                    return jsonify({
                        "success": True,
                        "message": f"Memory dump created successfully",
                        "details": {
                            "target_pid": target_pid,
                            "dump_path": dump_path,
                            "dump_size_mb": round(dump_size / (1024 * 1024), 2),
                            "timestamp": datetime.now().isoformat()
                        }
                    }), 200
                else:
                    error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                    logger.error(f"Memory dump failed: {error_msg}")
                    log_memory_dump(target_pid, dump_path, 0, success=False, error=error_msg)
                    
                    return jsonify({
                        "success": False,
                        "error": f"Memory dump failed: {error_msg}"
                    }), 500
                    
            except subprocess.TimeoutExpired:
                logger.error(f"Memory dump timed out for PID {target_pid}")
                log_memory_dump(target_pid, dump_path, 0, success=False, error="Timeout")
                
                return jsonify({
                    "success": False,
                    "error": "Memory dump timed out after 30 seconds"
                }), 500
                
        except Exception as e:
            logger.error(f"Memory dump execution error: {str(e)}")
            log_memory_dump(target_pid, dump_path, 0, success=False, error=str(e))
            
            return jsonify({
                "success": False,
                "error": f"Failed to execute memory dump: {str(e)}"
            }), 500
            
    except Exception as e:
        logger.error(f"Memory dump API error: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Internal server error"
        }), 500

def log_memory_dump(target_pid, dump_path, dump_size, success, error=None):
    """Log memory dump execution to database"""
    try:
        from integrations.supabase import supabase
        
        log_data = {
            'playbook_type': 'MemoryDump',
            'target': str(target_pid),
            'severity': 'high',
            'start_time': datetime.now().isoformat(),
            'end_time': datetime.now().isoformat(),
            'actions': [{
                'timestamp': datetime.now().isoformat(),
                'action': 'Memory Dump',
                'status': 'success' if success else 'failed',
                'details': f"Dumped process memory to {dump_path}" if success else f"Error: {error}"
            }],
            'status': 'completed' if success else 'failed'
        }
        
        supabase.table('playbook_executions').insert(log_data).execute()
        
    except Exception as e:
        logger.error(f"Failed to log memory dump: {e}")

@api_bp.route('/memory-dumps', methods=['GET'])
@require_auth
def get_memory_dumps():
    """Get list of recent memory dumps"""
    try:
        from integrations.supabase import supabase
        
        result = supabase.table('playbook_executions')\
            .select('*')\
            .eq('playbook_type', 'MemoryDump')\
            .order('created_at', desc=True)\
            .limit(50)\
            .execute()
        
        dumps = []
        for dump in result.data or []:
            dumps.append({
                'id': dump['id'],
                'target_pid': dump['target'],
                'status': dump['status'],
                'created_at': dump['created_at'],
                'actions': dump['actions']
            })
        
        return jsonify({
            "success": True,
            "memory_dumps": dumps
        }), 200
        
    except Exception as e:
        logger.error(f"Failed to get memory dumps: {e}")
        return jsonify({
            "success": False,
            "error": "Failed to retrieve memory dumps"
        }), 500
