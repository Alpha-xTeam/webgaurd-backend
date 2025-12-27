from integrations.supabase import supabase
from datetime import datetime, timedelta, timezone
import json
import os
import uuid

def get_baghdad_time():
    """Returns current time in Baghdad (UTC+3) with proper offset"""
    tz = timezone(timedelta(hours=3))
    return datetime.now(tz).isoformat()

def log_attack(attack_type, attacker_ip, attacker_email, stolen_data, target_url, user_agent=None):
    """Log an attack attempt to the database"""
    attack_data = {
        'attack_type': attack_type,
        'attacker_ip': attacker_ip,
        'attacker_email': attacker_email,
        'stolen_data': stolen_data,
        'target_url': target_url,
        'user_agent': user_agent,
        'status': 'active',
        'detected_at': get_baghdad_time()
    }
    
    try:
        return supabase.table('attacks').insert(attack_data).execute()
    except Exception as e:
        print(f"Supabase login failed: {e}")
        # Return a dummy response object that mimics Supabase response
        class DummyResponse:
            data = [attack_data]
        return DummyResponse()

def get_all_attacks():
    """Get all attack logs from DB"""
    try:
        db_attacks = supabase.table('attacks').select('*').order('detected_at', desc=True).execute().data
    except:
        db_attacks = []
        
    all_attacks = db_attacks
    # Sort by detected_at desc
    all_attacks.sort(key=lambda x: x.get('detected_at', ''), reverse=True)
    
    class DummyResponse:
        data = all_attacks
    return DummyResponse()

def get_active_attacks():
    """Get only active (unmitigated) attacks from DB"""
    try:
        db_attacks = supabase.table('attacks').select('*').eq('status', 'active').order('detected_at', desc=True).execute().data
    except:
        db_attacks = []
        
    all_attacks = db_attacks
    all_attacks.sort(key=lambda x: x.get('detected_at', ''), reverse=True)
    
    class DummyResponse:
        data = all_attacks
    return DummyResponse()

def block_attacker(attacker_email):
    """Block an attacker by adding them to blocked users"""
    try:
        # Update user status to blocked
        supabase.table('users').update({'status': 'blocked', 'blocked_at': datetime.now(timezone.utc).isoformat()}).eq('email', attacker_email).execute()
        
        # Mark all their attacks as mitigated
        supabase.table('attacks').update({'status': 'mitigated', 'mitigated_at': datetime.now(timezone.utc).isoformat()}).eq('attacker_email', attacker_email).execute()
    except Exception as e:
        print(f"Block attacker DB failed: {e}")
        
    return True

def mitigate_all_attacks():
    """Mitigate all active attacks and block all attackers"""
    # Get all active attacks
    attacks_resp = get_active_attacks()
    attacks = attacks_resp.data
    
    blocked_users = []
    for attack in attacks:
        if attack.get('attacker_email') and attack['attacker_email'] not in blocked_users:
            block_attacker(attack['attacker_email'])
            blocked_users.append(attack['attacker_email'])
    
    # Mark all attacks as mitigated in DB
    try:
        supabase.table('attacks').update({
            'status': 'mitigated',
            'mitigated_at': datetime.now(timezone.utc).isoformat()
        }).eq('status', 'active').execute()
    except:
        pass
        
    return {
        'mitigated_attacks': len(attacks),
        'blocked_users': len(blocked_users)
    }

def update_attack_status(attack_id, status, notes=None, mitigated_at=None):
    """Update status of a specific attack in DB"""
    update_data = {
        'status': status,
        'mitigated_at': mitigated_at or get_baghdad_time()
    }
    if notes:
        update_data['analyst_notes'] = notes

    # 1. Try DB
    try:
        supabase.table('attacks').update(update_data).eq('id', attack_id).execute()
        return True
    except Exception as e:
        print(f"DB update failed for attack {attack_id}: {e}")
        return False

def delete_attack(attack_id):
    """Delete a specific attack record from DB"""
    try:
        supabase.table('attacks').delete().eq('id', attack_id).execute()
        return True
    except Exception as e:
        print(f"DB delete failed for attack {attack_id}: {e}")
        return False

def clear_all_attacker_data():
    """Nuclear purge of ALL security data across all tables"""
    print("🧹 Starting deep purge of security data...")
    
    # All possible tables that might store attack/security data
    tables_to_clear = [
        'attacks', 
        'alerts', 
        'incidents', 
        'incident_responses', 
        'blocked_ips', 
        'security_alerts',
        'honeypot_logs',
        'network_logs'
    ]
    
    for table in tables_to_clear:
        try:
            # More reliable way to delete all rows in Supabase/PostgREST
            # We use a filter that is always true for any existing row
            supabase.table(table).delete().gt('created_at', '1970-01-01T00:00:00Z').execute()
            print(f"✅ Table '{table}' purged via created_at.")
        except Exception as e:
            try:
                # Fallback to id check if created_at is not available or fails
                supabase.table(table).delete().neq('id', '00000000-0000-0000-0000-000000000001').execute()
                print(f"✅ Table '{table}' purged via ID neq.")
            except Exception as e2:
                print(f"ℹ️ Clear for {table} failed: {str(e2)}")

    # 3. Reset local global variables if accessed via this process
    from api.attacker import STORED_SEARCHES, STOLEN_DATA
    STORED_SEARCHES.clear()
    STOLEN_DATA.clear()
    
    return True
