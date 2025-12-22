from integrations.supabase import supabase
from datetime import datetime
import json
import os
import uuid

FALLBACK_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'attacks_fallback.json')

def _save_fallback(attack_data):
    try:
        os.makedirs(os.path.dirname(FALLBACK_FILE), exist_ok=True)
        if os.path.exists(FALLBACK_FILE):
            with open(FALLBACK_FILE, 'r') as f:
                attacks = json.load(f)
        else:
            attacks = []
        
        # Add ID if missing
        if 'id' not in attack_data:
            attack_data['id'] = str(uuid.uuid4())
            
        attacks.append(attack_data)
        
        with open(FALLBACK_FILE, 'w') as f:
            json.dump(attacks, f, indent=2)
        return True
    except Exception as e:
        print(f"Fallback save failed: {e}")
        return False

def _load_fallback():
    try:
        if os.path.exists(FALLBACK_FILE):
            with open(FALLBACK_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return []

def log_attack(attack_type, attacker_ip, attacker_email, stolen_data, target_url, user_agent=None):
    """Log an attack attempt to the database with fallback"""
    attack_data = {
        'attack_type': attack_type,
        'attacker_ip': attacker_ip,
        'attacker_email': attacker_email,
        'stolen_data': stolen_data,
        'target_url': target_url,
        'user_agent': user_agent,
        'status': 'active',
        'detected_at': datetime.utcnow().isoformat()
    }
    
    try:
        return supabase.table('attacks').insert(attack_data).execute()
    except Exception as e:
        # Silently use fallback (RLS errors are expected in dev)
        _save_fallback(attack_data)
        # Return a dummy response object that mimics Supabase response
        class DummyResponse:
            data = [attack_data]
        return DummyResponse()

def get_all_attacks():
    """Get all attack logs (merged DB + Fallback)"""
    try:
        db_attacks = supabase.table('attacks').select('*').order('detected_at', desc=True).execute().data
    except:
        db_attacks = []
        
    fallback_attacks = _load_fallback()
    
    # Merge and sort
    all_attacks = db_attacks + fallback_attacks
    # Sort by detected_at desc
    all_attacks.sort(key=lambda x: x.get('detected_at', ''), reverse=True)
    
    class DummyResponse:
        data = all_attacks
    return DummyResponse()

def get_active_attacks():
    """Get only active (unmitigated) attacks"""
    try:
        db_attacks = supabase.table('attacks').select('*').eq('status', 'active').order('detected_at', desc=True).execute().data
    except:
        db_attacks = []
        
    fallback_attacks = [a for a in _load_fallback() if a.get('status') == 'active']
    
    all_attacks = db_attacks + fallback_attacks
    all_attacks.sort(key=lambda x: x.get('detected_at', ''), reverse=True)
    
    class DummyResponse:
        data = all_attacks
    return DummyResponse()

def block_attacker(attacker_email):
    """Block an attacker by adding them to blocked users"""
    try:
        # Update user status to blocked
        supabase.table('users').update({'status': 'blocked', 'blocked_at': datetime.utcnow().isoformat()}).eq('email', attacker_email).execute()
        
        # Mark all their attacks as mitigated
        supabase.table('attacks').update({'status': 'mitigated', 'mitigated_at': datetime.utcnow().isoformat()}).eq('attacker_email', attacker_email).execute()
    except Exception as e:
        print(f"Block attacker DB failed: {e}")
        
    return True

def mitigate_all_attacks():
    """Mitigate all active attacks and block all attackers"""
    # Get all active attacks
    attacks = get_active_attacks().data
    
    blocked_users = []
    for attack in attacks:
        if attack.get('attacker_email') and attack['attacker_email'] not in blocked_users:
            block_attacker(attack['attacker_email'])
            blocked_users.append(attack['attacker_email'])
    
    # Mark all attacks as mitigated in DB
    try:
        supabase.table('attacks').update({
            'status': 'mitigated',
            'mitigated_at': datetime.utcnow().isoformat()
        }).eq('status', 'active').execute()
    except:
        pass
        
    # Mark all attacks as mitigated in Fallback
    try:
        if os.path.exists(FALLBACK_FILE):
            with open(FALLBACK_FILE, 'r') as f:
                fallback_data = json.load(f)
            
            for attack in fallback_data:
                if attack.get('status') == 'active':
                    attack['status'] = 'mitigated'
                    attack['mitigated_at'] = datetime.utcnow().isoformat()
            
            with open(FALLBACK_FILE, 'w') as f:
                json.dump(fallback_data, f, indent=2)
    except:
        pass
    
    return {
        'mitigated_attacks': len(attacks),
        'blocked_users': len(blocked_users)
    }
