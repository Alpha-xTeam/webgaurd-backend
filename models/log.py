from integrations.supabase import supabase

def create_log(level, message, source=None, user_id=None, ip_address=None, user_agent=None):
    return supabase.table('logs').insert({
        'level': level,
        'message': message,
        'source': source,
        'user_id': user_id,
        'ip_address': ip_address,
        'user_agent': user_agent
    }).execute()

def get_logs(limit=100):
    return supabase.table('logs').select('*').order('created_at', desc=True).limit(limit).execute()