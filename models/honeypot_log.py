from integrations.supabase import supabase

def create_honeypot_log(trap_name, ip_address, user_agent, request_data):
    return supabase.table('honeypot_logs').insert({
        'trap_name': trap_name,
        'ip_address': ip_address,
        'user_agent': user_agent,
        'request_data': request_data
    }).execute()

def get_honeypot_logs():
    return supabase.table('honeypot_logs').select('*').execute()