from integrations.supabase import supabase

def create_detection_rule(name, pattern, severity='medium', created_by=None):
    return supabase.table('detection_rules').insert({
        'name': name,
        'pattern': pattern,
        'severity': severity,
        'created_by': created_by
    }).execute()

def get_detection_rules():
    return supabase.table('detection_rules').select('*').execute()