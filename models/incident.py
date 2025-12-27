from integrations.supabase import supabase
from datetime import datetime, timedelta

def get_baghdad_time():
    from datetime import timezone
    tz = timezone(timedelta(hours=3))
    return datetime.now(tz).isoformat()

def create_incident(title, description, severity='medium', created_by=None, created_at=None):
    return supabase.table('incidents').insert({
        'title': title,
        'description': description,
        'severity': severity,
        'created_by': created_by,
        'created_at': created_at or get_baghdad_time()
    }).execute()

def get_incidents():
    return supabase.table('incidents').select('*').execute()

def update_incident_status(incident_id, status, assigned_to=None):
    update_data = {'status': status}
    if assigned_to:
        update_data['assigned_to'] = assigned_to
    return supabase.table('incidents').update(update_data).eq('id', incident_id).execute()