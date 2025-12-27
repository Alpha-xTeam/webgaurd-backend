from integrations.supabase import supabase
from datetime import datetime, timedelta

def get_baghdad_time():
    from datetime import timezone
    tz = timezone(timedelta(hours=3))
    return datetime.now(tz).isoformat()

def create_alert(message, severity='low', source=None, created_at=None):
    return supabase.table('alerts').insert({
        'message': message,
        'severity': severity,
        'source': source,
        'created_at': created_at or get_baghdad_time()
    }).execute()

def get_alerts():
    return supabase.table('alerts').select('*').order('created_at', desc=True).execute()

def acknowledge_alert(alert_id, acknowledged_by):
    return supabase.table('alerts').update({
        'acknowledged': True,
        'acknowledged_by': acknowledged_by,
        'acknowledged_at': 'now()'
    }).eq('id', alert_id).execute()

def update_alert_status(alert_id, status, notes=None, analyst=None):
    data = {
        'status': status,
        'updated_at': 'now()'
    }
    if notes:
        data['notes'] = notes
    if analyst:
        data['assigned_to'] = analyst
        
    return supabase.table('alerts').update(data).eq('id', alert_id).execute()