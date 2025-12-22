from integrations.supabase import supabase

def create_incident(title, description, severity='medium', created_by=None):
    return supabase.table('incidents').insert({
        'title': title,
        'description': description,
        'severity': severity,
        'created_by': created_by
    }).execute()

def get_incidents():
    return supabase.table('incidents').select('*').execute()

def update_incident_status(incident_id, status, assigned_to=None):
    update_data = {'status': status}
    if assigned_to:
        update_data['assigned_to'] = assigned_to
    return supabase.table('incidents').update(update_data).eq('id', incident_id).execute()