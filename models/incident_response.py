from integrations.supabase import supabase

def create_incident_response(incident_id, action, performed_by):
    return supabase.table('incident_responses').insert({
        'incident_id': incident_id,
        'action': action,
        'performed_by': performed_by
    }).execute()

def get_incident_responses(incident_id):
    return supabase.table('incident_responses').select('*').eq('incident_id', incident_id).execute()