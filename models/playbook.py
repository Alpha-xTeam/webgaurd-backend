from ..integrations.supabase import supabase

def create_playbook(name, description, steps, created_by=None):
    return supabase.table('playbooks').insert({
        'name': name,
        'description': description,
        'steps': steps,
        'created_by': created_by
    }).execute()

def get_playbooks():
    return supabase.table('playbooks').select('*').execute()