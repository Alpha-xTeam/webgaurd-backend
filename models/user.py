from integrations.supabase import supabase

def create_user(email, password_hash, role='user'):
    return supabase.table('users').insert({
        'email': email,
        'password_hash': password_hash,
        'role': role
    }).execute()

def get_user(email):
    return supabase.table('users').select('*').eq('email', email).execute()

def get_user_by_id(user_id):
    """Get user by ID"""
    return supabase.table('users').select('*').eq('id', user_id).execute()

def get_all_users():
    """Get all users for admin/owner dashboard"""
    return supabase.table('users').select('id, email, role, created_at').execute()

def update_user_role(user_id, new_role):
    """Update user role"""
    return supabase.table('users').update({'role': new_role}).eq('id', user_id).execute()

def delete_user_by_id(user_id):
    """Delete user by ID"""
    return supabase.table('users').delete().eq('id', user_id).execute()