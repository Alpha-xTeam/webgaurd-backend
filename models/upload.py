from integrations.supabase import supabase

def create_upload(filename, original_filename, file_path, file_size, mime_type, uploaded_by):
    return supabase.table('uploads').insert({
        'filename': filename,
        'original_filename': original_filename,
        'file_path': file_path,
        'file_size': file_size,
        'mime_type': mime_type,
        'uploaded_by': uploaded_by
    }).execute()

def get_uploads():
    return supabase.table('uploads').select('*').execute()

def update_upload_status(upload_id, status):
    return supabase.table('uploads').update({'status': status}).eq('id', upload_id).execute()