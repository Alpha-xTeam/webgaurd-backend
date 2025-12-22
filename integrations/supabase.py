from supabase import create_client, Client
from config import Config

# Use Service Role Key if available (bypasses RLS), otherwise fall back to Anon Key
key = Config.SUPABASE_SERVICE_ROLE_KEY if Config.SUPABASE_SERVICE_ROLE_KEY else Config.SUPABASE_KEY
supabase: Client = create_client(Config.SUPABASE_URL, key)