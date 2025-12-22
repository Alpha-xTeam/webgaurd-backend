from datetime import datetime, timedelta

# In-memory store for active users: {user_id: last_seen_datetime}
_active_users = {}
ACTIVE_THRESHOLD_MINUTES = 5

def update_user_activity(user_id):
    """Update the last seen timestamp for a user."""
    _active_users[str(user_id)] = datetime.now()

def is_user_active(user_id):
    """Check if a user has been active within the threshold."""
    user_id = str(user_id)
    if user_id not in _active_users:
        return False
    
    last_seen = _active_users[user_id]
    if datetime.now() - last_seen > timedelta(minutes=ACTIVE_THRESHOLD_MINUTES):
        return False
    
    return True

def get_active_user_ids():
    """Get a list of all currently active user IDs."""
    # Clean up old sessions first (optional, but good for memory)
    cleanup_inactive_users()
    return [uid for uid, last_seen in _active_users.items() 
            if datetime.now() - last_seen <= timedelta(minutes=ACTIVE_THRESHOLD_MINUTES)]

def cleanup_inactive_users():
    """Remove users who haven't been seen in a long time."""
    to_remove = []
    for uid, last_seen in _active_users.items():
        if datetime.now() - last_seen > timedelta(minutes=ACTIVE_THRESHOLD_MINUTES):
            to_remove.append(uid)
    
    for uid in to_remove:
        del _active_users[uid]
