from flask import request

def get_request_ip():
    """Get real IP address from request, checking various sources."""
    # Check JSON body
    try:
        if request.is_json:
            body = request.get_json(silent=True) or {}
            if body.get('ip'):
                return body.get('ip')
    except:
        pass
    
    # Check query parameters
    if request.args.get('ip'):
        return request.args.get('ip')
        
    # Check headers (e.g. from proxy or frontend)
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        # Get the first IP in the list
        return forwarded.split(',')[0].strip()
        
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip
        
    return request.remote_addr
