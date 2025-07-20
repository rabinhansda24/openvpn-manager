"""
Minimal utilities to avoid import errors during testing
"""

from functools import wraps
from flask import request, jsonify

def validate_json_input(required_fields=None):
    """Minimal validation decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({'error': 'Content-Type must be application/json'}), 400
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def rate_limit(limit):
    """Minimal rate limiting decorator (disabled for testing)"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def audit_log(action, data=None):
    """Minimal audit logging (just print for testing)"""
    print(f"AUDIT: {action} - {data}")

def sanitize_input(data):
    """Minimal input sanitization (pass-through for testing)"""
    return data

def session_timeout_check():
    """Minimal session timeout check (always return True for testing)"""
    return True

def require_auth(f):
    """Minimal auth requirement decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    """Minimal admin requirement decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated_function
