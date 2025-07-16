"""
Validation utilities for input sanitization and security.
"""

import re
import os
from functools import wraps
from flask import request, jsonify, current_app
from flask_login import current_user
import ipaddress

def validate_client_name(name):
    """
    Validate VPN client name.
    
    Rules:
    - Only alphanumeric characters, hyphens, and underscores
    - 3-50 characters long
    - Cannot start or end with hyphen or underscore
    """
    if not name or not isinstance(name, str):
        return False
    
    # Check length
    if len(name) < 3 or len(name) > 50:
        return False
    
    # Check pattern
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9_-]*[a-zA-Z0-9]$'
    if len(name) == 3:
        pattern = r'^[a-zA-Z0-9]{3}$'
    
    return bool(re.match(pattern, name))

def validate_email(email):
    """Validate email address format."""
    if not email:
        return True  # Email is optional
    
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_ip_address(ip):
    """Validate IP address format."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_port(port):
    """Validate port number."""
    try:
        port_int = int(port)
        return 1 <= port_int <= 65535
    except (ValueError, TypeError):
        return False

def validate_file_path(path, allowed_dirs=None):
    """
    Validate file path to prevent directory traversal attacks.
    
    Args:
        path: File path to validate
        allowed_dirs: List of allowed base directories
    """
    if not path:
        return False
    
    # Normalize the path
    normalized_path = os.path.normpath(path)
    
    # Check for directory traversal attempts
    if '..' in normalized_path or normalized_path.startswith('/'):
        return False
    
    # Check against allowed directories if specified
    if allowed_dirs:
        for allowed_dir in allowed_dirs:
            if normalized_path.startswith(allowed_dir):
                return True
        return False
    
    return True

def sanitize_filename(filename):
    """Sanitize filename to prevent security issues."""
    if not filename:
        return None
    
    # Remove or replace dangerous characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove leading/trailing whitespace and dots
    sanitized = sanitized.strip(' .')
    
    # Limit length
    if len(sanitized) > 255:
        name, ext = os.path.splitext(sanitized)
        sanitized = name[:255-len(ext)] + ext
    
    return sanitized

def validate_bandwidth_limit(limit):
    """Validate bandwidth limit value."""
    try:
        limit_int = int(limit)
        return 0 <= limit_int <= 10000  # 0-10000 MB/s
    except (ValueError, TypeError):
        return False

def validate_password_strength(password):
    """
    Validate password strength.
    
    Requirements:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is strong"

class ValidationError(Exception):
    """Custom exception for validation errors."""
    def __init__(self, message, field=None):
        self.message = message
        self.field = field
        super().__init__(self.message)

def validate_json_input(required_fields=None, optional_fields=None):
    """
    Decorator to validate JSON input.
    
    Args:
        required_fields: List of required field names
        optional_fields: List of optional field names
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({'error': 'Content-Type must be application/json'}), 400
            
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No JSON data provided'}), 400
            
            # Check required fields
            if required_fields:
                missing_fields = [field for field in required_fields if field not in data]
                if missing_fields:
                    return jsonify({
                        'error': f'Missing required fields: {", ".join(missing_fields)}'
                    }), 400
            
            # Check for unexpected fields
            if required_fields or optional_fields:
                allowed_fields = set(required_fields or []) | set(optional_fields or [])
                unexpected_fields = [field for field in data.keys() if field not in allowed_fields]
                if unexpected_fields:
                    return jsonify({
                        'error': f'Unexpected fields: {", ".join(unexpected_fields)}'
                    }), 400
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_admin(f):
    """Decorator to require admin privileges."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required'}), 401
        
        if not current_user.is_admin:
            return jsonify({'error': 'Admin privileges required'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

def require_auth(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required'}), 401
        
        return f(*args, **kwargs)
    return decorated_function
