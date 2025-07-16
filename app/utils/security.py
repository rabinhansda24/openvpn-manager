"""
Security utilities for the OpenVPN management application.
"""

import hashlib
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app, session
from flask_login import current_user
import redis
import bcrypt

class RateLimiter:
    """Rate limiting utility using Redis."""
    
    def __init__(self, redis_client=None):
        if redis_client is None:
            redis_url = current_app.config.get('RATELIMIT_STORAGE_URL')
            self.redis_client = redis.from_url(redis_url) if redis_url else None
        else:
            self.redis_client = redis_client
    
    def is_allowed(self, key, limit, window):
        """
        Check if request is allowed based on rate limit.
        
        Args:
            key: Unique identifier for the rate limit
            limit: Number of requests allowed
            window: Time window in seconds
        
        Returns:
            bool: True if allowed, False if rate limited
        """
        if not self.redis_client:
            return True  # Allow if Redis is not available
        
        try:
            current_time = int(time.time())
            window_start = current_time - window
            
            # Remove old entries
            self.redis_client.zremrangebyscore(key, 0, window_start)
            
            # Count current requests
            current_requests = self.redis_client.zcard(key)
            
            if current_requests >= limit:
                return False
            
            # Add current request
            self.redis_client.zadd(key, {str(current_time): current_time})
            self.redis_client.expire(key, window)
            
            return True
        except Exception:
            # Allow request if Redis operation fails
            return True

def rate_limit(limit_string):
    """
    Decorator for rate limiting.
    
    Args:
        limit_string: Rate limit in format "number/timeperiod" (e.g., "100/hour", "5/minute")
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Parse limit string
            try:
                number, period = limit_string.split('/')
                limit = int(number)
                
                if period == 'minute':
                    window = 60
                elif period == 'hour':
                    window = 3600
                elif period == 'day':
                    window = 86400
                else:
                    window = 3600  # Default to hour
                    
            except ValueError:
                return jsonify({'error': 'Invalid rate limit format'}), 500
            
            # Create rate limiter
            rate_limiter = RateLimiter()
            
            # Use IP address and endpoint as key
            key = f"rate_limit:{request.remote_addr}:{request.endpoint}"
            
            if not rate_limiter.is_allowed(key, limit, window):
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': window
                }), 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def generate_csrf_token():
    """Generate CSRF token."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token."""
    return token and session.get('csrf_token') == token

def csrf_protect(f):
    """Decorator for CSRF protection."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
            if not validate_csrf_token(token):
                return jsonify({'error': 'CSRF token validation failed'}), 403
        return f(*args, **kwargs)
    return decorated_function

def hash_password(password):
    """Hash password using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password, hashed):
    """Verify password against hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_secure_token(length=32):
    """Generate a secure random token."""
    return secrets.token_urlsafe(length)

def generate_api_key():
    """Generate API key."""
    return f"ovpn_{secrets.token_urlsafe(32)}"

def secure_filename(filename):
    """Make filename secure by removing dangerous characters."""
    import re
    filename = re.sub(r'[^\w\s-]', '', filename).strip()
    filename = re.sub(r'[-\s]+', '-', filename)
    return filename

class SecurityHeaders:
    """Security headers middleware."""
    
    @staticmethod
    def apply_headers(response):
        """Apply security headers to response."""
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
        }
        
        for header, value in security_headers.items():
            response.headers[header] = value
        
        return response

def audit_log(action, details=None):
    """Log security-related actions."""
    log_entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'user_id': current_user.id if current_user.is_authenticated else None,
        'username': current_user.username if current_user.is_authenticated else 'anonymous',
        'action': action,
        'ip_address': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'details': details or {}
    }
    
    # Log to application logger
    current_app.logger.info(f"AUDIT: {log_entry}")
    
    return log_entry

def require_2fa(f):
    """Decorator to require 2FA for sensitive operations."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required'}), 401
        
        if current_user.two_factor_enabled:
            # Check if 2FA was verified in this session
            if not session.get('2fa_verified'):
                return jsonify({'error': '2FA verification required'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

def check_password_breach(password):
    """
    Check if password has been breached using SHA-1 hash prefix.
    Uses Have I Been Pwned API.
    """
    import requests
    
    # Create SHA-1 hash of password
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    try:
        # Query Have I Been Pwned API
        response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=5)
        if response.status_code == 200:
            hashes = response.text.split('\n')
            for hash_line in hashes:
                if hash_line.startswith(suffix):
                    count = int(hash_line.split(':')[1])
                    return True, count
            return False, 0
        else:
            # If API is unavailable, don't block the password
            return False, 0
    except Exception:
        # If there's an error, don't block the password
        return False, 0

def session_timeout_check():
    """Check if session has timed out."""
    timeout_minutes = current_app.config.get('SESSION_TIMEOUT_MINUTES', 60)
    last_activity = session.get('last_activity')
    
    if last_activity:
        last_activity_time = datetime.fromisoformat(last_activity)
        if datetime.utcnow() - last_activity_time > timedelta(minutes=timeout_minutes):
            session.clear()
            return False
    
    session['last_activity'] = datetime.utcnow().isoformat()
    return True

def sanitize_input(data):
    """Sanitize input data to prevent XSS and injection attacks."""
    if isinstance(data, str):
        # Basic HTML/script tag removal
        import re
        data = re.sub(r'<[^>]*>', '', data)
        # Remove potential script content
        data = re.sub(r'javascript:', '', data, flags=re.IGNORECASE)
        data = re.sub(r'on\w+\s*=', '', data, flags=re.IGNORECASE)
        return data.strip()
    elif isinstance(data, dict):
        return {key: sanitize_input(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    else:
        return data
