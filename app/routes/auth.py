"""
Authentication routes for the OpenVPN management application.
"""

from flask import Blueprint, request, jsonify, session, current_app
from flask_login import login_user, logout_user, current_user
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from app.models.user import User
from app.utils import (
    validate_json_input, 
    rate_limit, 
    audit_log, 
    sanitize_input,
    session_timeout_check
)
from app import db
import pyotp

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
@rate_limit('10/minute')
@validate_json_input(required_fields=['username', 'password'])
def login():
    """User login endpoint."""
    data = sanitize_input(request.get_json())
    username = data.get('username')
    password = data.get('password')
    totp_token = data.get('totp_token')
    remember_me = data.get('remember_me', False)
    
    # Find user
    user = User.query.filter_by(username=username).first()
    
    if not user or not user.check_password(password):
        audit_log('login_failed', {'username': username, 'reason': 'invalid_credentials'})
        
        # Record failed login attempt if user exists
        if user:
            user.record_failed_login()
        
        return jsonify({'error': 'Invalid username or password'}), 401
    
    # Check if account is active
    if not user.is_active:
        audit_log('login_failed', {'username': username, 'reason': 'account_disabled'})
        return jsonify({'error': 'Account is disabled'}), 401
    
    # Check for too many failed attempts
    if user.failed_login_attempts >= 5:
        audit_log('login_failed', {'username': username, 'reason': 'too_many_attempts'})
        return jsonify({'error': 'Account temporarily locked due to too many failed attempts'}), 429
    
    # Check 2FA if enabled
    if user.two_factor_enabled:
        if not totp_token:
            return jsonify({
                'error': '2FA token required',
                'requires_2fa': True
            }), 200
        
        if not user.verify_totp(totp_token):
            audit_log('login_failed', {'username': username, 'reason': 'invalid_2fa'})
            user.record_failed_login()
            return jsonify({'error': 'Invalid 2FA token'}), 401
        
        # Mark 2FA as verified for this session
        session['2fa_verified'] = True
    
    # Successful login
    login_user(user, remember=remember_me)
    user.record_login()
    
    # Create JWT token
    access_token = create_access_token(
        identity=user.id,
        additional_claims={
            'username': user.username,
            'is_admin': user.is_admin
        }
    )
    
    audit_log('login_success', {'username': username})
    
    response_data = {
        'message': 'Login successful',
        'access_token': access_token,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin,
            'two_factor_enabled': user.two_factor_enabled,
            'last_login': user.last_login.isoformat() if user.last_login else None
        }
    }
    
    return jsonify(response_data), 200

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """User logout endpoint."""
    if current_user.is_authenticated:
        username = current_user.username
        audit_log('logout', {'username': username})
    
    logout_user()
    session.clear()
    
    return jsonify({'message': 'Logout successful'}), 200

@auth_bp.route('/2fa/setup', methods=['POST'])
@jwt_required()
def setup_2fa():
    """Setup 2FA for the current user."""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Generate TOTP secret if not already exists
    if not user.totp_secret:
        user.generate_totp_secret()
        db.session.commit()
    
    # Generate QR code
    qr_code = user.generate_qr_code()
    totp_uri = user.get_totp_uri()
    
    audit_log('2fa_setup_initiated', {'user_id': user.id})
    
    return jsonify({
        'secret': user.totp_secret,
        'qr_code': f'data:image/png;base64,{qr_code}',
        'totp_uri': totp_uri
    }), 200

@auth_bp.route('/2fa/verify', methods=['POST'])
@jwt_required()
@validate_json_input(required_fields=['token'])
def verify_2fa():
    """Verify 2FA token and enable 2FA."""
    data = sanitize_input(request.get_json())
    token = data.get('token')
    
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if not user.totp_secret:
        return jsonify({'error': '2FA not set up'}), 400
    
    if user.verify_totp(token):
        user.two_factor_enabled = True
        db.session.commit()
        
        audit_log('2fa_enabled', {'user_id': user.id})
        
        return jsonify({'message': '2FA enabled successfully'}), 200
    else:
        audit_log('2fa_verification_failed', {'user_id': user.id})
        return jsonify({'error': 'Invalid token'}), 400

@auth_bp.route('/2fa/disable', methods=['POST'])
@jwt_required()
@validate_json_input(required_fields=['password', 'token'])
def disable_2fa():
    """Disable 2FA for the current user."""
    data = sanitize_input(request.get_json())
    password = data.get('password')
    token = data.get('token')
    
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Verify password
    if not user.check_password(password):
        audit_log('2fa_disable_failed', {'user_id': user.id, 'reason': 'invalid_password'})
        return jsonify({'error': 'Invalid password'}), 401
    
    # Verify current 2FA token
    if not user.verify_totp(token):
        audit_log('2fa_disable_failed', {'user_id': user.id, 'reason': 'invalid_token'})
        return jsonify({'error': 'Invalid 2FA token'}), 401
    
    # Disable 2FA
    user.two_factor_enabled = False
    user.totp_secret = None
    db.session.commit()
    
    audit_log('2fa_disabled', {'user_id': user.id})
    
    return jsonify({'message': '2FA disabled successfully'}), 200

@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """Get current user profile."""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_admin': user.is_admin,
        'two_factor_enabled': user.two_factor_enabled,
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'last_login': user.last_login.isoformat() if user.last_login else None,
        'last_seen': user.last_seen.isoformat() if user.last_seen else None
    }), 200

@auth_bp.route('/change-password', methods=['POST'])
@jwt_required()
@validate_json_input(required_fields=['current_password', 'new_password'])
def change_password():
    """Change user password."""
    data = sanitize_input(request.get_json())
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Verify current password
    if not user.check_password(current_password):
        audit_log('password_change_failed', {'user_id': user.id, 'reason': 'invalid_current_password'})
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    # Validate new password strength
    from app.utils.validation import validate_password_strength
    is_strong, message = validate_password_strength(new_password)
    if not is_strong:
        return jsonify({'error': message}), 400
    
    # Check if password has been breached
    from app.utils.security import check_password_breach
    is_breached, count = check_password_breach(new_password)
    if is_breached:
        return jsonify({
            'error': f'This password has been found in {count} data breaches. Please choose a different password.'
        }), 400
    
    # Update password
    user.set_password(new_password)
    db.session.commit()
    
    audit_log('password_changed', {'user_id': user.id})
    
    return jsonify({'message': 'Password changed successfully'}), 200

@auth_bp.route('/session/check', methods=['GET'])
def check_session():
    """Check if session is valid and not timed out."""
    if not session_timeout_check():
        return jsonify({'valid': False, 'reason': 'session_timeout'}), 401
    
    if current_user.is_authenticated:
        return jsonify({
            'valid': True,
            'user': {
                'id': current_user.id,
                'username': current_user.username,
                'is_admin': current_user.is_admin
            }
        }), 200
    else:
        return jsonify({'valid': False, 'reason': 'not_authenticated'}), 401

@auth_bp.before_request
def before_request():
    """Before request handler for session timeout."""
    if current_user.is_authenticated:
        if not session_timeout_check():
            logout_user()
            session.clear()
