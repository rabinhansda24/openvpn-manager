"""
Main routes for the OpenVPN management application.
"""

from flask import Blueprint, render_template, jsonify, current_app, redirect, url_for, request, session
from flask_login import login_required, current_user
from app.utils import require_auth, audit_log
from app.models.client import VPNClient
from app.models.user import User
from app import db
import os
import psutil
from datetime import datetime, timedelta

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    """Main entry point - redirect to dashboard if authenticated, login if not."""
    try:
        # Add explicit check to handle potential proxy issues
        if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
            current_app.logger.debug("User is authenticated, redirecting to dashboard")
            return redirect(url_for('main.dashboard'))
        else:
            current_app.logger.debug("User is not authenticated, redirecting to login")
            # Pass the next parameter to login page for redirect after login
            next_url = request.args.get('next', url_for('main.dashboard'))
            return redirect(url_for('auth.login_page', next=next_url))
    except Exception as e:
        current_app.logger.error(f"Error in index route: {str(e)}")
        # Default to login page if there's any error
        return redirect(url_for('auth.login_page'))

@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Dashboard page."""
    return render_template('dashboard.html')

@main_bp.route('/clients')
@login_required
def clients():
    """Clients management page."""
    return render_template('clients.html')

@main_bp.route('/logs')
@login_required
def logs():
    """Logs viewer page."""
    return render_template('logs.html')

@main_bp.route('/settings')
@login_required
def settings():
    """Settings page."""
    return render_template('settings.html')

@main_bp.route('/api/dashboard/stats')
@require_auth
def dashboard_stats():
    """Get dashboard statistics."""
    try:
        # Client statistics
        total_clients = VPNClient.query.count()
        active_clients = VPNClient.query.filter_by(is_active=True, is_revoked=False).count()
        revoked_clients = VPNClient.query.filter_by(is_revoked=True).count()
        
        # Expiring certificates (within 30 days)
        thirty_days_from_now = datetime.utcnow() + timedelta(days=30)
        expiring_clients = VPNClient.query.filter(
            VPNClient.cert_expires_at <= thirty_days_from_now,
            VPNClient.is_revoked == False
        ).count()
        
        # System statistics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Network statistics
        network = psutil.net_io_counters()
        
        # OpenVPN status
        openvpn_running = check_openvpn_status()
        
        stats = {
            'clients': {
                'total': total_clients,
                'active': active_clients,
                'revoked': revoked_clients,
                'expiring_soon': expiring_clients
            },
            'system': {
                'cpu_percent': cpu_percent,
                'memory': {
                    'total': memory.total,
                    'available': memory.available,
                    'percent': memory.percent,
                    'used': memory.used
                },
                'disk': {
                    'total': disk.total,
                    'used': disk.used,
                    'free': disk.free,
                    'percent': (disk.used / disk.total) * 100
                },
                'network': {
                    'bytes_sent': network.bytes_sent,
                    'bytes_recv': network.bytes_recv,
                    'packets_sent': network.packets_sent,
                    'packets_recv': network.packets_recv
                }
            },
            'openvpn': {
                'running': openvpn_running,
                'status': 'running' if openvpn_running else 'stopped'
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(stats), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting dashboard stats: {str(e)}")
        return jsonify({'error': 'Failed to get dashboard statistics'}), 500

@main_bp.route('/api/dashboard/recent-activity')
@require_auth
def recent_activity():
    """Get recent activity."""
    try:
        # Get recently created clients
        recent_clients = VPNClient.query.order_by(
            VPNClient.created_at.desc()
        ).limit(5).all()
        
        # Get recently connected clients
        recently_connected = VPNClient.query.filter(
            VPNClient.last_seen.isnot(None)
        ).order_by(VPNClient.last_seen.desc()).limit(5).all()
        
        activity = {
            'recent_clients': [
                {
                    'name': client.name,
                    'created_at': client.created_at.isoformat() if client.created_at else None,
                    'is_active': client.is_active
                }
                for client in recent_clients
            ],
            'recently_connected': [
                {
                    'name': client.name,
                    'last_seen': client.last_seen.isoformat() if client.last_seen else None,
                    'bandwidth_usage': client.formatted_bandwidth_usage
                }
                for client in recently_connected
            ]
        }
        
        return jsonify(activity), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting recent activity: {str(e)}")
        return jsonify({'error': 'Failed to get recent activity'}), 500

def check_openvpn_status():
    """Check if OpenVPN service is running."""
    try:
        # Check if openvpn process is running
        for process in psutil.process_iter(['pid', 'name']):
            if 'openvpn' in process.info['name'].lower():
                return True
        return False
    except Exception:
        return False

@main_bp.route('/api/system/health')
@require_auth
def system_health():
    """Get system health status."""
    try:
        health_status = {
            'database': check_database_health(),
            'redis': check_redis_health(),
            'openvpn': check_openvpn_status(),
            'disk_space': check_disk_space(),
            'memory': check_memory_usage(),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Overall health
        all_healthy = all([
            health_status['database'],
            health_status['redis'],
            health_status['openvpn'],
            health_status['disk_space'],
            health_status['memory']
        ])
        
        health_status['overall'] = 'healthy' if all_healthy else 'unhealthy'
        
        return jsonify(health_status), 200
        
    except Exception as e:
        current_app.logger.error(f"Error checking system health: {str(e)}")
        return jsonify({'error': 'Failed to check system health'}), 500

def check_database_health():
    """Check database connectivity."""
    try:
        db.session.execute('SELECT 1')
        return True
    except Exception:
        return False

def check_redis_health():
    """Check Redis connectivity."""
    try:
        import redis
        redis_client = redis.from_url(current_app.config['REDIS_URL'])
        redis_client.ping()
        return True
    except Exception:
        return False

def check_disk_space():
    """Check if sufficient disk space is available."""
    try:
        disk = psutil.disk_usage('/')
        free_percent = (disk.free / disk.total) * 100
        return free_percent > 10  # Consider healthy if more than 10% free
    except Exception:
        return False

def check_memory_usage():
    """Check memory usage."""
    try:
        memory = psutil.virtual_memory()
        return memory.percent < 90  # Consider healthy if less than 90% used
    except Exception:
        return False

@main_bp.route('/debug-auth')
def debug_auth():
    """Debug endpoint to check authentication state."""
    auth_status = {
        'is_authenticated': getattr(current_user, 'is_authenticated', False),
        'user_id': getattr(current_user, 'id', None),
        'username': getattr(current_user, 'username', None),
        'session_keys': list(session.keys()) if session else [],
        'request_cookies': {k: v for k, v in request.cookies.items()}
    }
    return jsonify(auth_status)

@main_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    if current_user.is_authenticated:
        audit_log('page_not_found', {'path': request.path})
    return render_template('errors/404.html'), 404

@main_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    db.session.rollback()
    if current_user.is_authenticated:
        audit_log('internal_error', {'path': request.path, 'error': str(error)})
    return render_template('errors/500.html'), 500

@main_bp.errorhandler(403)
def forbidden(error):
    """Handle 403 errors."""
    if current_user.is_authenticated:
        audit_log('access_denied', {'path': request.path})
    return render_template('errors/403.html'), 403
