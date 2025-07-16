"""
API routes for the OpenVPN management application.
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required
from app.utils import require_auth, require_admin, validate_json_input, audit_log, sanitize_input
from app.models.client import VPNClient
from app.models.user import User
from app import db
import os
import psutil
from datetime import datetime

api_bp = Blueprint('api', __name__)

@api_bp.route('/status', methods=['GET'])
@require_auth
def api_status():
    """API status endpoint."""
    return jsonify({
        'status': 'operational',
        'version': '1.0.0',
        'timestamp': datetime.utcnow().isoformat(),
        'user': {
            'authenticated': True,
            'username': request.current_user.username if hasattr(request, 'current_user') else None
        }
    }), 200

@api_bp.route('/clients', methods=['GET'])
@require_auth
def list_clients():
    """List all VPN clients."""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        status_filter = request.args.get('status', 'all')
        search = request.args.get('search', '')
        
        # Build query
        query = VPNClient.query
        
        # Apply status filter
        if status_filter == 'active':
            query = query.filter_by(is_active=True, is_revoked=False)
        elif status_filter == 'revoked':
            query = query.filter_by(is_revoked=True)
        elif status_filter == 'expired':
            query = query.filter(VPNClient.cert_expires_at <= datetime.utcnow())
        
        # Apply search filter
        if search:
            query = query.filter(
                VPNClient.name.ilike(f'%{search}%') |
                VPNClient.email.ilike(f'%{search}%')
            )
        
        # Paginate
        pagination = query.order_by(VPNClient.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        clients_data = [client.to_dict() for client in pagination.items]
        
        return jsonify({
            'clients': clients_data,
            'pagination': {
                'page': page,
                'pages': pagination.pages,
                'per_page': per_page,
                'total': pagination.total,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error listing clients: {str(e)}")
        return jsonify({'error': 'Failed to list clients'}), 500

@api_bp.route('/clients/<int:client_id>', methods=['GET'])
@require_auth
def get_client(client_id):
    """Get specific client details."""
    try:
        client = VPNClient.query.get_or_404(client_id)
        return jsonify(client.to_dict()), 200
    except Exception as e:
        current_app.logger.error(f"Error getting client {client_id}: {str(e)}")
        return jsonify({'error': 'Failed to get client details'}), 500

@api_bp.route('/clients', methods=['POST'])
@require_admin
@validate_json_input(required_fields=['name'], optional_fields=['email', 'description', 'bandwidth_limit_download', 'bandwidth_limit_upload'])
def create_client():
    """Create a new VPN client."""
    try:
        data = sanitize_input(request.get_json())
        
        # Validate client name
        from app.utils.validation import validate_client_name, validate_email
        if not validate_client_name(data['name']):
            return jsonify({'error': 'Invalid client name format'}), 400
        
        # Check if client already exists
        existing_client = VPNClient.query.filter_by(name=data['name']).first()
        if existing_client:
            return jsonify({'error': 'Client with this name already exists'}), 409
        
        # Validate email if provided
        if data.get('email') and not validate_email(data['email']):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Create new client
        client = VPNClient(
            name=data['name'],
            email=data.get('email'),
            description=data.get('description'),
            bandwidth_limit_download=data.get('bandwidth_limit_download', 0),
            bandwidth_limit_upload=data.get('bandwidth_limit_upload', 0),
            created_by=request.current_user.id if hasattr(request, 'current_user') else None
        )
        
        db.session.add(client)
        db.session.commit()
        
        # TODO: Generate OpenVPN certificates and config
        # This would call the OpenVPN service to create certificates
        
        audit_log('client_created', {
            'client_id': client.id,
            'client_name': client.name
        })
        
        return jsonify({
            'message': 'Client created successfully',
            'client': client.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating client: {str(e)}")
        return jsonify({'error': 'Failed to create client'}), 500

@api_bp.route('/clients/<int:client_id>', methods=['PUT'])
@require_admin
@validate_json_input(optional_fields=['email', 'description', 'bandwidth_limit_download', 'bandwidth_limit_upload', 'is_active'])
def update_client(client_id):
    """Update client details."""
    try:
        client = VPNClient.query.get_or_404(client_id)
        data = sanitize_input(request.get_json())
        
        # Validate email if provided
        if data.get('email'):
            from app.utils.validation import validate_email
            if not validate_email(data['email']):
                return jsonify({'error': 'Invalid email format'}), 400
            client.email = data['email']
        
        # Update other fields
        if 'description' in data:
            client.description = data['description']
        if 'bandwidth_limit_download' in data:
            client.bandwidth_limit_download = data['bandwidth_limit_download']
        if 'bandwidth_limit_upload' in data:
            client.bandwidth_limit_upload = data['bandwidth_limit_upload']
        if 'is_active' in data and not client.is_revoked:
            client.is_active = data['is_active']
        
        db.session.commit()
        
        audit_log('client_updated', {
            'client_id': client.id,
            'client_name': client.name,
            'changes': data
        })
        
        return jsonify({
            'message': 'Client updated successfully',
            'client': client.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error updating client {client_id}: {str(e)}")
        return jsonify({'error': 'Failed to update client'}), 500

@api_bp.route('/clients/<int:client_id>/revoke', methods=['POST'])
@require_admin
def revoke_client(client_id):
    """Revoke a client certificate."""
    try:
        client = VPNClient.query.get_or_404(client_id)
        
        if client.is_revoked:
            return jsonify({'error': 'Client is already revoked'}), 400
        
        # Revoke the client
        client.revoke()
        db.session.commit()
        
        # TODO: Revoke certificate in OpenVPN
        # This would call the OpenVPN service to revoke the certificate
        
        audit_log('client_revoked', {
            'client_id': client.id,
            'client_name': client.name
        })
        
        return jsonify({
            'message': 'Client revoked successfully',
            'client': client.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error revoking client {client_id}: {str(e)}")
        return jsonify({'error': 'Failed to revoke client'}), 500

@api_bp.route('/clients/<int:client_id>/download', methods=['GET'])
@require_auth
def download_client_config(client_id):
    """Download client configuration file."""
    try:
        client = VPNClient.query.get_or_404(client_id)
        
        if client.is_revoked:
            return jsonify({'error': 'Cannot download config for revoked client'}), 400
        
        # TODO: Generate and return .ovpn file
        # This would generate the OpenVPN configuration file
        
        audit_log('client_config_downloaded', {
            'client_id': client.id,
            'client_name': client.name
        })
        
        return jsonify({
            'message': 'Config download would start here',
            'client_name': client.name
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error downloading config for client {client_id}: {str(e)}")
        return jsonify({'error': 'Failed to download client config'}), 500

@api_bp.route('/clients/<int:client_id>/qr', methods=['GET'])
@require_auth
def get_client_qr_code(client_id):
    """Generate QR code for client setup."""
    try:
        client = VPNClient.query.get_or_404(client_id)
        
        if client.is_revoked:
            return jsonify({'error': 'Cannot generate QR code for revoked client'}), 400
        
        # TODO: Generate QR code with client configuration
        # This would generate a QR code containing the OpenVPN configuration
        
        return jsonify({
            'message': 'QR code would be generated here',
            'client_name': client.name
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error generating QR code for client {client_id}: {str(e)}")
        return jsonify({'error': 'Failed to generate QR code'}), 500

@api_bp.route('/server/status', methods=['GET'])
@require_auth
def server_status():
    """Get VPN server status."""
    try:
        # TODO: Implement actual OpenVPN status checking
        # This would parse the OpenVPN status log
        
        # Mock data for now
        status = {
            'running': True,
            'uptime': '2 days, 5 hours, 30 minutes',
            'connected_clients': 5,
            'total_clients': 12,
            'server_load': 'low',
            'last_updated': datetime.utcnow().isoformat()
        }
        
        return jsonify(status), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting server status: {str(e)}")
        return jsonify({'error': 'Failed to get server status'}), 500

@api_bp.route('/server/config', methods=['GET'])
@require_auth
def get_server_config():
    """Get OpenVPN server configuration."""
    try:
        # TODO: Read actual OpenVPN server configuration
        config_path = current_app.config.get('OPENVPN_CONFIG_PATH', '/etc/openvpn')
        
        return jsonify({
            'message': 'Server config would be loaded here',
            'config_path': config_path
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting server config: {str(e)}")
        return jsonify({'error': 'Failed to get server configuration'}), 500

@api_bp.route('/server/config', methods=['POST'])
@require_admin
def update_server_config():
    """Update OpenVPN server configuration."""
    try:
        # TODO: Implement server configuration update
        # This would validate and update the OpenVPN server configuration
        
        audit_log('server_config_updated', {
            'config_changes': 'would be logged here'
        })
        
        return jsonify({
            'message': 'Server configuration would be updated here'
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error updating server config: {str(e)}")
        return jsonify({'error': 'Failed to update server configuration'}), 500

@api_bp.route('/logs', methods=['GET'])
@require_auth
def get_logs():
    """Get OpenVPN logs."""
    try:
        lines = request.args.get('lines', 100, type=int)
        log_type = request.args.get('type', 'openvpn')
        
        # TODO: Implement actual log reading
        # This would read and return OpenVPN logs
        
        return jsonify({
            'message': 'Logs would be returned here',
            'lines': lines,
            'log_type': log_type
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting logs: {str(e)}")
        return jsonify({'error': 'Failed to get logs'}), 500

@api_bp.route('/system/metrics', methods=['GET'])
@require_auth
def system_metrics():
    """Get system performance metrics."""
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        
        # Memory usage
        memory = psutil.virtual_memory()
        
        # Disk usage
        disk = psutil.disk_usage('/')
        
        # Network statistics
        network = psutil.net_io_counters()
        
        # Load average (Unix systems)
        try:
            load_avg = os.getloadavg()
        except (OSError, AttributeError):
            load_avg = [0, 0, 0]  # Windows doesn't have load average
        
        metrics = {
            'cpu': {
                'percent': cpu_percent,
                'count': cpu_count,
                'load_avg': {
                    '1min': load_avg[0],
                    '5min': load_avg[1],
                    '15min': load_avg[2]
                }
            },
            'memory': {
                'total': memory.total,
                'available': memory.available,
                'percent': memory.percent,
                'used': memory.used,
                'free': memory.free
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
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(metrics), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting system metrics: {str(e)}")
        return jsonify({'error': 'Failed to get system metrics'}), 500

@api_bp.errorhandler(404)
def api_not_found(error):
    """Handle API 404 errors."""
    return jsonify({'error': 'API endpoint not found'}), 404

@api_bp.errorhandler(405)
def method_not_allowed(error):
    """Handle method not allowed errors."""
    return jsonify({'error': 'Method not allowed'}), 405

@api_bp.errorhandler(500)
def api_internal_error(error):
    """Handle API 500 errors."""
    return jsonify({'error': 'Internal server error'}), 500
