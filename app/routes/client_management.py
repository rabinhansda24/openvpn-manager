"""
Client management routes for the OpenVPN management application.
"""

from flask import Blueprint, request, jsonify, send_file, current_app
from flask_login import current_user
from app.utils import require_auth, require_admin, validate_json_input, audit_log, sanitize_input
from app.models.client import VPNClient
from app.services.openvpn_service import OpenVPNService
from app.services.certificate_service import CertificateService
from app import db
from datetime import datetime, timedelta
import io
import zipfile
import os

client_bp = Blueprint('client_management', __name__)

@client_bp.route('/bulk-create', methods=['POST'])
@require_admin
@validate_json_input(required_fields=['clients'])
def bulk_create_clients():
    """Create multiple VPN clients at once."""
    try:
        data = sanitize_input(request.get_json())
        clients_data = data.get('clients', [])
        
        if not isinstance(clients_data, list) or len(clients_data) == 0:
            return jsonify({'error': 'Clients data must be a non-empty array'}), 400
        
        if len(clients_data) > 50:  # Limit bulk operations
            return jsonify({'error': 'Cannot create more than 50 clients at once'}), 400
        
        created_clients = []
        errors = []
        
        openvpn_service = OpenVPNService()
        cert_service = CertificateService()
        
        for idx, client_data in enumerate(clients_data):
            try:
                # Validate required fields
                if 'name' not in client_data:
                    errors.append(f"Client {idx + 1}: Name is required")
                    continue
                
                # Validate client name
                from app.utils.validation import validate_client_name, validate_email
                if not validate_client_name(client_data['name']):
                    errors.append(f"Client {idx + 1}: Invalid name format")
                    continue
                
                # Check if client already exists
                existing_client = VPNClient.query.filter_by(name=client_data['name']).first()
                if existing_client:
                    errors.append(f"Client {idx + 1}: Name '{client_data['name']}' already exists")
                    continue
                
                # Validate email if provided
                if client_data.get('email') and not validate_email(client_data['email']):
                    errors.append(f"Client {idx + 1}: Invalid email format")
                    continue
                
                # Create client
                client = VPNClient(
                    name=client_data['name'],
                    email=client_data.get('email'),
                    description=client_data.get('description'),
                    bandwidth_limit_download=client_data.get('bandwidth_limit_download', 0),
                    bandwidth_limit_upload=client_data.get('bandwidth_limit_upload', 0),
                    created_by=current_user.id
                )
                
                db.session.add(client)
                db.session.flush()  # Get the ID without committing
                
                # Generate certificates
                cert_result = cert_service.create_client_certificate(client.name)
                if not cert_result['success']:
                    errors.append(f"Client {idx + 1}: Failed to create certificate - {cert_result['error']}")
                    db.session.rollback()
                    continue
                
                # Update client with certificate paths
                client.certificate_path = cert_result['cert_path']
                client.private_key_path = cert_result['key_path']
                client.config_file_path = cert_result['config_path']
                client.cert_created_at = datetime.utcnow()
                
                created_clients.append(client.to_dict())
                
            except Exception as e:
                errors.append(f"Client {idx + 1}: {str(e)}")
                continue
        
        if created_clients:
            db.session.commit()
            
            audit_log('bulk_clients_created', {
                'count': len(created_clients),
                'client_names': [c['name'] for c in created_clients]
            })
        else:
            db.session.rollback()
        
        return jsonify({
            'message': f'Created {len(created_clients)} clients successfully',
            'created_clients': created_clients,
            'errors': errors,
            'success_count': len(created_clients),
            'error_count': len(errors)
        }), 201 if created_clients else 400
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error in bulk client creation: {str(e)}")
        return jsonify({'error': 'Failed to create clients'}), 500

@client_bp.route('/export', methods=['GET'])
@require_auth
def export_clients():
    """Export client list as CSV or JSON."""
    try:
        format_type = request.args.get('format', 'json').lower()
        include_revoked = request.args.get('include_revoked', 'false').lower() == 'true'
        
        # Build query
        query = VPNClient.query
        if not include_revoked:
            query = query.filter_by(is_revoked=False)
        
        clients = query.order_by(VPNClient.created_at.desc()).all()
        
        if format_type == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                'Name', 'Email', 'Description', 'Status', 'Created At', 
                'Last Seen', 'Bytes Sent', 'Bytes Received', 'Expires At'
            ])
            
            # Write data
            for client in clients:
                writer.writerow([
                    client.name,
                    client.email or '',
                    client.description or '',
                    'Active' if client.is_active and not client.is_revoked else 'Inactive',
                    client.created_at.isoformat() if client.created_at else '',
                    client.last_seen.isoformat() if client.last_seen else '',
                    client.total_bytes_sent,
                    client.total_bytes_received,
                    client.cert_expires_at.isoformat() if client.cert_expires_at else ''
                ])
            
            output.seek(0)
            
            return send_file(
                io.BytesIO(output.getvalue().encode()),
                mimetype='text/csv',
                as_attachment=True,
                download_name=f'vpn_clients_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            )
        
        else:  # JSON format
            clients_data = [client.to_dict() for client in clients]
            
            audit_log('clients_exported', {
                'format': format_type,
                'count': len(clients_data),
                'include_revoked': include_revoked
            })
            
            return jsonify({
                'clients': clients_data,
                'exported_at': datetime.utcnow().isoformat(),
                'total_count': len(clients_data)
            }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error exporting clients: {str(e)}")
        return jsonify({'error': 'Failed to export clients'}), 500

@client_bp.route('/bulk-download', methods=['POST'])
@require_auth
@validate_json_input(required_fields=['client_ids'])
def bulk_download_configs():
    """Download multiple client configurations as a ZIP file."""
    try:
        data = sanitize_input(request.get_json())
        client_ids = data.get('client_ids', [])
        
        if not isinstance(client_ids, list) or len(client_ids) == 0:
            return jsonify({'error': 'Client IDs must be a non-empty array'}), 400
        
        if len(client_ids) > 20:  # Limit bulk downloads
            return jsonify({'error': 'Cannot download more than 20 configurations at once'}), 400
        
        # Get clients
        clients = VPNClient.query.filter(
            VPNClient.id.in_(client_ids),
            VPNClient.is_revoked == False
        ).all()
        
        if not clients:
            return jsonify({'error': 'No valid clients found'}), 404
        
        # Create ZIP file in memory
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            openvpn_service = OpenVPNService()
            
            for client in clients:
                try:
                    # Generate client configuration
                    config_content = openvpn_service.generate_client_config(client.name)
                    if config_content:
                        zip_file.writestr(f"{client.name}.ovpn", config_content)
                except Exception as e:
                    current_app.logger.error(f"Error generating config for {client.name}: {str(e)}")
                    continue
        
        zip_buffer.seek(0)
        
        audit_log('bulk_configs_downloaded', {
            'client_ids': client_ids,
            'client_names': [c.name for c in clients]
        })
        
        return send_file(
            zip_buffer,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'vpn_configs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip'
        )
        
    except Exception as e:
        current_app.logger.error(f"Error in bulk config download: {str(e)}")
        return jsonify({'error': 'Failed to download configurations'}), 500

@client_bp.route('/analytics', methods=['GET'])
@require_auth
def client_analytics():
    """Get client usage analytics."""
    try:
        days = request.args.get('days', 30, type=int)
        client_id = request.args.get('client_id', type=int)
        
        # Limit days to prevent excessive queries
        days = min(days, 365)
        start_date = datetime.utcnow() - timedelta(days=days)
        
        analytics = {}
        
        if client_id:
            # Analytics for specific client
            client = VPNClient.query.get_or_404(client_id)
            
            analytics = {
                'client': client.to_dict(),
                'usage_summary': {
                    'total_bytes_sent': client.total_bytes_sent,
                    'total_bytes_received': client.total_bytes_received,
                    'total_bytes_transferred': client.total_bytes_transferred,
                    'total_connection_time': client.total_connection_time,
                    'formatted_usage': client.formatted_bandwidth_usage
                },
                'certificate_info': {
                    'created_at': client.cert_created_at.isoformat() if client.cert_created_at else None,
                    'expires_at': client.cert_expires_at.isoformat() if client.cert_expires_at else None,
                    'days_until_expiry': client.days_until_expiry,
                    'is_expiring_soon': client.is_expiring_soon,
                    'is_expired': client.is_certificate_expired
                }
            }
        else:
            # Overall analytics
            total_clients = VPNClient.query.count()
            active_clients = VPNClient.query.filter_by(is_active=True, is_revoked=False).count()
            revoked_clients = VPNClient.query.filter_by(is_revoked=True).count()
            
            # Clients created in the period
            new_clients = VPNClient.query.filter(
                VPNClient.created_at >= start_date
            ).count()
            
            # Expiring certificates
            thirty_days_from_now = datetime.utcnow() + timedelta(days=30)
            expiring_clients = VPNClient.query.filter(
                VPNClient.cert_expires_at <= thirty_days_from_now,
                VPNClient.is_revoked == False
            ).count()
            
            # Total bandwidth usage
            total_sent = db.session.query(
                db.func.sum(VPNClient.total_bytes_sent)
            ).scalar() or 0
            
            total_received = db.session.query(
                db.func.sum(VPNClient.total_bytes_received)
            ).scalar() or 0
            
            analytics = {
                'summary': {
                    'total_clients': total_clients,
                    'active_clients': active_clients,
                    'revoked_clients': revoked_clients,
                    'new_clients_period': new_clients,
                    'expiring_certificates': expiring_clients
                },
                'bandwidth': {
                    'total_bytes_sent': total_sent,
                    'total_bytes_received': total_received,
                    'total_bytes_transferred': total_sent + total_received
                },
                'period': {
                    'days': days,
                    'start_date': start_date.isoformat(),
                    'end_date': datetime.utcnow().isoformat()
                }
            }
        
        return jsonify(analytics), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting client analytics: {str(e)}")
        return jsonify({'error': 'Failed to get analytics'}), 500

@client_bp.route('/<int:client_id>/regenerate-cert', methods=['POST'])
@require_admin
def regenerate_certificate(client_id):
    """Regenerate certificate for a client."""
    try:
        client = VPNClient.query.get_or_404(client_id)
        
        if client.is_revoked:
            return jsonify({'error': 'Cannot regenerate certificate for revoked client'}), 400
        
        cert_service = CertificateService()
        
        # Revoke old certificate first
        if client.certificate_path:
            revoke_result = cert_service.revoke_client_certificate(client.name)
            if not revoke_result['success']:
                current_app.logger.warning(f"Failed to revoke old certificate for {client.name}: {revoke_result['error']}")
        
        # Generate new certificate
        cert_result = cert_service.create_client_certificate(client.name)
        if not cert_result['success']:
            return jsonify({'error': f"Failed to create new certificate: {cert_result['error']}"}), 500
        
        # Update client record
        client.certificate_path = cert_result['cert_path']
        client.private_key_path = cert_result['key_path']
        client.config_file_path = cert_result['config_path']
        client.cert_created_at = datetime.utcnow()
        client.cert_expires_at = datetime.utcnow() + timedelta(days=365)
        
        db.session.commit()
        
        audit_log('certificate_regenerated', {
            'client_id': client.id,
            'client_name': client.name
        })
        
        return jsonify({
            'message': 'Certificate regenerated successfully',
            'client': client.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error regenerating certificate for client {client_id}: {str(e)}")
        return jsonify({'error': 'Failed to regenerate certificate'}), 500

@client_bp.route('/expiring', methods=['GET'])
@require_auth
def get_expiring_certificates():
    """Get clients with expiring certificates."""
    try:
        days = request.args.get('days', 30, type=int)
        days = min(days, 365)  # Limit to 1 year
        
        expiry_date = datetime.utcnow() + timedelta(days=days)
        
        expiring_clients = VPNClient.query.filter(
            VPNClient.cert_expires_at <= expiry_date,
            VPNClient.is_revoked == False
        ).order_by(VPNClient.cert_expires_at.asc()).all()
        
        clients_data = []
        for client in expiring_clients:
            client_dict = client.to_dict()
            client_dict['urgency'] = 'critical' if client.days_until_expiry <= 7 else 'warning'
            clients_data.append(client_dict)
        
        return jsonify({
            'expiring_clients': clients_data,
            'count': len(clients_data),
            'period_days': days,
            'check_date': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting expiring certificates: {str(e)}")
        return jsonify({'error': 'Failed to get expiring certificates'}), 500

@client_bp.route('/<int:client_id>/reset-usage', methods=['POST'])
@require_admin
def reset_client_usage(client_id):
    """Reset usage statistics for a client."""
    try:
        client = VPNClient.query.get_or_404(client_id)
        
        # Store old values for audit
        old_usage = {
            'bytes_sent': client.total_bytes_sent,
            'bytes_received': client.total_bytes_received,
            'connection_time': client.total_connection_time
        }
        
        # Reset usage statistics
        client.total_bytes_sent = 0
        client.total_bytes_received = 0
        client.total_connection_time = 0
        
        db.session.commit()
        
        audit_log('client_usage_reset', {
            'client_id': client.id,
            'client_name': client.name,
            'old_usage': old_usage
        })
        
        return jsonify({
            'message': 'Usage statistics reset successfully',
            'client': client.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error resetting usage for client {client_id}: {str(e)}")
        return jsonify({'error': 'Failed to reset usage statistics'}), 500
