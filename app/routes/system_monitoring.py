"""
System monitoring routes for the OpenVPN management application.
"""

from flask import Blueprint, request, jsonify, current_app
from app.utils import require_auth, require_admin, audit_log
from app.services.monitoring_service import MonitoringService
from app.services.openvpn_service import OpenVPNService
from datetime import datetime, timedelta
import psutil
import os

system_bp = Blueprint('system_monitoring', __name__)

@system_bp.route('/metrics/realtime', methods=['GET'])
@require_auth
def realtime_metrics():
    """Get real-time system metrics."""
    try:
        monitoring_service = MonitoringService()
        metrics = monitoring_service.get_realtime_metrics()
        
        return jsonify(metrics), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting realtime metrics: {str(e)}")
        return jsonify({'error': 'Failed to get realtime metrics'}), 500

@system_bp.route('/metrics/historical', methods=['GET'])
@require_auth
def historical_metrics():
    """Get historical system metrics."""
    try:
        hours = request.args.get('hours', 24, type=int)
        hours = min(hours, 168)  # Limit to 1 week
        
        monitoring_service = MonitoringService()
        metrics = monitoring_service.get_historical_metrics(hours)
        
        return jsonify(metrics), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting historical metrics: {str(e)}")
        return jsonify({'error': 'Failed to get historical metrics'}), 500

@system_bp.route('/openvpn/status', methods=['GET'])
@require_auth
def openvpn_status():
    """Get detailed OpenVPN status."""
    try:
        openvpn_service = OpenVPNService()
        status = openvpn_service.get_detailed_status()
        
        return jsonify(status), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting OpenVPN status: {str(e)}")
        return jsonify({'error': 'Failed to get OpenVPN status'}), 500

@system_bp.route('/openvpn/connected-clients', methods=['GET'])
@require_auth
def connected_clients():
    """Get list of currently connected clients."""
    try:
        openvpn_service = OpenVPNService()
        connected = openvpn_service.get_connected_clients()
        
        return jsonify({
            'connected_clients': connected,
            'count': len(connected),
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting connected clients: {str(e)}")
        return jsonify({'error': 'Failed to get connected clients'}), 500

@system_bp.route('/openvpn/restart', methods=['POST'])
@require_admin
def restart_openvpn():
    """Restart OpenVPN service."""
    try:
        openvpn_service = OpenVPNService()
        result = openvpn_service.restart_service()
        
        if result['success']:
            audit_log('openvpn_restarted', {
                'restart_time': datetime.utcnow().isoformat()
            })
            
            return jsonify({
                'message': 'OpenVPN service restarted successfully',
                'details': result
            }), 200
        else:
            return jsonify({
                'error': 'Failed to restart OpenVPN service',
                'details': result
            }), 500
        
    except Exception as e:
        current_app.logger.error(f"Error restarting OpenVPN: {str(e)}")
        return jsonify({'error': 'Failed to restart OpenVPN service'}), 500

@system_bp.route('/logs/openvpn', methods=['GET'])
@require_auth
def openvpn_logs():
    """Get OpenVPN logs."""
    try:
        lines = request.args.get('lines', 100, type=int)
        lines = min(lines, 1000)  # Limit to 1000 lines
        
        follow = request.args.get('follow', 'false').lower() == 'true'
        search = request.args.get('search', '')
        
        monitoring_service = MonitoringService()
        logs = monitoring_service.get_openvpn_logs(lines=lines, search=search)
        
        return jsonify({
            'logs': logs,
            'lines_returned': len(logs),
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting OpenVPN logs: {str(e)}")
        return jsonify({'error': 'Failed to get OpenVPN logs'}), 500

@system_bp.route('/logs/system', methods=['GET'])
@require_auth
def system_logs():
    """Get system logs."""
    try:
        lines = request.args.get('lines', 100, type=int)
        lines = min(lines, 1000)  # Limit to 1000 lines
        
        log_level = request.args.get('level', 'all')
        search = request.args.get('search', '')
        
        monitoring_service = MonitoringService()
        logs = monitoring_service.get_system_logs(lines=lines, level=log_level, search=search)
        
        return jsonify({
            'logs': logs,
            'lines_returned': len(logs),
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting system logs: {str(e)}")
        return jsonify({'error': 'Failed to get system logs'}), 500

@system_bp.route('/processes', methods=['GET'])
@require_auth
def system_processes():
    """Get running system processes."""
    try:
        sort_by = request.args.get('sort', 'cpu')  # cpu, memory, name
        limit = request.args.get('limit', 20, type=int)
        limit = min(limit, 100)  # Limit to 100 processes
        
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
            try:
                proc_info = proc.info
                proc_info['cpu_percent'] = proc.cpu_percent()
                proc_info['memory_percent'] = proc.memory_percent()
                processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Sort processes
        if sort_by == 'cpu':
            processes.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
        elif sort_by == 'memory':
            processes.sort(key=lambda x: x.get('memory_percent', 0), reverse=True)
        elif sort_by == 'name':
            processes.sort(key=lambda x: x.get('name', ''))
        
        # Limit results
        processes = processes[:limit]
        
        return jsonify({
            'processes': processes,
            'count': len(processes),
            'sort_by': sort_by,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting system processes: {str(e)}")
        return jsonify({'error': 'Failed to get system processes'}), 500

@system_bp.route('/network/interfaces', methods=['GET'])
@require_auth
def network_interfaces():
    """Get network interface information."""
    try:
        interfaces = {}
        
        # Get interface statistics
        net_io = psutil.net_io_counters(pernic=True)
        
        # Get interface addresses
        net_if_addrs = psutil.net_if_addrs()
        
        # Get interface status
        net_if_stats = psutil.net_if_stats()
        
        for interface, stats in net_io.items():
            interface_info = {
                'name': interface,
                'bytes_sent': stats.bytes_sent,
                'bytes_recv': stats.bytes_recv,
                'packets_sent': stats.packets_sent,
                'packets_recv': stats.packets_recv,
                'errin': stats.errin,
                'errout': stats.errout,
                'dropin': stats.dropin,
                'dropout': stats.dropout
            }
            
            # Add addresses if available
            if interface in net_if_addrs:
                addresses = []
                for addr in net_if_addrs[interface]:
                    addresses.append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
                interface_info['addresses'] = addresses
            
            # Add status if available
            if interface in net_if_stats:
                stat = net_if_stats[interface]
                interface_info['is_up'] = stat.isup
                interface_info['duplex'] = str(stat.duplex)
                interface_info['speed'] = stat.speed
                interface_info['mtu'] = stat.mtu
            
            interfaces[interface] = interface_info
        
        return jsonify({
            'interfaces': interfaces,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting network interfaces: {str(e)}")
        return jsonify({'error': 'Failed to get network interfaces'}), 500

@system_bp.route('/disk/usage', methods=['GET'])
@require_auth
def disk_usage():
    """Get disk usage information."""
    try:
        disk_info = []
        
        # Get disk partitions
        partitions = psutil.disk_partitions()
        
        for partition in partitions:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                
                partition_info = {
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'total': usage.total,
                    'used': usage.used,
                    'free': usage.free,
                    'percent': (usage.used / usage.total) * 100 if usage.total > 0 else 0
                }
                
                disk_info.append(partition_info)
                
            except PermissionError:
                # Can't access some partitions on Windows
                continue
            except Exception:
                continue
        
        # Get disk I/O statistics
        try:
            disk_io = psutil.disk_io_counters()
            disk_io_info = {
                'read_count': disk_io.read_count,
                'write_count': disk_io.write_count,
                'read_bytes': disk_io.read_bytes,
                'write_bytes': disk_io.write_bytes,
                'read_time': disk_io.read_time,
                'write_time': disk_io.write_time
            }
        except Exception:
            disk_io_info = None
        
        return jsonify({
            'partitions': disk_info,
            'io_stats': disk_io_info,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting disk usage: {str(e)}")
        return jsonify({'error': 'Failed to get disk usage'}), 500

@system_bp.route('/alerts', methods=['GET'])
@require_auth
def system_alerts():
    """Get system alerts and warnings."""
    try:
        monitoring_service = MonitoringService()
        alerts = monitoring_service.get_system_alerts()
        
        return jsonify({
            'alerts': alerts,
            'count': len(alerts),
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting system alerts: {str(e)}")
        return jsonify({'error': 'Failed to get system alerts'}), 500

@system_bp.route('/backup/create', methods=['POST'])
@require_admin
def create_backup():
    """Create a system backup."""
    try:
        from app.services.backup_service import BackupService
        
        backup_service = BackupService()
        result = backup_service.create_backup()
        
        if result['success']:
            audit_log('backup_created', {
                'backup_file': result['backup_file'],
                'size': result.get('size', 0)
            })
            
            return jsonify({
                'message': 'Backup created successfully',
                'backup_file': result['backup_file'],
                'size': result.get('size', 0),
                'timestamp': datetime.utcnow().isoformat()
            }), 200
        else:
            return jsonify({
                'error': 'Failed to create backup',
                'details': result.get('error', 'Unknown error')
            }), 500
        
    except Exception as e:
        current_app.logger.error(f"Error creating backup: {str(e)}")
        return jsonify({'error': 'Failed to create backup'}), 500

@system_bp.route('/backup/list', methods=['GET'])
@require_auth
def list_backups():
    """List available backups."""
    try:
        from app.services.backup_service import BackupService
        
        backup_service = BackupService()
        backups = backup_service.list_backups()
        
        return jsonify({
            'backups': backups,
            'count': len(backups),
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error listing backups: {str(e)}")
        return jsonify({'error': 'Failed to list backups'}), 500

@system_bp.route('/backup/restore/<backup_name>', methods=['POST'])
@require_admin
def restore_backup(backup_name):
    """Restore from a backup."""
    try:
        from app.services.backup_service import BackupService
        
        backup_service = BackupService()
        result = backup_service.restore_backup(backup_name)
        
        if result['success']:
            audit_log('backup_restored', {
                'backup_file': backup_name,
                'restore_time': datetime.utcnow().isoformat()
            })
            
            return jsonify({
                'message': 'Backup restored successfully',
                'backup_file': backup_name,
                'timestamp': datetime.utcnow().isoformat()
            }), 200
        else:
            return jsonify({
                'error': 'Failed to restore backup',
                'details': result.get('error', 'Unknown error')
            }), 500
        
    except Exception as e:
        current_app.logger.error(f"Error restoring backup {backup_name}: {str(e)}")
        return jsonify({'error': 'Failed to restore backup'}), 500

@system_bp.route('/config/openvpn', methods=['GET'])
@require_auth
def get_openvpn_config():
    """Get OpenVPN server configuration."""
    try:
        openvpn_service = OpenVPNService()
        config = openvpn_service.get_server_config()
        
        return jsonify({
            'config': config,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting OpenVPN config: {str(e)}")
        return jsonify({'error': 'Failed to get OpenVPN configuration'}), 500

@system_bp.route('/config/openvpn', methods=['POST'])
@require_admin
def update_openvpn_config():
    """Update OpenVPN server configuration."""
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        config_data = request.get_json()
        if not config_data or 'config' not in config_data:
            return jsonify({'error': 'Configuration data is required'}), 400
        
        openvpn_service = OpenVPNService()
        result = openvpn_service.update_server_config(config_data['config'])
        
        if result['success']:
            audit_log('openvpn_config_updated', {
                'config_changes': 'Configuration updated',
                'update_time': datetime.utcnow().isoformat()
            })
            
            return jsonify({
                'message': 'OpenVPN configuration updated successfully',
                'restart_required': result.get('restart_required', True),
                'timestamp': datetime.utcnow().isoformat()
            }), 200
        else:
            return jsonify({
                'error': 'Failed to update OpenVPN configuration',
                'details': result.get('error', 'Unknown error')
            }), 500
        
    except Exception as e:
        current_app.logger.error(f"Error updating OpenVPN config: {str(e)}")
        return jsonify({'error': 'Failed to update OpenVPN configuration'}), 500

@system_bp.route('/prometheus/metrics', methods=['GET'])
@require_auth
def prometheus_metrics():
    """Get Prometheus-compatible metrics."""
    try:
        from app.services.prometheus_service import PrometheusService
        
        prometheus_service = PrometheusService()
        metrics = prometheus_service.generate_metrics()
        
        return metrics, 200, {'Content-Type': 'text/plain; charset=utf-8'}
        
    except Exception as e:
        current_app.logger.error(f"Error getting Prometheus metrics: {str(e)}")
        return "# Error generating metrics\n", 500, {'Content-Type': 'text/plain; charset=utf-8'}
