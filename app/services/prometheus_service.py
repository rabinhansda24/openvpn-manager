"""
Prometheus service for metrics export.
"""

from datetime import datetime
from flask import current_app
import psutil
import os
from app.models.client import VPNClient
from app.services.openvpn_service import OpenVPNService

class PrometheusService:
    """Service class for Prometheus metrics export."""
    
    def __init__(self):
        self.openvpn_service = OpenVPNService()
    
    def generate_metrics(self):
        """Generate Prometheus-compatible metrics."""
        try:
            metrics = []
            
            # Add help and type declarations
            metrics.append("# HELP openvpn_manager_info Information about the OpenVPN Manager")
            metrics.append("# TYPE openvpn_manager_info gauge")
            metrics.append('openvpn_manager_info{version="1.0.0"} 1')
            metrics.append("")
            
            # System metrics
            self._add_system_metrics(metrics)
            
            # OpenVPN metrics
            self._add_openvpn_metrics(metrics)
            
            # Client metrics
            self._add_client_metrics(metrics)
            
            # Application metrics
            self._add_application_metrics(metrics)
            
            return '\n'.join(metrics)
            
        except Exception as e:
            current_app.logger.error(f"Error generating Prometheus metrics: {str(e)}")
            return "# Error generating metrics\n"
    
    def _add_system_metrics(self, metrics):
        """Add system performance metrics."""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_count = psutil.cpu_count()
            
            metrics.extend([
                "# HELP system_cpu_usage_percent CPU usage percentage",
                "# TYPE system_cpu_usage_percent gauge",
                f"system_cpu_usage_percent {cpu_percent}",
                "",
                "# HELP system_cpu_count Number of CPU cores",
                "# TYPE system_cpu_count gauge", 
                f"system_cpu_count {cpu_count}",
                ""
            ])
            
            # Load average (Unix only)
            try:
                load_avg = os.getloadavg()
                metrics.extend([
                    "# HELP system_load_average System load average",
                    "# TYPE system_load_average gauge",
                    f'system_load_average{{period="1m"}} {load_avg[0]}',
                    f'system_load_average{{period="5m"}} {load_avg[1]}',
                    f'system_load_average{{period="15m"}} {load_avg[2]}',
                    ""
                ])
            except (OSError, AttributeError):
                pass
            
            # Memory metrics
            memory = psutil.virtual_memory()
            metrics.extend([
                "# HELP system_memory_usage_bytes Memory usage in bytes",
                "# TYPE system_memory_usage_bytes gauge",
                f"system_memory_usage_bytes {memory.used}",
                "",
                "# HELP system_memory_total_bytes Total memory in bytes",
                "# TYPE system_memory_total_bytes gauge",
                f"system_memory_total_bytes {memory.total}",
                "",
                "# HELP system_memory_usage_percent Memory usage percentage",
                "# TYPE system_memory_usage_percent gauge",
                f"system_memory_usage_percent {memory.percent}",
                ""
            ])
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100 if disk.total > 0 else 0
            
            metrics.extend([
                "# HELP system_disk_usage_bytes Disk usage in bytes",
                "# TYPE system_disk_usage_bytes gauge",
                f"system_disk_usage_bytes {disk.used}",
                "",
                "# HELP system_disk_total_bytes Total disk space in bytes",
                "# TYPE system_disk_total_bytes gauge",
                f"system_disk_total_bytes {disk.total}",
                "",
                "# HELP system_disk_usage_percent Disk usage percentage",
                "# TYPE system_disk_usage_percent gauge",
                f"system_disk_usage_percent {disk_percent}",
                ""
            ])
            
            # Network metrics
            network = psutil.net_io_counters()
            if network:
                metrics.extend([
                    "# HELP system_network_bytes_sent_total Network bytes sent",
                    "# TYPE system_network_bytes_sent_total counter",
                    f"system_network_bytes_sent_total {network.bytes_sent}",
                    "",
                    "# HELP system_network_bytes_received_total Network bytes received",
                    "# TYPE system_network_bytes_received_total counter",
                    f"system_network_bytes_received_total {network.bytes_recv}",
                    ""
                ])
            
        except Exception as e:
            current_app.logger.error(f"Error adding system metrics: {str(e)}")
    
    def _add_openvpn_metrics(self, metrics):
        """Add OpenVPN server metrics."""
        try:
            # Server status
            status = self.openvpn_service.get_server_status()
            server_running = 1 if status.get('running', False) else 0
            
            metrics.extend([
                "# HELP openvpn_server_up OpenVPN server status (1 = up, 0 = down)",
                "# TYPE openvpn_server_up gauge",
                f"openvpn_server_up {server_running}",
                ""
            ])
            
            # Connected clients
            connected_clients = self.openvpn_service.get_connected_clients()
            
            metrics.extend([
                "# HELP openvpn_connected_clients Number of connected clients",
                "# TYPE openvpn_connected_clients gauge",
                f"openvpn_connected_clients {len(connected_clients)}",
                ""
            ])
            
            # Per-client metrics
            if connected_clients:
                metrics.extend([
                    "# HELP openvpn_client_bytes_sent_total Bytes sent by client",
                    "# TYPE openvpn_client_bytes_sent_total counter",
                ])
                
                for client in connected_clients:
                    client_name = client.get('name', 'unknown')
                    bytes_sent = client.get('bytes_sent', 0)
                    metrics.append(f'openvpn_client_bytes_sent_total{{client="{client_name}"}} {bytes_sent}')
                
                metrics.append("")
                
                metrics.extend([
                    "# HELP openvpn_client_bytes_received_total Bytes received by client",
                    "# TYPE openvpn_client_bytes_received_total counter",
                ])
                
                for client in connected_clients:
                    client_name = client.get('name', 'unknown')
                    bytes_received = client.get('bytes_received', 0)
                    metrics.append(f'openvpn_client_bytes_received_total{{client="{client_name}"}} {bytes_received}')
                
                metrics.append("")
            
        except Exception as e:
            current_app.logger.error(f"Error adding OpenVPN metrics: {str(e)}")
    
    def _add_client_metrics(self, metrics):
        """Add VPN client metrics from database."""
        try:
            # Total clients
            total_clients = VPNClient.query.count()
            active_clients = VPNClient.query.filter_by(is_active=True, is_revoked=False).count()
            revoked_clients = VPNClient.query.filter_by(is_revoked=True).count()
            
            metrics.extend([
                "# HELP openvpn_clients_total Total number of VPN clients",
                "# TYPE openvpn_clients_total gauge",
                f"openvpn_clients_total {total_clients}",
                "",
                "# HELP openvpn_clients_active Number of active VPN clients",
                "# TYPE openvpn_clients_active gauge",
                f"openvpn_clients_active {active_clients}",
                "",
                "# HELP openvpn_clients_revoked Number of revoked VPN clients",
                "# TYPE openvpn_clients_revoked gauge",
                f"openvpn_clients_revoked {revoked_clients}",
                ""
            ])
            
            # Certificate expiration metrics
            from datetime import datetime, timedelta
            thirty_days_from_now = datetime.utcnow() + timedelta(days=30)
            expiring_clients = VPNClient.query.filter(
                VPNClient.cert_expires_at <= thirty_days_from_now,
                VPNClient.is_revoked == False
            ).count()
            
            metrics.extend([
                "# HELP openvpn_certificates_expiring_soon Certificates expiring within 30 days",
                "# TYPE openvpn_certificates_expiring_soon gauge",
                f"openvpn_certificates_expiring_soon {expiring_clients}",
                ""
            ])
            
            # Total bandwidth usage
            from sqlalchemy import func
            from app import db
            
            total_sent = db.session.query(
                func.sum(VPNClient.total_bytes_sent)
            ).scalar() or 0
            
            total_received = db.session.query(
                func.sum(VPNClient.total_bytes_received)
            ).scalar() or 0
            
            metrics.extend([
                "# HELP openvpn_total_bytes_sent_total Total bytes sent by all clients",
                "# TYPE openvpn_total_bytes_sent_total counter",
                f"openvpn_total_bytes_sent_total {total_sent}",
                "",
                "# HELP openvpn_total_bytes_received_total Total bytes received by all clients",
                "# TYPE openvpn_total_bytes_received_total counter",
                f"openvpn_total_bytes_received_total {total_received}",
                ""
            ])
            
        except Exception as e:
            current_app.logger.error(f"Error adding client metrics: {str(e)}")
    
    def _add_application_metrics(self, metrics):
        """Add application-specific metrics."""
        try:
            # Application uptime
            boot_time = psutil.boot_time()
            uptime_seconds = datetime.utcnow().timestamp() - boot_time
            
            metrics.extend([
                "# HELP openvpn_manager_uptime_seconds Application uptime in seconds",
                "# TYPE openvpn_manager_uptime_seconds counter",
                f"openvpn_manager_uptime_seconds {int(uptime_seconds)}",
                ""
            ])
            
            # Process metrics
            process = psutil.Process()
            process_memory = process.memory_info()
            process_cpu = process.cpu_percent()
            
            metrics.extend([
                "# HELP openvpn_manager_memory_usage_bytes Application memory usage",
                "# TYPE openvpn_manager_memory_usage_bytes gauge",
                f"openvpn_manager_memory_usage_bytes {process_memory.rss}",
                "",
                "# HELP openvpn_manager_cpu_usage_percent Application CPU usage",
                "# TYPE openvpn_manager_cpu_usage_percent gauge",
                f"openvpn_manager_cpu_usage_percent {process_cpu}",
                ""
            ])
            
            # Database connection pool metrics (if applicable)
            try:
                from app import db
                if hasattr(db.engine.pool, 'size'):
                    pool_size = db.engine.pool.size()
                    checked_out = db.engine.pool.checkedout()
                    
                    metrics.extend([
                        "# HELP openvpn_manager_db_pool_size Database connection pool size",
                        "# TYPE openvpn_manager_db_pool_size gauge",
                        f"openvpn_manager_db_pool_size {pool_size}",
                        "",
                        "# HELP openvpn_manager_db_pool_checked_out Database connections checked out",
                        "# TYPE openvpn_manager_db_pool_checked_out gauge",
                        f"openvpn_manager_db_pool_checked_out {checked_out}",
                        ""
                    ])
            except Exception:
                pass
            
        except Exception as e:
            current_app.logger.error(f"Error adding application metrics: {str(e)}")
