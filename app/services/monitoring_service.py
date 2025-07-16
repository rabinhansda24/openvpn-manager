"""
Monitoring service for system and application monitoring.
"""

import psutil
import os
import re
from datetime import datetime, timedelta
from flask import current_app
import redis
import json
import subprocess

class MonitoringService:
    """Service class for system monitoring operations."""
    
    def __init__(self):
        self.redis_client = self._get_redis_client()
        self.openvpn_log = current_app.config.get('OPENVPN_LOG_PATH', '/var/log/openvpn/openvpn.log')
        self.system_log = '/var/log/syslog'  # Linux system log
        
    def get_realtime_metrics(self):
        """Get real-time system metrics."""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            # Disk metrics
            disk_usage = psutil.disk_usage('/')
            disk_io = psutil.disk_io_counters()
            
            # Network metrics
            network_io = psutil.net_io_counters()
            
            # Load average (Unix only)
            try:
                load_avg = os.getloadavg()
            except (OSError, AttributeError):
                load_avg = [0, 0, 0]
            
            # Process count
            process_count = len(psutil.pids())
            
            # Boot time
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.utcnow() - boot_time
            
            metrics = {
                'timestamp': datetime.utcnow().isoformat(),
                'cpu': {
                    'percent': cpu_percent,
                    'count': cpu_count,
                    'frequency': {
                        'current': cpu_freq.current if cpu_freq else 0,
                        'min': cpu_freq.min if cpu_freq else 0,
                        'max': cpu_freq.max if cpu_freq else 0
                    },
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
                    'free': memory.free,
                    'active': getattr(memory, 'active', 0),
                    'inactive': getattr(memory, 'inactive', 0),
                    'buffers': getattr(memory, 'buffers', 0),
                    'cached': getattr(memory, 'cached', 0)
                },
                'swap': {
                    'total': swap.total,
                    'used': swap.used,
                    'free': swap.free,
                    'percent': swap.percent
                },
                'disk': {
                    'total': disk_usage.total,
                    'used': disk_usage.used,
                    'free': disk_usage.free,
                    'percent': (disk_usage.used / disk_usage.total) * 100 if disk_usage.total > 0 else 0,
                    'io': {
                        'read_count': disk_io.read_count if disk_io else 0,
                        'write_count': disk_io.write_count if disk_io else 0,
                        'read_bytes': disk_io.read_bytes if disk_io else 0,
                        'write_bytes': disk_io.write_bytes if disk_io else 0,
                        'read_time': disk_io.read_time if disk_io else 0,
                        'write_time': disk_io.write_time if disk_io else 0
                    }
                },
                'network': {
                    'bytes_sent': network_io.bytes_sent,
                    'bytes_recv': network_io.bytes_recv,
                    'packets_sent': network_io.packets_sent,
                    'packets_recv': network_io.packets_recv,
                    'errin': network_io.errin,
                    'errout': network_io.errout,
                    'dropin': network_io.dropin,
                    'dropout': network_io.dropout
                },
                'system': {
                    'process_count': process_count,
                    'boot_time': boot_time.isoformat(),
                    'uptime_seconds': uptime.total_seconds(),
                    'uptime_formatted': str(uptime).split('.')[0]
                }
            }
            
            # Store metrics in Redis for historical tracking
            self._store_metrics(metrics)
            
            return metrics
            
        except Exception as e:
            current_app.logger.error(f"Error getting realtime metrics: {str(e)}")
            return {'error': str(e)}
    
    def get_historical_metrics(self, hours=24):
        """Get historical system metrics."""
        try:
            if not self.redis_client:
                return {'error': 'Redis not available for historical data'}
            
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=hours)
            
            # Get stored metrics from Redis
            metrics_list = []
            
            # Get keys for the time range
            pattern = 'metrics:*'
            keys = self.redis_client.keys(pattern)
            
            for key in keys:
                try:
                    key_timestamp = datetime.fromisoformat(key.decode().split(':', 1)[1])
                    if start_time <= key_timestamp <= end_time:
                        data = self.redis_client.get(key)
                        if data:
                            metrics_list.append(json.loads(data))
                except Exception:
                    continue
            
            # Sort by timestamp
            metrics_list.sort(key=lambda x: x.get('timestamp', ''))
            
            # Calculate averages and trends
            summary = self._calculate_metrics_summary(metrics_list)
            
            return {
                'metrics': metrics_list,
                'summary': summary,
                'period': {
                    'start': start_time.isoformat(),
                    'end': end_time.isoformat(),
                    'hours': hours
                },
                'count': len(metrics_list)
            }
            
        except Exception as e:
            current_app.logger.error(f"Error getting historical metrics: {str(e)}")
            return {'error': str(e)}
    
    def get_openvpn_logs(self, lines=100, search=''):
        """Get OpenVPN logs with optional search."""
        try:
            if not os.path.exists(self.openvpn_log):
                return []
            
            # Read log file
            with open(self.openvpn_log, 'r') as f:
                log_lines = f.readlines()
            
            # Get last N lines
            log_lines = log_lines[-lines:]
            
            # Parse and filter logs
            parsed_logs = []
            for line in log_lines:
                line = line.strip()
                if not line:
                    continue
                
                # Apply search filter
                if search and search.lower() not in line.lower():
                    continue
                
                # Parse log entry
                parsed_entry = self._parse_log_entry(line)
                if parsed_entry:
                    parsed_logs.append(parsed_entry)
            
            return parsed_logs
            
        except Exception as e:
            current_app.logger.error(f"Error reading OpenVPN logs: {str(e)}")
            return []
    
    def get_system_logs(self, lines=100, level='all', search=''):
        """Get system logs with filtering."""
        try:
            # Try different log locations
            log_files = ['/var/log/syslog', '/var/log/messages', '/var/log/system.log']
            log_file = None
            
            for file_path in log_files:
                if os.path.exists(file_path):
                    log_file = file_path
                    break
            
            if not log_file:
                return []
            
            # Read log file
            with open(log_file, 'r') as f:
                log_lines = f.readlines()
            
            # Get last N lines
            log_lines = log_lines[-lines:]
            
            # Parse and filter logs
            parsed_logs = []
            for line in log_lines:
                line = line.strip()
                if not line:
                    continue
                
                # Apply search filter
                if search and search.lower() not in line.lower():
                    continue
                
                # Apply level filter
                if level != 'all':
                    if level.upper() not in line.upper():
                        continue
                
                # Parse log entry
                parsed_entry = self._parse_system_log_entry(line)
                if parsed_entry:
                    parsed_logs.append(parsed_entry)
            
            return parsed_logs
            
        except Exception as e:
            current_app.logger.error(f"Error reading system logs: {str(e)}")
            return []
    
    def get_system_alerts(self):
        """Generate system alerts based on current metrics."""
        try:
            alerts = []
            
            # Get current metrics
            metrics = self.get_realtime_metrics()
            
            if 'error' in metrics:
                return []
            
            # CPU alerts
            if metrics['cpu']['percent'] > 90:
                alerts.append({
                    'type': 'critical',
                    'category': 'cpu',
                    'message': f"High CPU usage: {metrics['cpu']['percent']:.1f}%",
                    'value': metrics['cpu']['percent'],
                    'threshold': 90
                })
            elif metrics['cpu']['percent'] > 80:
                alerts.append({
                    'type': 'warning',
                    'category': 'cpu',
                    'message': f"Elevated CPU usage: {metrics['cpu']['percent']:.1f}%",
                    'value': metrics['cpu']['percent'],
                    'threshold': 80
                })
            
            # Memory alerts
            if metrics['memory']['percent'] > 95:
                alerts.append({
                    'type': 'critical',
                    'category': 'memory',
                    'message': f"Critical memory usage: {metrics['memory']['percent']:.1f}%",
                    'value': metrics['memory']['percent'],
                    'threshold': 95
                })
            elif metrics['memory']['percent'] > 85:
                alerts.append({
                    'type': 'warning',
                    'category': 'memory',
                    'message': f"High memory usage: {metrics['memory']['percent']:.1f}%",
                    'value': metrics['memory']['percent'],
                    'threshold': 85
                })
            
            # Disk alerts
            if metrics['disk']['percent'] > 95:
                alerts.append({
                    'type': 'critical',
                    'category': 'disk',
                    'message': f"Critical disk usage: {metrics['disk']['percent']:.1f}%",
                    'value': metrics['disk']['percent'],
                    'threshold': 95
                })
            elif metrics['disk']['percent'] > 85:
                alerts.append({
                    'type': 'warning',
                    'category': 'disk',
                    'message': f"High disk usage: {metrics['disk']['percent']:.1f}%",
                    'value': metrics['disk']['percent'],
                    'threshold': 85
                })
            
            # Load average alerts (Unix only)
            load_1min = metrics['cpu']['load_avg']['1min']
            cpu_count = metrics['cpu']['count']
            
            if load_1min > cpu_count * 2:
                alerts.append({
                    'type': 'critical',
                    'category': 'load',
                    'message': f"Very high system load: {load_1min:.2f} (CPUs: {cpu_count})",
                    'value': load_1min,
                    'threshold': cpu_count * 2
                })
            elif load_1min > cpu_count * 1.5:
                alerts.append({
                    'type': 'warning',
                    'category': 'load',
                    'message': f"High system load: {load_1min:.2f} (CPUs: {cpu_count})",
                    'value': load_1min,
                    'threshold': cpu_count * 1.5
                })
            
            # Add timestamps to alerts
            for alert in alerts:
                alert['timestamp'] = datetime.utcnow().isoformat()
            
            return alerts
            
        except Exception as e:
            current_app.logger.error(f"Error generating system alerts: {str(e)}")
            return []
    
    def _get_redis_client(self):
        """Get Redis client for storing metrics."""
        try:
            redis_url = current_app.config.get('REDIS_URL')
            if redis_url:
                return redis.from_url(redis_url)
            return None
        except Exception:
            return None
    
    def _store_metrics(self, metrics):
        """Store metrics in Redis for historical tracking."""
        try:
            if not self.redis_client:
                return
            
            timestamp = metrics['timestamp']
            key = f"metrics:{timestamp}"
            
            # Store metrics with 7 day expiration
            self.redis_client.setex(
                key,
                timedelta(days=7),
                json.dumps(metrics)
            )
            
            # Keep only essential data to save memory
            essential_metrics = {
                'timestamp': timestamp,
                'cpu_percent': metrics['cpu']['percent'],
                'memory_percent': metrics['memory']['percent'],
                'disk_percent': metrics['disk']['percent'],
                'load_avg_1min': metrics['cpu']['load_avg']['1min']
            }
            
            # Store in a time series list for easier querying
            self.redis_client.lpush(
                'metrics_timeseries',
                json.dumps(essential_metrics)
            )
            
            # Keep only last 1000 entries
            self.redis_client.ltrim('metrics_timeseries', 0, 999)
            
        except Exception as e:
            current_app.logger.error(f"Error storing metrics: {str(e)}")
    
    def _calculate_metrics_summary(self, metrics_list):
        """Calculate summary statistics from metrics list."""
        try:
            if not metrics_list:
                return {}
            
            cpu_values = [m['cpu']['percent'] for m in metrics_list if 'cpu' in m]
            memory_values = [m['memory']['percent'] for m in metrics_list if 'memory' in m]
            disk_values = [m['disk']['percent'] for m in metrics_list if 'disk' in m]
            
            summary = {}
            
            if cpu_values:
                summary['cpu'] = {
                    'avg': sum(cpu_values) / len(cpu_values),
                    'min': min(cpu_values),
                    'max': max(cpu_values)
                }
            
            if memory_values:
                summary['memory'] = {
                    'avg': sum(memory_values) / len(memory_values),
                    'min': min(memory_values),
                    'max': max(memory_values)
                }
            
            if disk_values:
                summary['disk'] = {
                    'avg': sum(disk_values) / len(disk_values),
                    'min': min(disk_values),
                    'max': max(disk_values)
                }
            
            return summary
            
        except Exception:
            return {}
    
    def _parse_log_entry(self, line):
        """Parse OpenVPN log entry."""
        try:
            # OpenVPN log format varies, try to extract common fields
            entry = {
                'raw_message': line,
                'timestamp': None,
                'level': 'INFO',
                'message': line
            }
            
            # Try to extract timestamp (common formats)
            timestamp_patterns = [
                r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',  # Jul 16 14:30:15
                r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',  # 2024-07-16 14:30:15
            ]
            
            for pattern in timestamp_patterns:
                match = re.match(pattern, line)
                if match:
                    entry['timestamp'] = match.group(1)
                    entry['message'] = line[len(match.group(1)):].strip()
                    break
            
            # Extract log level
            if 'ERROR' in line.upper():
                entry['level'] = 'ERROR'
            elif 'WARN' in line.upper():
                entry['level'] = 'WARNING'
            elif 'DEBUG' in line.upper():
                entry['level'] = 'DEBUG'
            
            return entry
            
        except Exception:
            return {'raw_message': line, 'message': line, 'level': 'INFO'}
    
    def _parse_system_log_entry(self, line):
        """Parse system log entry."""
        try:
            # System log format: timestamp hostname process[pid]: message
            entry = {
                'raw_message': line,
                'timestamp': None,
                'hostname': None,
                'process': None,
                'pid': None,
                'level': 'INFO',
                'message': line
            }
            
            # Try to parse syslog format
            syslog_pattern = r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[]+)(?:\[(\d+)\])?:\s*(.*)$'
            match = re.match(syslog_pattern, line)
            
            if match:
                entry['timestamp'] = match.group(1)
                entry['hostname'] = match.group(2)
                entry['process'] = match.group(3)
                entry['pid'] = match.group(4)
                entry['message'] = match.group(5)
            
            # Extract log level from message
            message = entry['message'].upper()
            if any(word in message for word in ['ERROR', 'FAIL', 'CRITICAL']):
                entry['level'] = 'ERROR'
            elif any(word in message for word in ['WARN', 'WARNING']):
                entry['level'] = 'WARNING'
            elif any(word in message for word in ['DEBUG']):
                entry['level'] = 'DEBUG'
            
            return entry
            
        except Exception:
            return {'raw_message': line, 'message': line, 'level': 'INFO'}
