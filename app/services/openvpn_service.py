"""
OpenVPN service for managing OpenVPN server operations.
"""

import subprocess
import os
import re
import psutil
from datetime import datetime, timedelta
from flask import current_app
import tempfile
import shutil

class OpenVPNService:
    """Service class for OpenVPN operations."""
    
    def __init__(self):
        self.config_path = current_app.config.get('OPENVPN_CONFIG_PATH', '/etc/openvpn')
        self.status_log = current_app.config.get('OPENVPN_STATUS_LOG', '/var/log/openvpn/openvpn-status.log')
        self.server_log = current_app.config.get('OPENVPN_LOG_PATH', '/var/log/openvpn/openvpn.log')
        self.scripts_path = os.path.join(os.path.dirname(__file__), '..', 'scripts')
    
    def get_server_status(self):
        """Get OpenVPN server status."""
        try:
            # Check if OpenVPN process is running
            is_running = self._is_process_running()
            
            if not is_running:
                return {
                    'running': False,
                    'status': 'stopped',
                    'uptime': None,
                    'connected_clients': 0
                }
            
            # Get uptime
            uptime = self._get_process_uptime()
            
            # Count connected clients
            connected_clients = len(self.get_connected_clients())
            
            return {
                'running': True,
                'status': 'running',
                'uptime': uptime,
                'connected_clients': connected_clients,
                'last_updated': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            current_app.logger.error(f"Error getting server status: {str(e)}")
            return {
                'running': False,
                'status': 'error',
                'error': str(e)
            }
    
    def get_detailed_status(self):
        """Get detailed OpenVPN server status."""
        try:
            basic_status = self.get_server_status()
            
            if not basic_status['running']:
                return basic_status
            
            # Get configuration info
            config_info = self._get_config_info()
            
            # Get connection statistics
            stats = self._get_connection_stats()
            
            return {
                **basic_status,
                'config': config_info,
                'statistics': stats,
                'pid': self._get_process_pid(),
                'config_file': os.path.join(self.config_path, 'server.conf')
            }
            
        except Exception as e:
            current_app.logger.error(f"Error getting detailed status: {str(e)}")
            return {'running': False, 'status': 'error', 'error': str(e)}
    
    def get_connected_clients(self):
        """Parse status log to get connected clients."""
        try:
            if not os.path.exists(self.status_log):
                return []
            
            connected_clients = []
            
            with open(self.status_log, 'r') as f:
                content = f.read()
            
            # Parse the status file
            # Format: CLIENT_LIST,client_name,real_address,virtual_address,bytes_received,bytes_sent,connected_since
            lines = content.split('\n')
            
            for line in lines:
                if line.startswith('CLIENT_LIST'):
                    parts = line.split(',')
                    if len(parts) >= 7:
                        try:
                            client_info = {
                                'name': parts[1],
                                'real_address': parts[2],
                                'virtual_address': parts[3],
                                'bytes_received': int(parts[4]) if parts[4].isdigit() else 0,
                                'bytes_sent': int(parts[5]) if parts[5].isdigit() else 0,
                                'connected_since': self._parse_openvpn_time(parts[6]),
                                'connection_duration': self._calculate_duration(parts[6])
                            }
                            connected_clients.append(client_info)
                        except (ValueError, IndexError):
                            continue
            
            return connected_clients
            
        except Exception as e:
            current_app.logger.error(f"Error parsing connected clients: {str(e)}")
            return []
    
    def get_server_config(self):
        """Get OpenVPN server configuration."""
        try:
            config_file = os.path.join(self.config_path, 'server.conf')
            
            if not os.path.exists(config_file):
                return {'error': 'Configuration file not found'}
            
            with open(config_file, 'r') as f:
                config_content = f.read()
            
            # Parse configuration into structured format
            config_lines = config_content.split('\n')
            parsed_config = {}
            
            for line in config_lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    if ' ' in line:
                        key, value = line.split(' ', 1)
                        parsed_config[key] = value
                    else:
                        parsed_config[line] = True
            
            return {
                'raw_config': config_content,
                'parsed_config': parsed_config,
                'file_path': config_file,
                'last_modified': os.path.getmtime(config_file)
            }
            
        except Exception as e:
            current_app.logger.error(f"Error reading server config: {str(e)}")
            return {'error': str(e)}
    
    def update_server_config(self, config_content):
        """Update OpenVPN server configuration."""
        try:
            config_file = os.path.join(self.config_path, 'server.conf')
            backup_file = f"{config_file}.backup.{int(datetime.utcnow().timestamp())}"
            
            # Create backup
            if os.path.exists(config_file):
                shutil.copy2(config_file, backup_file)
            
            # Validate configuration before writing
            validation_result = self._validate_config(config_content)
            if not validation_result['valid']:
                return {
                    'success': False,
                    'error': f"Configuration validation failed: {validation_result['error']}"
                }
            
            # Write new configuration
            with open(config_file, 'w') as f:
                f.write(config_content)
            
            return {
                'success': True,
                'backup_file': backup_file,
                'restart_required': True
            }
            
        except Exception as e:
            current_app.logger.error(f"Error updating server config: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def restart_service(self):
        """Restart OpenVPN service."""
        try:
            # First, try to stop the service gracefully
            stop_result = self._execute_script('stop-openvpn.sh')
            
            # Wait a moment
            import time
            time.sleep(2)
            
            # Start the service
            start_result = self._execute_script('start-openvpn.sh')
            
            # Wait for service to start
            time.sleep(3)
            
            # Verify it's running
            is_running = self._is_process_running()
            
            return {
                'success': is_running,
                'stop_result': stop_result,
                'start_result': start_result,
                'running': is_running
            }
            
        except Exception as e:
            current_app.logger.error(f"Error restarting OpenVPN service: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def generate_client_config(self, client_name):
        """Generate client configuration file."""
        try:
            script_path = os.path.join(self.scripts_path, 'generate-client-config.sh')
            
            result = subprocess.run(
                [script_path, client_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Read the generated config
                config_file = os.path.join(self.config_path, 'clients', f"{client_name}.ovpn")
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        return f.read()
                else:
                    return None
            else:
                current_app.logger.error(f"Error generating client config: {result.stderr}")
                return None
                
        except Exception as e:
            current_app.logger.error(f"Error generating client config for {client_name}: {str(e)}")
            return None
    
    def _is_process_running(self):
        """Check if OpenVPN process is running."""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                if 'openvpn' in proc.info['name'].lower():
                    return True
            return False
        except Exception:
            return False
    
    def _get_process_pid(self):
        """Get OpenVPN process PID."""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if 'openvpn' in proc.info['name'].lower():
                    return proc.info['pid']
            return None
        except Exception:
            return None
    
    def _get_process_uptime(self):
        """Get OpenVPN process uptime."""
        try:
            pid = self._get_process_pid()
            if pid:
                proc = psutil.Process(pid)
                create_time = datetime.fromtimestamp(proc.create_time())
                uptime = datetime.utcnow() - create_time
                return str(uptime).split('.')[0]  # Remove microseconds
            return None
        except Exception:
            return None
    
    def _get_config_info(self):
        """Get basic configuration information."""
        try:
            config = self.get_server_config()
            if 'error' in config:
                return {'error': config['error']}
            
            parsed = config.get('parsed_config', {})
            
            return {
                'port': parsed.get('port', '1194'),
                'proto': parsed.get('proto', 'udp'),
                'server_network': parsed.get('server', 'Unknown'),
                'ca_cert': parsed.get('ca', 'ca.crt'),
                'server_cert': parsed.get('cert', 'server.crt'),
                'server_key': parsed.get('key', 'server.key'),
                'dh_params': parsed.get('dh', 'dh.pem')
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _get_connection_stats(self):
        """Get connection statistics from log."""
        try:
            if not os.path.exists(self.status_log):
                return {}
            
            with open(self.status_log, 'r') as f:
                content = f.read()
            
            stats = {}
            lines = content.split('\n')
            
            for line in lines:
                if line.startswith('GLOBAL_STATS'):
                    # Parse global stats if available
                    continue
                elif line.startswith('ROUTING_TABLE'):
                    # Parse routing table if needed
                    continue
            
            return stats
            
        except Exception:
            return {}
    
    def _parse_openvpn_time(self, time_str):
        """Parse OpenVPN time format."""
        try:
            # OpenVPN uses different time formats
            # Try common formats
            formats = [
                '%a %b %d %H:%M:%S %Y',
                '%Y-%m-%d %H:%M:%S',
                '%m/%d/%Y %H:%M:%S'
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(time_str.strip(), fmt).isoformat()
                except ValueError:
                    continue
            
            # If all formats fail, return the original string
            return time_str
            
        except Exception:
            return time_str
    
    def _calculate_duration(self, start_time_str):
        """Calculate connection duration."""
        try:
            start_time = datetime.fromisoformat(self._parse_openvpn_time(start_time_str))
            duration = datetime.utcnow() - start_time
            return str(duration).split('.')[0]  # Remove microseconds
        except Exception:
            return 'Unknown'
    
    def _validate_config(self, config_content):
        """Validate OpenVPN configuration."""
        try:
            # Basic validation - check for required directives
            required_directives = ['port', 'proto', 'dev', 'ca', 'cert', 'key']
            
            lines = config_content.split('\n')
            found_directives = set()
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    if ' ' in line:
                        directive = line.split(' ')[0]
                        found_directives.add(directive)
            
            missing_directives = set(required_directives) - found_directives
            
            if missing_directives:
                return {
                    'valid': False,
                    'error': f"Missing required directives: {', '.join(missing_directives)}"
                }
            
            # Additional validation can be added here
            
            return {'valid': True}
            
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    def _execute_script(self, script_name, args=None):
        """Execute a shell script safely."""
        try:
            script_path = os.path.join(self.scripts_path, script_name)
            
            if not os.path.exists(script_path):
                return {'success': False, 'error': f"Script {script_name} not found"}
            
            cmd = [script_path]
            if args:
                cmd.extend(args)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Script execution timed out'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
