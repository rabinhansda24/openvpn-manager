"""
OpenVPN service for managing OpenVPN server operations in Docker environment.
"""

import subprocess
import os
import re
import socket
import psutil
from datetime import datetime, timedelta
from flask import current_app
import tempfile
import shutil
import time

class OpenVPNService:
    """Service class for OpenVPN operations in containerized environment."""
    
    def __init__(self):
        self.config_path = current_app.config.get('OPENVPN_CONFIG_PATH', '/etc/openvpn')
        self.status_log = current_app.config.get('OPENVPN_STATUS_LOG', '/var/log/openvpn/openvpn-status.log')
        self.server_log = current_app.config.get('OPENVPN_LOG_PATH', '/var/log/openvpn/openvpn.log')
        self.scripts_path = os.path.join(os.path.dirname(__file__), '..', 'scripts')
        
        # Docker environment settings
        self.openvpn_host = 'openvpn'  # Container name
        self.management_port = 7505    # OpenVPN management interface port
        self.openvpn_container = 'openvpn'  # Container name for docker commands
    
    def get_server_status(self):
        """Get OpenVPN server status via management interface."""
        try:
            # Check if OpenVPN management interface is accessible
            is_running = self._is_management_accessible()
            
            if not is_running:
                return {
                    'running': False,
                    'status': 'stopped',
                    'uptime': None,
                    'connected_clients': 0
                }
            
            # Get uptime from management interface
            uptime = self._get_uptime_via_management()
            
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
            
            # Get version info
            version_info = self._get_version_info()
            
            return {
                **basic_status,
                'config': config_info,
                'statistics': stats,
                'version': version_info,
                'management_interface': f"{self.openvpn_host}:{self.management_port}",
                'config_file': '/etc/openvpn/server.conf'
            }
            
        except Exception as e:
            current_app.logger.error(f"Error getting detailed status: {str(e)}")
            return {'running': False, 'status': 'error', 'error': str(e)}
    
    def get_connected_clients(self):
        """Get connected clients via management interface."""
        try:
            # Try to get clients from management interface first
            clients = self._get_clients_via_management()
            if clients:
                return clients
            
            # Fallback to status log parsing if management interface fails
            return self._parse_status_log()
            
        except Exception as e:
            current_app.logger.error(f"Error getting connected clients: {str(e)}")
            return []
    
    def get_server_config(self):
        """Get OpenVPN server configuration from Docker volume."""
        try:
            # Use docker exec to read config from OpenVPN container
            result = subprocess.run(
                ['docker', 'exec', self.openvpn_container, 'cat', '/etc/openvpn/server.conf'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                config_content = result.stdout
                
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
                    'file_path': '/etc/openvpn/server.conf',
                    'container': self.openvpn_container
                }
            else:
                return {'error': f'Failed to read config: {result.stderr}'}
            
        except Exception as e:
            current_app.logger.error(f"Error reading server config: {str(e)}")
            return {'error': str(e)}
    
    def update_server_config(self, config_content):
        """Update OpenVPN server configuration in Docker container."""
        try:
            # Create backup first
            timestamp = int(datetime.utcnow().timestamp())
            
            backup_result = subprocess.run(
                ['docker', 'exec', self.openvpn_container, 'cp', 
                 '/etc/openvpn/server.conf', f'/etc/openvpn/server.conf.backup.{timestamp}'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Validate configuration before writing
            validation_result = self._validate_config(config_content)
            if not validation_result['valid']:
                return {
                    'success': False,
                    'error': f"Configuration validation failed: {validation_result['error']}"
                }
            
            # Write new configuration via docker exec
            write_result = subprocess.run(
                ['docker', 'exec', '-i', self.openvpn_container, 'tee', '/etc/openvpn/server.conf'],
                input=config_content,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if write_result.returncode == 0:
                return {
                    'success': True,
                    'backup_file': f'server.conf.backup.{timestamp}',
                    'restart_required': True
                }
            else:
                return {'success': False, 'error': f'Failed to write config: {write_result.stderr}'}
            
        except Exception as e:
            current_app.logger.error(f"Error updating server config: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def restart_service(self):
        """Restart OpenVPN service in Docker container."""
        try:
            # Get the container ID
            result = subprocess.run(
                ['docker', 'restart', self.openvpn_container],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Wait for service to start
                time.sleep(5)
                
                # Verify it's running
                is_running = self._is_management_accessible()
                
                return {
                    'success': is_running,
                    'message': 'Container restarted successfully',
                    'running': is_running
                }
            else:
                return {
                    'success': False,
                    'error': f'Failed to restart container: {result.stderr}'
                }
            
        except Exception as e:
            current_app.logger.error(f"Error restarting OpenVPN service: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def generate_client_config(self, client_name):
        """Generate client configuration file via Docker container."""
        try:
            # Execute client generation script in OpenVPN container
            result = subprocess.run(
                ['docker', 'exec', self.openvpn_container, 
                 '/etc/openvpn/easy-rsa/easyrsa', '--batch', 'build-client-full', client_name, 'nopass'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                # Generate the .ovpn file
                ovpn_result = subprocess.run(
                    ['docker', 'exec', self.openvpn_container, 
                     'sh', '-c', f'cat /etc/openvpn/client-template.ovpn | sed "s/CLIENT_NAME/{client_name}/g"'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if ovpn_result.returncode == 0:
                    return ovpn_result.stdout
                else:
                    current_app.logger.error(f"Error generating .ovpn file: {ovpn_result.stderr}")
                    return None
            else:
                current_app.logger.error(f"Error generating client certificate: {result.stderr}")
                return None
                
        except Exception as e:
            current_app.logger.error(f"Error generating client config for {client_name}: {str(e)}")
            return None
    
    def _is_management_accessible(self):
        """Check if OpenVPN management interface is accessible."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)  # 5 second timeout
            
            # Try to connect to the management interface
            result = sock.connect_ex((self.openvpn_host, self.management_port))
            sock.close()
            
            return result == 0
            
        except Exception as e:
            current_app.logger.debug(f"Management interface not accessible: {str(e)}")
            return False
    
    def _get_uptime_via_management(self):
        """Get uptime via management interface."""
        try:
            response = self._send_management_command('state')
            if response:
                # Parse response for uptime information
                lines = response.split('\n')
                for line in lines:
                    if 'CONNECTED,SUCCESS' in line:
                        # Extract timestamp and calculate uptime
                        parts = line.split(',')
                        if len(parts) >= 2:
                            try:
                                timestamp = int(parts[0])
                                start_time = datetime.fromtimestamp(timestamp)
                                uptime = datetime.utcnow() - start_time
                                return str(uptime).split('.')[0]  # Remove microseconds
                            except (ValueError, IndexError):
                                pass
            
            # Fallback: try to get uptime from container
            return self._get_container_uptime()
            
        except Exception:
            return self._get_container_uptime()
    
    def _get_container_uptime(self):
        """Get container uptime as fallback."""
        try:
            result = subprocess.run(
                ['docker', 'inspect', '--format={{.State.StartedAt}}', self.openvpn_container],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                start_time_str = result.stdout.strip()
                # Parse the timestamp (format: 2025-07-20T18:09:51.123456789Z)
                start_time = datetime.fromisoformat(start_time_str.replace('Z', '+00:00'))
                uptime = datetime.utcnow() - start_time.replace(tzinfo=None)
                return str(uptime).split('.')[0]  # Remove microseconds
            
        except Exception:
            pass
        
        return 'Unknown'
    
    def _get_clients_via_management(self):
        """Get connected clients via management interface."""
        try:
            response = self._send_management_command('status')
            if not response:
                return []
            
            connected_clients = []
            lines = response.split('\n')
            
            for line in lines:
                if line.startswith('CLIENT_LIST'):
                    parts = line.split('\t')  # Management interface uses tabs
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
            current_app.logger.error(f"Error getting clients via management: {str(e)}")
            return []
    
    def _parse_status_log(self):
        """Fallback: Parse status log to get connected clients."""
        try:
            # Read status log from container
            result = subprocess.run(
                ['docker', 'exec', self.openvpn_container, 'cat', '/var/log/openvpn/openvpn-status.log'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                return []
            
            content = result.stdout
            connected_clients = []
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
            current_app.logger.error(f"Error parsing status log: {str(e)}")
            return []
    
    def _send_management_command(self, command):
        """Send command to OpenVPN management interface."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            # Connect to management interface
            sock.connect((self.openvpn_host, self.management_port))
            
            # Send command
            sock.send(f"{command}\n".encode())
            
            # Read response
            response = ""
            while True:
                data = sock.recv(4096).decode()
                if not data:
                    break
                response += data
                if "END" in response or "ERROR" in response:
                    break
            
            sock.close()
            return response
            
        except Exception as e:
            current_app.logger.error(f"Error sending management command '{command}': {str(e)}")
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
        """Get connection statistics."""
        try:
            response = self._send_management_command('load-stats')
            if response:
                # Parse load statistics
                stats = {}
                lines = response.split('\n')
                for line in lines:
                    if '=' in line:
                        key, value = line.split('=', 1)
                        stats[key.strip()] = value.strip()
                return stats
            
            return {}
            
        except Exception:
            return {}
    
    def _get_version_info(self):
        """Get OpenVPN version information."""
        try:
            response = self._send_management_command('version')
            if response:
                lines = response.split('\n')
                for line in lines:
                    if 'OpenVPN' in line:
                        return line.strip()
            
            # Fallback: get version from container
            result = subprocess.run(
                ['docker', 'exec', self.openvpn_container, 'openvpn', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                if lines:
                    return lines[0].strip()
            
            return 'Unknown'
            
        except Exception:
            return 'Unknown'
    
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
            
            return {'valid': True}
            
        except Exception as e:
            return {'valid': False, 'error': str(e)}
