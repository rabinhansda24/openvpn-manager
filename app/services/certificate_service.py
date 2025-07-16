"""
Certificate service for managing OpenVPN certificates and PKI operations.
"""

import subprocess
import os
import shutil
from datetime import datetime, timedelta
from flask import current_app
import tempfile
import re

class CertificateService:
    """Service class for certificate operations."""
    
    def __init__(self):
        self.config_path = current_app.config.get('OPENVPN_CONFIG_PATH', '/etc/openvpn')
        self.easy_rsa_path = os.path.join(self.config_path, 'easy-rsa')
        self.pki_path = os.path.join(self.easy_rsa_path, 'pki')
        self.scripts_path = os.path.join(os.path.dirname(__file__), '..', 'scripts')
    
    def initialize_pki(self):
        """Initialize PKI infrastructure."""
        try:
            # Check if PKI already exists
            if os.path.exists(self.pki_path):
                return {
                    'success': True,
                    'message': 'PKI already initialized',
                    'pki_path': self.pki_path
                }
            
            # Execute PKI initialization script
            result = self._execute_script('init-pki.sh')
            
            if result['success']:
                return {
                    'success': True,
                    'message': 'PKI initialized successfully',
                    'pki_path': self.pki_path
                }
            else:
                return {
                    'success': False,
                    'error': f"PKI initialization failed: {result['error']}"
                }
                
        except Exception as e:
            current_app.logger.error(f"Error initializing PKI: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def create_ca_certificate(self, ca_name='OpenVPN-CA'):
        """Create Certificate Authority certificate."""
        try:
            ca_cert_path = os.path.join(self.pki_path, 'ca.crt')
            
            # Check if CA already exists
            if os.path.exists(ca_cert_path):
                return {
                    'success': True,
                    'message': 'CA certificate already exists',
                    'ca_cert_path': ca_cert_path
                }
            
            # Execute CA creation script
            result = self._execute_script('create-ca.sh', [ca_name])
            
            if result['success'] and os.path.exists(ca_cert_path):
                return {
                    'success': True,
                    'message': 'CA certificate created successfully',
                    'ca_cert_path': ca_cert_path
                }
            else:
                return {
                    'success': False,
                    'error': f"CA creation failed: {result.get('error', 'Unknown error')}"
                }
                
        except Exception as e:
            current_app.logger.error(f"Error creating CA certificate: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def create_server_certificate(self, server_name='server'):
        """Create server certificate."""
        try:
            server_cert_path = os.path.join(self.pki_path, 'issued', f'{server_name}.crt')
            server_key_path = os.path.join(self.pki_path, 'private', f'{server_name}.key')
            
            # Check if server certificate already exists
            if os.path.exists(server_cert_path):
                return {
                    'success': True,
                    'message': 'Server certificate already exists',
                    'cert_path': server_cert_path,
                    'key_path': server_key_path
                }
            
            # Execute server certificate creation script
            result = self._execute_script('create-server-cert.sh', [server_name])
            
            if result['success'] and os.path.exists(server_cert_path):
                return {
                    'success': True,
                    'message': 'Server certificate created successfully',
                    'cert_path': server_cert_path,
                    'key_path': server_key_path
                }
            else:
                return {
                    'success': False,
                    'error': f"Server certificate creation failed: {result.get('error', 'Unknown error')}"
                }
                
        except Exception as e:
            current_app.logger.error(f"Error creating server certificate: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def create_client_certificate(self, client_name):
        """Create client certificate."""
        try:
            # Validate client name
            if not self._validate_client_name(client_name):
                return {
                    'success': False,
                    'error': 'Invalid client name format'
                }
            
            cert_path = os.path.join(self.pki_path, 'issued', f'{client_name}.crt')
            key_path = os.path.join(self.pki_path, 'private', f'{client_name}.key')
            
            # Check if client certificate already exists
            if os.path.exists(cert_path):
                return {
                    'success': False,
                    'error': 'Client certificate already exists'
                }
            
            # Execute client certificate creation script
            result = self._execute_script('create-client-cert.sh', [client_name])
            
            if result['success'] and os.path.exists(cert_path):
                # Generate client configuration file
                config_path = self._generate_client_config(client_name)
                
                return {
                    'success': True,
                    'message': 'Client certificate created successfully',
                    'cert_path': cert_path,
                    'key_path': key_path,
                    'config_path': config_path
                }
            else:
                return {
                    'success': False,
                    'error': f"Client certificate creation failed: {result.get('error', 'Unknown error')}"
                }
                
        except Exception as e:
            current_app.logger.error(f"Error creating client certificate for {client_name}: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def revoke_client_certificate(self, client_name):
        """Revoke client certificate."""
        try:
            cert_path = os.path.join(self.pki_path, 'issued', f'{client_name}.crt')
            
            # Check if certificate exists
            if not os.path.exists(cert_path):
                return {
                    'success': False,
                    'error': 'Client certificate not found'
                }
            
            # Execute certificate revocation script
            result = self._execute_script('revoke-client-cert.sh', [client_name])
            
            if result['success']:
                # Update CRL
                crl_result = self._execute_script('update-crl.sh')
                
                return {
                    'success': True,
                    'message': 'Client certificate revoked successfully',
                    'crl_updated': crl_result['success']
                }
            else:
                return {
                    'success': False,
                    'error': f"Certificate revocation failed: {result.get('error', 'Unknown error')}"
                }
                
        except Exception as e:
            current_app.logger.error(f"Error revoking client certificate for {client_name}: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def list_certificates(self):
        """List all certificates."""
        try:
            certificates = {
                'ca': self._get_ca_info(),
                'server': self._get_server_certificates(),
                'clients': self._get_client_certificates(),
                'revoked': self._get_revoked_certificates()
            }
            
            return {
                'success': True,
                'certificates': certificates
            }
            
        except Exception as e:
            current_app.logger.error(f"Error listing certificates: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def get_certificate_info(self, cert_name, cert_type='client'):
        """Get detailed information about a certificate."""
        try:
            if cert_type == 'client':
                cert_path = os.path.join(self.pki_path, 'issued', f'{cert_name}.crt')
            elif cert_type == 'server':
                cert_path = os.path.join(self.pki_path, 'issued', f'{cert_name}.crt')
            elif cert_type == 'ca':
                cert_path = os.path.join(self.pki_path, 'ca.crt')
            else:
                return {'success': False, 'error': 'Invalid certificate type'}
            
            if not os.path.exists(cert_path):
                return {'success': False, 'error': 'Certificate not found'}
            
            # Parse certificate using openssl
            result = subprocess.run([
                'openssl', 'x509', '-in', cert_path, '-text', '-noout'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                cert_info = self._parse_certificate_text(result.stdout)
                cert_info['file_path'] = cert_path
                
                return {
                    'success': True,
                    'certificate': cert_info
                }
            else:
                return {
                    'success': False,
                    'error': f"Failed to parse certificate: {result.stderr}"
                }
                
        except Exception as e:
            current_app.logger.error(f"Error getting certificate info for {cert_name}: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def backup_pki(self):
        """Create backup of PKI directory."""
        try:
            backup_dir = current_app.config.get('BACKUP_PATH', '/app/backups')
            os.makedirs(backup_dir, exist_ok=True)
            
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            backup_file = os.path.join(backup_dir, f'pki_backup_{timestamp}.tar.gz')
            
            # Create compressed backup
            result = subprocess.run([
                'tar', '-czf', backup_file, '-C', os.path.dirname(self.pki_path), 'pki'
            ], capture_output=True, text=True)
            
            if result.returncode == 0 and os.path.exists(backup_file):
                return {
                    'success': True,
                    'backup_file': backup_file,
                    'size': os.path.getsize(backup_file)
                }
            else:
                return {
                    'success': False,
                    'error': f"Backup failed: {result.stderr}"
                }
                
        except Exception as e:
            current_app.logger.error(f"Error creating PKI backup: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _validate_client_name(self, name):
        """Validate client name for certificate creation."""
        # Allow alphanumeric characters, hyphens, and underscores
        pattern = r'^[a-zA-Z0-9][a-zA-Z0-9_-]*[a-zA-Z0-9]$'
        if len(name) == 1:
            pattern = r'^[a-zA-Z0-9]$'
        elif len(name) == 2:
            pattern = r'^[a-zA-Z0-9]{2}$'
        
        return bool(re.match(pattern, name)) and 3 <= len(name) <= 50
    
    def _generate_client_config(self, client_name):
        """Generate OpenVPN client configuration file."""
        try:
            config_dir = os.path.join(self.config_path, 'clients')
            os.makedirs(config_dir, exist_ok=True)
            
            config_file = os.path.join(config_dir, f'{client_name}.ovpn')
            
            # Read necessary files
            ca_cert = self._read_file(os.path.join(self.pki_path, 'ca.crt'))
            client_cert = self._read_file(os.path.join(self.pki_path, 'issued', f'{client_name}.crt'))
            client_key = self._read_file(os.path.join(self.pki_path, 'private', f'{client_name}.key'))
            ta_key = self._read_file(os.path.join(self.config_path, 'ta.key'))
            
            # Generate configuration content
            config_content = self._build_client_config(ca_cert, client_cert, client_key, ta_key)
            
            # Write configuration file
            with open(config_file, 'w') as f:
                f.write(config_content)
            
            return config_file
            
        except Exception as e:
            current_app.logger.error(f"Error generating client config for {client_name}: {str(e)}")
            return None
    
    def _build_client_config(self, ca_cert, client_cert, client_key, ta_key):
        """Build client configuration content."""
        config_template = """client
dev tun
proto udp
remote YOUR_SERVER_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3

<ca>
{ca_cert}
</ca>

<cert>
{client_cert}
</cert>

<key>
{client_key}
</key>

<tls-auth>
{ta_key}
</tls-auth>
key-direction 1
"""
        
        return config_template.format(
            ca_cert=ca_cert.strip(),
            client_cert=self._extract_cert_content(client_cert),
            client_key=client_key.strip(),
            ta_key=ta_key.strip() if ta_key else ''
        )
    
    def _extract_cert_content(self, cert_content):
        """Extract certificate content between BEGIN and END markers."""
        lines = cert_content.split('\n')
        cert_lines = []
        in_cert = False
        
        for line in lines:
            if '-----BEGIN CERTIFICATE-----' in line:
                in_cert = True
                continue
            elif '-----END CERTIFICATE-----' in line:
                break
            elif in_cert:
                cert_lines.append(line)
        
        return '\n'.join(cert_lines)
    
    def _read_file(self, file_path):
        """Safely read file content."""
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    return f.read()
            return ''
        except Exception:
            return ''
    
    def _get_ca_info(self):
        """Get CA certificate information."""
        try:
            ca_path = os.path.join(self.pki_path, 'ca.crt')
            if os.path.exists(ca_path):
                info = self.get_certificate_info('ca', 'ca')
                return info.get('certificate', {})
            return {}
        except Exception:
            return {}
    
    def _get_server_certificates(self):
        """Get server certificates."""
        try:
            issued_dir = os.path.join(self.pki_path, 'issued')
            if not os.path.exists(issued_dir):
                return []
            
            server_certs = []
            for file in os.listdir(issued_dir):
                if file.startswith('server') and file.endswith('.crt'):
                    cert_name = file[:-4]  # Remove .crt extension
                    info = self.get_certificate_info(cert_name, 'server')
                    if info['success']:
                        server_certs.append(info['certificate'])
            
            return server_certs
        except Exception:
            return []
    
    def _get_client_certificates(self):
        """Get client certificates."""
        try:
            issued_dir = os.path.join(self.pki_path, 'issued')
            if not os.path.exists(issued_dir):
                return []
            
            client_certs = []
            for file in os.listdir(issued_dir):
                if file.endswith('.crt') and not file.startswith('server'):
                    cert_name = file[:-4]  # Remove .crt extension
                    info = self.get_certificate_info(cert_name, 'client')
                    if info['success']:
                        client_certs.append(info['certificate'])
            
            return client_certs
        except Exception:
            return []
    
    def _get_revoked_certificates(self):
        """Get revoked certificates from CRL."""
        try:
            crl_path = os.path.join(self.pki_path, 'crl.pem')
            if not os.path.exists(crl_path):
                return []
            
            # Parse CRL to get revoked certificates
            result = subprocess.run([
                'openssl', 'crl', '-in', crl_path, '-text', '-noout'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                return self._parse_crl_text(result.stdout)
            
            return []
        except Exception:
            return []
    
    def _parse_certificate_text(self, cert_text):
        """Parse certificate text output from openssl."""
        info = {}
        
        try:
            lines = cert_text.split('\n')
            
            for line in lines:
                line = line.strip()
                
                if 'Subject:' in line:
                    info['subject'] = line.split('Subject:')[1].strip()
                elif 'Issuer:' in line:
                    info['issuer'] = line.split('Issuer:')[1].strip()
                elif 'Not Before:' in line:
                    info['not_before'] = line.split('Not Before:')[1].strip()
                elif 'Not After:' in line:
                    info['not_after'] = line.split('Not After:')[1].strip()
                elif 'Serial Number:' in line:
                    info['serial_number'] = line.split('Serial Number:')[1].strip()
        
        except Exception:
            pass
        
        return info
    
    def _parse_crl_text(self, crl_text):
        """Parse CRL text to extract revoked certificates."""
        revoked = []
        
        try:
            lines = crl_text.split('\n')
            
            for line in lines:
                line = line.strip()
                if 'Serial Number:' in line and 'Revocation Date:' in line:
                    # Parse revoked certificate info
                    # This is a simplified parser
                    revoked.append({
                        'serial_number': 'parsed_serial',
                        'revocation_date': 'parsed_date'
                    })
        
        except Exception:
            pass
        
        return revoked
    
    def _execute_script(self, script_name, args=None):
        """Execute a certificate management script."""
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
                timeout=120,  # Longer timeout for certificate operations
                cwd=self.easy_rsa_path
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
