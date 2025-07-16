"""
Backup service for system and configuration backups.
"""

import os
import shutil
import tarfile
import gzip
import json
from datetime import datetime, timedelta
from flask import current_app
import tempfile
import subprocess

class BackupService:
    """Service class for backup and restore operations."""
    
    def __init__(self):
        self.backup_path = current_app.config.get('BACKUP_PATH', '/app/backups')
        self.config_path = current_app.config.get('OPENVPN_CONFIG_PATH', '/etc/openvpn')
        self.retention_days = current_app.config.get('BACKUP_RETENTION_DAYS', 30)
        
        # Ensure backup directory exists
        os.makedirs(self.backup_path, exist_ok=True)
    
    def create_backup(self, backup_type='full'):
        """Create a system backup."""
        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            backup_name = f"openvpn_backup_{backup_type}_{timestamp}"
            backup_file = os.path.join(self.backup_path, f"{backup_name}.tar.gz")
            
            # Create backup metadata
            metadata = {
                'backup_name': backup_name,
                'backup_type': backup_type,
                'created_at': datetime.utcnow().isoformat(),
                'version': '1.0.0',
                'files_included': []
            }
            
            with tarfile.open(backup_file, 'w:gz') as tar:
                # Backup OpenVPN configuration
                if os.path.exists(self.config_path):
                    tar.add(self.config_path, arcname='openvpn_config')
                    metadata['files_included'].append('openvpn_config')
                
                # Backup application database (if SQLite)
                database_url = current_app.config.get('SQLALCHEMY_DATABASE_URI', '')
                if 'sqlite' in database_url:
                    db_file = database_url.replace('sqlite:///', '')
                    if os.path.exists(db_file):
                        tar.add(db_file, arcname='app_database.db')
                        metadata['files_included'].append('app_database.db')
                
                # Backup application logs
                log_dir = '/app/logs'
                if os.path.exists(log_dir):
                    tar.add(log_dir, arcname='app_logs')
                    metadata['files_included'].append('app_logs')
                
                # Backup PKI certificates
                pki_path = os.path.join(self.config_path, 'easy-rsa', 'pki')
                if os.path.exists(pki_path):
                    tar.add(pki_path, arcname='pki_certificates')
                    metadata['files_included'].append('pki_certificates')
                
                # Add metadata file
                metadata_json = json.dumps(metadata, indent=2)
                metadata_info = tarfile.TarInfo(name='backup_metadata.json')
                metadata_info.size = len(metadata_json.encode())
                metadata_info.mtime = int(datetime.utcnow().timestamp())
                tar.addfile(metadata_info, fileobj=tarfile.io.BytesIO(metadata_json.encode()))
            
            # Get backup file size
            backup_size = os.path.getsize(backup_file)
            
            # Clean up old backups
            self._cleanup_old_backups()
            
            return {
                'success': True,
                'backup_file': backup_name,
                'backup_path': backup_file,
                'size': backup_size,
                'metadata': metadata
            }
            
        except Exception as e:
            current_app.logger.error(f"Error creating backup: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def restore_backup(self, backup_name):
        """Restore from a backup."""
        try:
            # Find backup file
            backup_file = None
            for file in os.listdir(self.backup_path):
                if file.startswith(backup_name) and file.endswith('.tar.gz'):
                    backup_file = os.path.join(self.backup_path, file)
                    break
            
            if not backup_file or not os.path.exists(backup_file):
                return {'success': False, 'error': 'Backup file not found'}
            
            # Create temporary directory for extraction
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract backup
                with tarfile.open(backup_file, 'r:gz') as tar:
                    tar.extractall(temp_dir)
                
                # Read metadata
                metadata_file = os.path.join(temp_dir, 'backup_metadata.json')
                metadata = {}
                if os.path.exists(metadata_file):
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                
                # Create backup of current state before restore
                pre_restore_backup = self.create_backup('pre_restore')
                
                # Restore OpenVPN configuration
                openvpn_backup = os.path.join(temp_dir, 'openvpn_config')
                if os.path.exists(openvpn_backup):
                    # Backup current config
                    if os.path.exists(self.config_path):
                        shutil.move(self.config_path, f"{self.config_path}.restore_backup")
                    
                    # Restore from backup
                    shutil.copytree(openvpn_backup, self.config_path)
                
                # Restore database (if SQLite)
                db_backup = os.path.join(temp_dir, 'app_database.db')
                if os.path.exists(db_backup):
                    database_url = current_app.config.get('SQLALCHEMY_DATABASE_URI', '')
                    if 'sqlite' in database_url:
                        db_file = database_url.replace('sqlite:///', '')
                        if os.path.exists(db_file):
                            shutil.copy2(db_file, f"{db_file}.restore_backup")
                        shutil.copy2(db_backup, db_file)
                
                # Restore PKI certificates
                pki_backup = os.path.join(temp_dir, 'pki_certificates')
                if os.path.exists(pki_backup):
                    pki_path = os.path.join(self.config_path, 'easy-rsa', 'pki')
                    if os.path.exists(pki_path):
                        shutil.move(pki_path, f"{pki_path}.restore_backup")
                    
                    os.makedirs(os.path.dirname(pki_path), exist_ok=True)
                    shutil.copytree(pki_backup, pki_path)
                
                return {
                    'success': True,
                    'backup_restored': backup_name,
                    'metadata': metadata,
                    'pre_restore_backup': pre_restore_backup.get('backup_file', 'None')
                }
        
        except Exception as e:
            current_app.logger.error(f"Error restoring backup {backup_name}: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def list_backups(self):
        """List available backups."""
        try:
            backups = []
            
            if not os.path.exists(self.backup_path):
                return backups
            
            for file in os.listdir(self.backup_path):
                if file.endswith('.tar.gz') and 'openvpn_backup' in file:
                    file_path = os.path.join(self.backup_path, file)
                    file_stats = os.stat(file_path)
                    
                    # Try to read metadata from backup
                    metadata = self._read_backup_metadata(file_path)
                    
                    backup_info = {
                        'name': file.replace('.tar.gz', ''),
                        'filename': file,
                        'size': file_stats.st_size,
                        'created_at': datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
                        'metadata': metadata
                    }
                    
                    backups.append(backup_info)
            
            # Sort by creation time (newest first)
            backups.sort(key=lambda x: x['created_at'], reverse=True)
            
            return backups
            
        except Exception as e:
            current_app.logger.error(f"Error listing backups: {str(e)}")
            return []
    
    def delete_backup(self, backup_name):
        """Delete a specific backup."""
        try:
            backup_file = None
            for file in os.listdir(self.backup_path):
                if file.startswith(backup_name) and file.endswith('.tar.gz'):
                    backup_file = os.path.join(self.backup_path, file)
                    break
            
            if not backup_file or not os.path.exists(backup_file):
                return {'success': False, 'error': 'Backup file not found'}
            
            os.remove(backup_file)
            
            return {
                'success': True,
                'deleted_backup': backup_name
            }
            
        except Exception as e:
            current_app.logger.error(f"Error deleting backup {backup_name}: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def validate_backup(self, backup_name):
        """Validate backup integrity."""
        try:
            backup_file = None
            for file in os.listdir(self.backup_path):
                if file.startswith(backup_name) and file.endswith('.tar.gz'):
                    backup_file = os.path.join(self.backup_path, file)
                    break
            
            if not backup_file or not os.path.exists(backup_file):
                return {'success': False, 'error': 'Backup file not found'}
            
            # Check if file can be opened and read
            try:
                with tarfile.open(backup_file, 'r:gz') as tar:
                    # List all files in backup
                    members = tar.getmembers()
                    
                    # Check for metadata file
                    has_metadata = any(m.name == 'backup_metadata.json' for m in members)
                    
                    # Basic integrity check
                    for member in members:
                        if member.isfile():
                            # Try to extract a small portion to verify
                            tar.extractfile(member).read(1024)
                
                return {
                    'success': True,
                    'valid': True,
                    'file_count': len(members),
                    'has_metadata': has_metadata
                }
                
            except (tarfile.TarError, IOError) as e:
                return {
                    'success': True,
                    'valid': False,
                    'error': f"Backup corruption detected: {str(e)}"
                }
        
        except Exception as e:
            current_app.logger.error(f"Error validating backup {backup_name}: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def schedule_automatic_backup(self):
        """Schedule automatic backup (for use with Celery)."""
        try:
            # This would be called by a Celery periodic task
            result = self.create_backup('automatic')
            
            if result['success']:
                current_app.logger.info(f"Automatic backup created: {result['backup_file']}")
            else:
                current_app.logger.error(f"Automatic backup failed: {result['error']}")
            
            return result
            
        except Exception as e:
            current_app.logger.error(f"Error in automatic backup: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _cleanup_old_backups(self):
        """Clean up old backups based on retention policy."""
        try:
            if not os.path.exists(self.backup_path):
                return
            
            cutoff_date = datetime.utcnow() - timedelta(days=self.retention_days)
            
            for file in os.listdir(self.backup_path):
                if file.endswith('.tar.gz') and 'openvpn_backup' in file:
                    file_path = os.path.join(self.backup_path, file)
                    file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                    
                    if file_mtime < cutoff_date:
                        try:
                            os.remove(file_path)
                            current_app.logger.info(f"Deleted old backup: {file}")
                        except Exception as e:
                            current_app.logger.error(f"Error deleting old backup {file}: {str(e)}")
        
        except Exception as e:
            current_app.logger.error(f"Error cleaning up old backups: {str(e)}")
    
    def _read_backup_metadata(self, backup_file):
        """Read metadata from backup file."""
        try:
            with tarfile.open(backup_file, 'r:gz') as tar:
                try:
                    metadata_member = tar.getmember('backup_metadata.json')
                    metadata_file = tar.extractfile(metadata_member)
                    if metadata_file:
                        return json.loads(metadata_file.read().decode())
                except KeyError:
                    # No metadata file found
                    pass
            
            return {}
            
        except Exception:
            return {}
    
    def get_backup_statistics(self):
        """Get backup statistics and health information."""
        try:
            backups = self.list_backups()
            
            if not backups:
                return {
                    'total_backups': 0,
                    'total_size': 0,
                    'oldest_backup': None,
                    'newest_backup': None,
                    'health_status': 'no_backups'
                }
            
            total_size = sum(backup['size'] for backup in backups)
            oldest_backup = min(backups, key=lambda x: x['created_at'])
            newest_backup = max(backups, key=lambda x: x['created_at'])
            
            # Determine health status
            newest_date = datetime.fromisoformat(newest_backup['created_at'])
            days_since_last = (datetime.utcnow() - newest_date).days
            
            if days_since_last <= 1:
                health_status = 'healthy'
            elif days_since_last <= 7:
                health_status = 'warning'
            else:
                health_status = 'critical'
            
            return {
                'total_backups': len(backups),
                'total_size': total_size,
                'total_size_formatted': self._format_bytes(total_size),
                'oldest_backup': oldest_backup,
                'newest_backup': newest_backup,
                'days_since_last_backup': days_since_last,
                'health_status': health_status,
                'retention_days': self.retention_days
            }
            
        except Exception as e:
            current_app.logger.error(f"Error getting backup statistics: {str(e)}")
            return {'error': str(e)}
    
    def _format_bytes(self, bytes_val):
        """Format bytes to human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"
