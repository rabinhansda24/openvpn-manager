"""
Background tasks for the OpenVPN management application using Celery.
"""

from celery import Celery
from flask import current_app
from app.services.backup_service import BackupService
from app.services.monitoring_service import MonitoringService
from app.services.certificate_service import CertificateService
from app.models.client import VPNClient
from app.models.user import User
from app import db
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart

def make_celery(app):
    """Create Celery instance with Flask app context."""
    celery = Celery(
        app.import_name,
        backend=app.config['CELERY_RESULT_BACKEND'],
        broker=app.config['CELERY_BROKER_URL']
    )
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        """Make celery tasks work with Flask app context."""
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery

# Tasks will be registered when this module is imported by the Flask app
celery = None

def init_celery(app):
    """Initialize Celery with Flask app."""
    global celery
    celery = make_celery(app)
    
    # Register periodic tasks
    celery.conf.beat_schedule = {
        'daily-backup': {
            'task': 'app.tasks.background_tasks.create_daily_backup',
            'schedule': 86400.0,  # 24 hours
        },
        'check-certificate-expiry': {
            'task': 'app.tasks.background_tasks.check_certificate_expiry',
            'schedule': 3600.0,  # 1 hour
        },
        'cleanup-logs': {
            'task': 'app.tasks.background_tasks.cleanup_old_logs',
            'schedule': 86400.0,  # 24 hours
        },
        'system-health-check': {
            'task': 'app.tasks.background_tasks.system_health_check',
            'schedule': 300.0,  # 5 minutes
        },
        'update-client-usage': {
            'task': 'app.tasks.background_tasks.update_client_usage_stats',
            'schedule': 900.0,  # 15 minutes
        },
    }
    
    return celery

@celery.task(bind=True)
def create_daily_backup(self):
    """Create daily system backup."""
    try:
        current_app.logger.info("Starting daily backup task")
        
        backup_service = BackupService()
        result = backup_service.create_backup('daily')
        
        if result['success']:
            current_app.logger.info(f"Daily backup completed: {result['backup_file']}")
            
            # Send notification email if configured
            send_backup_notification.delay(
                backup_name=result['backup_file'],
                backup_size=result['size'],
                success=True
            )
            
            return {
                'status': 'success',
                'backup_file': result['backup_file'],
                'size': result['size']
            }
        else:
            current_app.logger.error(f"Daily backup failed: {result['error']}")
            
            # Send failure notification
            send_backup_notification.delay(
                backup_name='daily',
                error=result['error'],
                success=False
            )
            
            return {
                'status': 'error',
                'error': result['error']
            }
    
    except Exception as e:
        current_app.logger.error(f"Daily backup task failed: {str(e)}")
        self.retry(countdown=60, max_retries=3)

@celery.task(bind=True)
def check_certificate_expiry(self):
    """Check for expiring certificates and send notifications."""
    try:
        current_app.logger.info("Checking certificate expiry")
        
        # Check for certificates expiring in 30, 7, and 1 days
        warning_periods = [30, 7, 1]
        notifications_sent = []
        
        for days in warning_periods:
            expiry_date = datetime.utcnow() + timedelta(days=days)
            
            expiring_clients = VPNClient.query.filter(
                VPNClient.cert_expires_at <= expiry_date,
                VPNClient.cert_expires_at > datetime.utcnow(),
                VPNClient.is_revoked == False
            ).all()
            
            if expiring_clients:
                current_app.logger.warning(f"Found {len(expiring_clients)} certificates expiring in {days} days")
                
                # Send notification
                send_certificate_expiry_notification.delay(
                    clients=[c.to_dict() for c in expiring_clients],
                    days_until_expiry=days
                )
                
                notifications_sent.append({
                    'days': days,
                    'count': len(expiring_clients)
                })
        
        return {
            'status': 'success',
            'notifications_sent': notifications_sent
        }
    
    except Exception as e:
        current_app.logger.error(f"Certificate expiry check failed: {str(e)}")
        self.retry(countdown=60, max_retries=3)

@celery.task(bind=True)
def cleanup_old_logs(self):
    """Clean up old log files and database records."""
    try:
        current_app.logger.info("Starting log cleanup task")
        
        import os
        import glob
        
        cleaned_files = []
        
        # Clean up old backup files
        backup_service = BackupService()
        backup_service._cleanup_old_backups()
        
        # Clean up old log files (keep last 30 days)
        log_dirs = ['/var/log/openvpn', '/app/logs']
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        
        for log_dir in log_dirs:
            if os.path.exists(log_dir):
                for log_file in glob.glob(os.path.join(log_dir, '*.log.*')):
                    try:
                        file_mtime = datetime.fromtimestamp(os.path.getmtime(log_file))
                        if file_mtime < cutoff_date:
                            os.remove(log_file)
                            cleaned_files.append(log_file)
                    except Exception as e:
                        current_app.logger.warning(f"Failed to remove log file {log_file}: {str(e)}")
        
        current_app.logger.info(f"Log cleanup completed. Removed {len(cleaned_files)} files")
        
        return {
            'status': 'success',
            'files_removed': len(cleaned_files),
            'files': cleaned_files
        }
    
    except Exception as e:
        current_app.logger.error(f"Log cleanup task failed: {str(e)}")
        self.retry(countdown=60, max_retries=3)

@celery.task(bind=True)
def system_health_check(self):
    """Perform system health check and alert on issues."""
    try:
        monitoring_service = MonitoringService()
        alerts = monitoring_service.get_system_alerts()
        
        critical_alerts = [a for a in alerts if a.get('type') == 'critical']
        
        if critical_alerts:
            current_app.logger.warning(f"Found {len(critical_alerts)} critical system alerts")
            
            # Send critical alert notification
            send_system_alert_notification.delay(alerts=critical_alerts)
        
        return {
            'status': 'success',
            'total_alerts': len(alerts),
            'critical_alerts': len(critical_alerts)
        }
    
    except Exception as e:
        current_app.logger.error(f"System health check failed: {str(e)}")
        self.retry(countdown=60, max_retries=3)

@celery.task(bind=True)
def update_client_usage_stats(self):
    """Update client usage statistics from OpenVPN status log."""
    try:
        from app.services.openvpn_service import OpenVPNService
        
        openvpn_service = OpenVPNService()
        connected_clients = openvpn_service.get_connected_clients()
        
        updated_count = 0
        
        for client_info in connected_clients:
            client_name = client_info.get('name')
            if not client_name:
                continue
            
            client = VPNClient.query.filter_by(name=client_name).first()
            if client:
                # Update usage statistics
                bytes_sent = client_info.get('bytes_sent', 0)
                bytes_received = client_info.get('bytes_received', 0)
                
                # Calculate incremental usage (simplified)
                client.total_bytes_sent = max(client.total_bytes_sent, bytes_sent)
                client.total_bytes_received = max(client.total_bytes_received, bytes_received)
                client.last_seen = datetime.utcnow()
                
                updated_count += 1
        
        if updated_count > 0:
            db.session.commit()
            current_app.logger.info(f"Updated usage stats for {updated_count} clients")
        
        return {
            'status': 'success',
            'updated_clients': updated_count,
            'connected_clients': len(connected_clients)
        }
    
    except Exception as e:
        current_app.logger.error(f"Client usage update failed: {str(e)}")
        db.session.rollback()
        self.retry(countdown=60, max_retries=3)

@celery.task(bind=True)
def send_backup_notification(self, backup_name=None, backup_size=None, success=True, error=None):
    """Send backup notification email."""
    try:
        if not current_app.config.get('MAIL_USERNAME'):
            return {'status': 'skipped', 'reason': 'Email not configured'}
        
        admin_users = User.query.filter_by(is_admin=True).all()
        admin_emails = [user.email for user in admin_users if user.email]
        
        if not admin_emails:
            return {'status': 'skipped', 'reason': 'No admin emails found'}
        
        subject = f"OpenVPN Manager - Backup {'Success' if success else 'Failed'}"
        
        if success:
            body = f"""
Backup completed successfully!

Backup Details:
- Name: {backup_name}
- Size: {backup_size if backup_size else 'Unknown'} bytes
- Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC

Your OpenVPN configuration and data have been safely backed up.
"""
        else:
            body = f"""
Backup failed!

Error Details:
- Backup Type: {backup_name}
- Error: {error}
- Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC

Please check the system logs and ensure the backup service is functioning correctly.
"""
        
        return send_email_notification(admin_emails, subject, body)
    
    except Exception as e:
        current_app.logger.error(f"Failed to send backup notification: {str(e)}")
        self.retry(countdown=60, max_retries=3)

@celery.task(bind=True)
def send_certificate_expiry_notification(self, clients, days_until_expiry):
    """Send certificate expiry notification email."""
    try:
        if not current_app.config.get('MAIL_USERNAME'):
            return {'status': 'skipped', 'reason': 'Email not configured'}
        
        admin_users = User.query.filter_by(is_admin=True).all()
        admin_emails = [user.email for user in admin_users if user.email]
        
        if not admin_emails:
            return {'status': 'skipped', 'reason': 'No admin emails found'}
        
        subject = f"OpenVPN Manager - Certificates Expiring in {days_until_expiry} Days"
        
        client_list = '\n'.join([f"- {client['name']} (expires: {client['cert_expires_at']})" for client in clients])
        
        body = f"""
Certificate Expiry Warning!

The following VPN client certificates will expire in {days_until_expiry} days:

{client_list}

Please renew these certificates to avoid service disruption.

You can regenerate certificates using the OpenVPN Manager web interface or CLI tools.
"""
        
        return send_email_notification(admin_emails, subject, body)
    
    except Exception as e:
        current_app.logger.error(f"Failed to send certificate expiry notification: {str(e)}")
        self.retry(countdown=60, max_retries=3)

@celery.task(bind=True)
def send_system_alert_notification(self, alerts):
    """Send system alert notification email."""
    try:
        if not current_app.config.get('MAIL_USERNAME'):
            return {'status': 'skipped', 'reason': 'Email not configured'}
        
        admin_users = User.query.filter_by(is_admin=True).all()
        admin_emails = [user.email for user in admin_users if user.email]
        
        if not admin_emails:
            return {'status': 'skipped', 'reason': 'No admin emails found'}
        
        subject = "OpenVPN Manager - Critical System Alerts"
        
        alert_list = '\n'.join([f"- {alert['category'].upper()}: {alert['message']}" for alert in alerts])
        
        body = f"""
Critical System Alerts Detected!

The following critical issues have been detected on your OpenVPN server:

{alert_list}

Please check your system immediately to resolve these issues.

System Information:
- Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
- Alert Count: {len(alerts)}
"""
        
        return send_email_notification(admin_emails, subject, body)
    
    except Exception as e:
        current_app.logger.error(f"Failed to send system alert notification: {str(e)}")
        self.retry(countdown=60, max_retries=3)

def send_email_notification(recipients, subject, body):
    """Helper function to send email notifications."""
    try:
        smtp_server = current_app.config.get('MAIL_SERVER')
        smtp_port = current_app.config.get('MAIL_PORT', 587)
        smtp_username = current_app.config.get('MAIL_USERNAME')
        smtp_password = current_app.config.get('MAIL_PASSWORD')
        use_tls = current_app.config.get('MAIL_USE_TLS', True)
        
        if not all([smtp_server, smtp_username, smtp_password]):
            return {'status': 'error', 'error': 'Email configuration incomplete'}
        
        msg = MimeMultipart()
        msg['From'] = smtp_username
        msg['To'] = ', '.join(recipients)
        msg['Subject'] = subject
        
        msg.attach(MimeText(body, 'plain'))
        
        server = smtplib.SMTP(smtp_server, smtp_port)
        if use_tls:
            server.starttls()
        
        server.login(smtp_username, smtp_password)
        server.sendmail(smtp_username, recipients, msg.as_string())
        server.quit()
        
        current_app.logger.info(f"Email notification sent to {len(recipients)} recipients")
        
        return {
            'status': 'success',
            'recipients': recipients,
            'subject': subject
        }
    
    except Exception as e:
        current_app.logger.error(f"Failed to send email: {str(e)}")
        return {'status': 'error', 'error': str(e)}

@celery.task(bind=True)
def regenerate_client_certificate(self, client_id):
    """Regenerate certificate for a specific client."""
    try:
        client = VPNClient.query.get(client_id)
        if not client:
            return {'status': 'error', 'error': 'Client not found'}
        
        if client.is_revoked:
            return {'status': 'error', 'error': 'Cannot regenerate certificate for revoked client'}
        
        cert_service = CertificateService()
        
        # Revoke old certificate
        if client.certificate_path:
            revoke_result = cert_service.revoke_client_certificate(client.name)
            if not revoke_result['success']:
                current_app.logger.warning(f"Failed to revoke old certificate for {client.name}")
        
        # Generate new certificate
        cert_result = cert_service.create_client_certificate(client.name)
        if not cert_result['success']:
            return {'status': 'error', 'error': cert_result['error']}
        
        # Update client record
        client.certificate_path = cert_result['cert_path']
        client.private_key_path = cert_result['key_path']
        client.config_file_path = cert_result['config_path']
        client.cert_created_at = datetime.utcnow()
        client.cert_expires_at = datetime.utcnow() + timedelta(days=365)
        
        db.session.commit()
        
        current_app.logger.info(f"Certificate regenerated for client: {client.name}")
        
        return {
            'status': 'success',
            'client_name': client.name,
            'cert_expires_at': client.cert_expires_at.isoformat()
        }
    
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Certificate regeneration failed for client {client_id}: {str(e)}")
        self.retry(countdown=60, max_retries=3)
