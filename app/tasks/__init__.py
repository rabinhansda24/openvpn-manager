"""
Tasks package for background processing in the OpenVPN management application.
"""

from .background_tasks import (
    init_celery,
    create_daily_backup,
    check_certificate_expiry,
    cleanup_old_logs,
    system_health_check,
    update_client_usage_stats,
    send_backup_notification,
    send_certificate_expiry_notification,
    send_system_alert_notification,
    regenerate_client_certificate
)

__all__ = [
    'init_celery',
    'create_daily_backup',
    'check_certificate_expiry',
    'cleanup_old_logs',
    'system_health_check',
    'update_client_usage_stats',
    'send_backup_notification',
    'send_certificate_expiry_notification',
    'send_system_alert_notification',
    'regenerate_client_certificate'
]
