"""
VPN Client model for managing OpenVPN clients.
"""

from app import db
from datetime import datetime, timedelta
from sqlalchemy import event
import uuid

class VPNClient(db.Model):
    """Model for VPN client management."""
    
    __tablename__ = 'vpn_clients'
    
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), nullable=True)
    description = db.Column(db.Text, nullable=True)
    
    # Client status
    is_active = db.Column(db.Boolean, default=True)
    is_revoked = db.Column(db.Boolean, default=False)
    
    # Certificate information
    certificate_path = db.Column(db.String(255), nullable=True)
    private_key_path = db.Column(db.String(255), nullable=True)
    config_file_path = db.Column(db.String(255), nullable=True)
    
    # Certificate validity
    cert_created_at = db.Column(db.DateTime, nullable=True)
    cert_expires_at = db.Column(db.DateTime, nullable=True)
    
    # Bandwidth limits (in MB/s, 0 = unlimited)
    bandwidth_limit_download = db.Column(db.Integer, default=0)
    bandwidth_limit_upload = db.Column(db.Integer, default=0)
    
    # Usage statistics
    total_bytes_sent = db.Column(db.BigInteger, default=0)
    total_bytes_received = db.Column(db.BigInteger, default=0)
    total_connection_time = db.Column(db.Integer, default=0)  # in seconds
    last_seen = db.Column(db.DateTime, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    revoked_at = db.Column(db.DateTime, nullable=True)
    
    # Foreign key to user who created this client
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Relationship
    creator = db.relationship('User', backref='created_clients', foreign_keys=[created_by])
    
    def __init__(self, name, **kwargs):
        super(VPNClient, self).__init__(name=name, **kwargs)
        # Set certificate expiry to 1 year from now by default
        if not self.cert_expires_at:
            self.cert_expires_at = datetime.utcnow() + timedelta(days=365)
    
    @property
    def is_certificate_expired(self):
        """Check if certificate is expired."""
        if not self.cert_expires_at:
            return False
        return datetime.utcnow() > self.cert_expires_at
    
    @property
    def days_until_expiry(self):
        """Get days until certificate expires."""
        if not self.cert_expires_at:
            return None
        delta = self.cert_expires_at - datetime.utcnow()
        return delta.days if delta.days > 0 else 0
    
    @property
    def is_expiring_soon(self, days=30):
        """Check if certificate is expiring within specified days."""
        if not self.cert_expires_at:
            return False
        return self.days_until_expiry <= days
    
    @property
    def total_bytes_transferred(self):
        """Get total bytes transferred."""
        return self.total_bytes_sent + self.total_bytes_received
    
    @property
    def formatted_bandwidth_usage(self):
        """Get formatted bandwidth usage."""
        def format_bytes(bytes_val):
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if bytes_val < 1024.0:
                    return f"{bytes_val:.2f} {unit}"
                bytes_val /= 1024.0
            return f"{bytes_val:.2f} PB"
        
        return {
            'sent': format_bytes(self.total_bytes_sent),
            'received': format_bytes(self.total_bytes_received),
            'total': format_bytes(self.total_bytes_transferred)
        }
    
    def revoke(self):
        """Revoke the client certificate."""
        self.is_revoked = True
        self.is_active = False
        self.revoked_at = datetime.utcnow()
    
    def reactivate(self):
        """Reactivate the client (if not revoked)."""
        if not self.is_revoked:
            self.is_active = True
    
    def update_usage_stats(self, bytes_sent, bytes_received, connection_time):
        """Update usage statistics."""
        self.total_bytes_sent += bytes_sent
        self.total_bytes_received += bytes_received
        self.total_connection_time += connection_time
        self.last_seen = datetime.utcnow()
    
    def to_dict(self):
        """Convert to dictionary for API responses."""
        return {
            'id': self.id,
            'client_id': self.client_id,
            'name': self.name,
            'email': self.email,
            'description': self.description,
            'is_active': self.is_active,
            'is_revoked': self.is_revoked,
            'is_certificate_expired': self.is_certificate_expired,
            'days_until_expiry': self.days_until_expiry,
            'is_expiring_soon': self.is_expiring_soon,
            'bandwidth_usage': self.formatted_bandwidth_usage,
            'bandwidth_limits': {
                'download': self.bandwidth_limit_download,
                'upload': self.bandwidth_limit_upload
            },
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'cert_expires_at': self.cert_expires_at.isoformat() if self.cert_expires_at else None
        }
    
    def __repr__(self):
        return f'<VPNClient {self.name}>'

# Event listener to update the updated_at timestamp
@event.listens_for(VPNClient, 'before_update')
def receive_before_update(mapper, connection, target):
    target.updated_at = datetime.utcnow()
