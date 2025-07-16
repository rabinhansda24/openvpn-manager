"""
Models package for the OpenVPN management application.
"""

from .user import User
from .client import VPNClient

__all__ = ['User', 'VPNClient']
