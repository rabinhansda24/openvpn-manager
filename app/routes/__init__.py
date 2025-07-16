"""
Routes package for the OpenVPN management application.
"""

from .auth import auth_bp
from .main import main_bp
from .api import api_bp
from .client_management import client_bp
from .system_monitoring import system_bp

__all__ = ['auth_bp', 'main_bp', 'api_bp', 'client_bp', 'system_bp']
