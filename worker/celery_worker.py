"""
Celery worker configuration for the OpenVPN Manager.
"""

import os
from celery_app import celery

if __name__ == '__main__':
    # Start the worker
    celery.start()
