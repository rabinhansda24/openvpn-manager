"""
Celery worker configuration for the OpenVPN Manager.
"""

import os
from celery import Celery
from app import create_app

# Create Flask app
app = create_app(os.environ.get('FLASK_ENV', 'production'))

# Initialize Celery
from app.tasks import init_celery
celery = init_celery(app)

if __name__ == '__main__':
    # Start the worker
    celery.start()
