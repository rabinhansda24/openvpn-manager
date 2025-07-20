"""
OpenVPN Manager - Main Application Entry Point
"""

import os
from app import create_app
from app.tasks import init_celery

# Create the Flask application
app = create_app(os.environ.get('FLASK_ENV', 'production'))

# Initialize Celery
celery = init_celery(app)

if __name__ == '__main__':
    # Development server
    app.run(debug=app.config.get('DEBUG', False), host='0.0.0.0', port=5000)
