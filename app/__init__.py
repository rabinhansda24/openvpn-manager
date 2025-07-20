"""
OpenVPN Server Management Application
Enhanced Flask application with security, monitoring, and modern features.
"""

from flask import Flask, jsonify, request, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_socketio import SocketIO
import redis
import os
from datetime import timedelta

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
jwt = JWTManager()
socketio = SocketIO()

def create_app(config_name='default'):
    """Application factory pattern."""
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(get_config(config_name))
    
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    jwt.init_app(app)
    CORS(app)
    socketio.init_app(app, cors_allowed_origins="*")
    
    # Configure login manager
    login_manager.login_view = 'auth.login_page'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    login_manager.needs_refresh_message = 'Please log in again to access this page.'
    login_manager.needs_refresh_message_category = 'info'
    login_manager.session_protection = "strong"
    
    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.api import api_bp
    from app.routes.main import main_bp
    from app.routes.client_management import client_bp
    from app.routes.system_monitoring import system_bp
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(main_bp)
    app.register_blueprint(client_bp, url_prefix='/clients')
    app.register_blueprint(system_bp, url_prefix='/system')
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register CLI commands
    register_cli_commands(app)
    
    # Add global before request handler
    @app.before_request
    def before_request():
        """Global before request handler."""
        from flask_login import current_user, logout_user
        from app.utils.security import session_timeout_check
        
        # Skip static files and auth routes
        if request.endpoint and (request.endpoint.startswith('static') or 
                               request.endpoint.startswith('auth.')):
            return
        
        # Check session timeout
        if current_user.is_authenticated and not session_timeout_check():
            logout_user()
            session.clear()
            
            # For API requests, return JSON error
            if (request.content_type and 'application/json' in request.content_type) or \
               request.path.startswith('/api/'):
                return jsonify({'error': 'Session expired', 'redirect': url_for('auth.login_page')}), 401
            
            # For web requests, redirect to login
            return redirect(url_for('auth.login_page', next=request.url))
    
    # Health check endpoint
    @app.route('/health')
    def health_check():
        """Health check endpoint for monitoring."""
        try:
            # Check database connection
            db.session.execute('SELECT 1')
            
            # Check Redis connection
            redis_client = redis.from_url(app.config['REDIS_URL'])
            redis_client.ping()
            
            return jsonify({
                'status': 'healthy',
                'database': 'connected',
                'redis': 'connected',
                'version': '1.0.0'
            }), 200
        except Exception as e:
            return jsonify({
                'status': 'unhealthy',
                'error': str(e)
            }), 503
    
    # Ensure session configuration is suitable for Docker
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_PERMANENT'] = True
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_REDIS'] = redis.from_url(app.config['REDIS_URL'])
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    
    # Ensure secret key is set
    if not app.config.get('SECRET_KEY'):
        app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'development-key')
    
    return app

def get_config(config_name):
    """Get configuration class based on environment."""
    from app.config import config
    config_class = config.get(config_name, config['default'])
    
    # Validate production config only when it's being used
    if config_name == 'production' and config_class.__name__ == 'ProductionConfig':
        if not config_class.SECRET_KEY:
            raise ValueError("No SECRET_KEY set for production environment")
        if not config_class.JWT_SECRET_KEY:
            raise ValueError("No JWT_SECRET_KEY set for production environment")
    
    return config_class

def register_error_handlers(app):
    """Register application error handlers."""
    
    @app.errorhandler(404)
    def not_found_error(error):
        return jsonify({'error': 'Resource not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500
    
    @app.errorhandler(403)
    def forbidden_error(error):
        return jsonify({'error': 'Access forbidden'}), 403
    
    @app.errorhandler(401)
    def unauthorized_error(error):
        return jsonify({'error': 'Authentication required'}), 401

def register_cli_commands(app):
    """Register CLI commands for management."""
    
    @app.cli.command()
    def init_db():
        """Initialize the database."""
        db.create_all()
        print('Database initialized!')
    
    @app.cli.command()
    def create_admin():
        """Create admin user."""
        from app.models.user import User
        from werkzeug.security import generate_password_hash
        
        admin_user = os.environ.get('ADMIN_USER', 'admin')
        admin_password = os.environ.get('ADMIN_PASSWORD', 'admin')
        
        # Check if admin already exists
        existing_admin = User.query.filter_by(username=admin_user).first()
        if existing_admin:
            print(f'Admin user {admin_user} already exists!')
            return
        
        # Create admin user
        admin = User(
            username=admin_user,
            email=f'{admin_user}@localhost',
            password_hash=generate_password_hash(admin_password),
            is_admin=True,
            is_active=True
        )
        
        db.session.add(admin)
        db.session.commit()
        print(f'Admin user {admin_user} created successfully!')

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login."""
    from app.models.user import User
    return User.query.get(int(user_id))
