# OpenVPN Manager

A comprehensive, self-hosted OpenVPN server management platform built with Flask, featuring a modern web interface, advanced security features, and enterprise-grade monitoring capabilities.

![OpenVPN Manager Dashboard](docs/images/dashboard-preview.png)

## 🚀 Features

### 🛡️ Security First
- **2FA Authentication** - TOTP-based two-factor authentication
- **Role-based Access Control** - Admin and read-only user roles
- **JWT Token Authentication** - Secure API access
- **Rate Limiting** - Protection against brute force attacks
- **CSRF Protection** - Cross-site request forgery prevention
- **Input Validation** - Comprehensive sanitization and validation
- **Security Headers** - Best-practice HTTP security headers

### 👥 Client Management
- **Easy Client Creation** - Simple web interface for adding VPN clients
- **Certificate Management** - Automated certificate generation and renewal
- **QR Code Generation** - Mobile-friendly client setup
- **Bulk Operations** - Create, revoke, or download multiple clients
- **Usage Analytics** - Bandwidth tracking and connection statistics
- **Certificate Expiry Alerts** - Automated notifications for expiring certificates
- **Client Configuration Export** - Download .ovpn files or bulk ZIP archives

### 📊 Monitoring & Analytics
- **Real-time Dashboard** - Live system and client status
- **System Metrics** - CPU, memory, disk, and network monitoring
- **Connected Clients View** - Real-time connection status
- **Log Management** - Advanced log viewing with search and filtering
- **Prometheus Integration** - Metrics export for external monitoring
- **Performance Alerts** - Configurable system health alerts
- **Historical Data** - Usage trends and analytics

### 🔧 Server Management
- **Configuration Editor** - Web-based OpenVPN config management
- **Service Control** - Start, stop, restart OpenVPN server
- **Certificate Authority** - Built-in CA management
- **Backup & Restore** - Automated configuration backups
- **Update Management** - Certificate revocation list updates
- **Network Configuration** - Easy VPN network setup

### 🔄 Automation
- **Background Tasks** - Celery-powered task processing
- **Scheduled Backups** - Automated daily backups
- **Certificate Monitoring** - Automatic expiry detection
- **Email Notifications** - Alerts for critical events
- **Log Rotation** - Automated log cleanup
- **Health Checks** - Continuous system monitoring

## 🛠️ Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Backend** | Flask + Python 3.11 | Web application framework |
| **Frontend** | Jinja2 + Alpine.js + Tailwind CSS | Responsive web interface |
| **Database** | PostgreSQL / SQLite | Data persistence |
| **Cache** | Redis | Session storage and caching |
| **Task Queue** | Celery | Background job processing |
| **VPN Server** | OpenVPN | VPN server implementation |
| **PKI** | Easy-RSA | Certificate management |
| **Containerization** | Docker + Docker Compose | Easy deployment |
| **Monitoring** | Prometheus | Metrics and monitoring |

## 📋 Prerequisites

- **Docker & Docker Compose** (recommended)
- **Python 3.11+** (for development)
- **Redis** (for caching and task queue)
- **PostgreSQL** (for production) or SQLite (for development)
- **OpenVPN** (if not using Docker)

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/openvpn-manager.git
cd openvpn-manager
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your configuration
nano .env
```

### 3. Start with Docker Compose

```bash
# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f web
```

### 4. Initialize the Application

```bash
# Create admin user
docker-compose exec web flask create-admin

# Initialize database
docker-compose exec web flask init-db
```

### 5. Access the Web Interface

Open your browser and navigate to:
- **Web Interface**: http://localhost:5000
- **Default Login**: admin / admin (change immediately!)

## 🔧 Development Setup

### 1. Local Development Environment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Set up development database
export FLASK_ENV=development
flask init-db
flask create-admin

# Start development server
python run.py
```

### 2. Using UV Package Manager

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create and activate environment
uv venv
source .venv/bin/activate

# Install dependencies
uv pip install -r requirements.txt

# Run development server
uv run python run.py
```

### 3. Start Background Services

```bash
# Start Redis (required for tasks)
redis-server

# Start Celery worker (in another terminal)
celery -A app.celery worker --loglevel=info

# Start Celery beat scheduler (in another terminal)
celery -A app.celery beat --loglevel=info
```

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Browser   │◄──►│  Flask Web App  │◄──►│   PostgreSQL    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │      Redis      │◄──►│ Celery Workers  │
                       └─────────────────┘    └─────────────────┘
                                                        │
                                                        ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     Clients     │◄──►│ OpenVPN Server  │◄──►│ Certificate CA  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📁 Project Structure

```
openvpn-manager/
├── app/                        # Main application
│   ├── models/                 # Database models
│   │   ├── user.py            # User model with 2FA
│   │   └── client.py          # VPN client model
│   ├── routes/                 # API and web routes
│   │   ├── auth.py            # Authentication endpoints
│   │   ├── api.py             # REST API endpoints
│   │   ├── main.py            # Main web routes
│   │   ├── client_management.py # Client management
│   │   └── system_monitoring.py # System monitoring
│   ├── services/               # Business logic services
│   │   ├── openvpn_service.py # OpenVPN management
│   │   ├── certificate_service.py # PKI operations
│   │   ├── monitoring_service.py # System monitoring
│   │   ├── backup_service.py  # Backup operations
│   │   └── prometheus_service.py # Metrics export
│   ├── tasks/                  # Background tasks
│   │   └── background_tasks.py # Celery tasks
│   ├── utils/                  # Utility functions
│   │   ├── validation.py      # Input validation
│   │   └── security.py        # Security utilities
│   ├── scripts/                # Shell scripts
│   │   ├── init-openvpn.sh    # OpenVPN setup
│   │   ├── add-client.sh      # Add VPN client
│   │   ├── revoke-client.sh   # Revoke client
│   │   └── system-metrics.sh  # System monitoring
│   ├── templates/              # Jinja2 templates
│   │   ├── base.html          # Base template
│   │   ├── dashboard.html     # Dashboard page
│   │   ├── clients.html       # Client management
│   │   ├── logs.html          # Log viewer
│   │   └── settings.html      # Settings page
│   ├── static/                 # Static assets
│   │   ├── css/               # Stylesheets
│   │   └── js/                # JavaScript files
│   ├── __init__.py            # App factory
│   └── config.py              # Configuration
├── worker/                     # Celery worker
├── openvpn-docker/            # OpenVPN container
├── tests/                      # Test suite
├── migrations/                 # Database migrations
├── docker-compose.yml         # Docker composition
├── Dockerfile                 # App container
├── requirements.txt           # Python dependencies
├── .env.example              # Environment template
└── README.md                 # This file
```

## 🔐 Security Features

### Authentication & Authorization
- **Multi-factor Authentication**: TOTP-based 2FA support
- **Session Management**: Secure session handling with timeout
- **Role-based Access**: Admin and read-only user roles
- **JWT Tokens**: Stateless API authentication
- **Password Security**: Bcrypt hashing with strength validation

### Input Validation & Sanitization
- **SQL Injection Prevention**: Parameterized queries with SQLAlchemy
- **XSS Protection**: Input sanitization and CSP headers
- **CSRF Protection**: Token-based CSRF prevention
- **Rate Limiting**: Configurable rate limits per endpoint
- **File Upload Security**: Secure file handling and validation

### Network Security
- **TLS Encryption**: HTTPS enforcement in production
- **Security Headers**: HSTS, CSP, X-Frame-Options, etc.
- **IP Filtering**: Optional IP whitelist for admin access
- **VPN Security**: Strong cipher suites and authentication

## 📊 Monitoring & Observability

### Built-in Monitoring
- **Real-time Metrics**: CPU, memory, disk, network usage
- **Service Health**: OpenVPN server status monitoring
- **Client Analytics**: Connection history and bandwidth usage
- **System Alerts**: Configurable threshold-based alerts

### External Integration
- **Prometheus Metrics**: Comprehensive metrics export
- **Grafana Dashboards**: Pre-built visualization templates
- **Email Alerts**: SMTP-based notification system
- **Webhook Support**: Custom integrations via webhooks

### Logging
- **Structured Logging**: JSON-formatted log entries
- **Log Aggregation**: Centralized log collection
- **Log Retention**: Configurable retention policies
- **Search & Filter**: Advanced log analysis tools

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_ENV` | Application environment | `production` |
| `SECRET_KEY` | Flask secret key | *required* |
| `DATABASE_URL` | Database connection string | SQLite |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/0` |
| `ADMIN_USER` | Default admin username | `admin` |
| `ADMIN_PASSWORD` | Default admin password | `admin` |
| `MAIL_SERVER` | SMTP server for notifications | None |
| `PROMETHEUS_ENABLED` | Enable Prometheus metrics | `True` |

### OpenVPN Configuration

The application automatically generates a secure OpenVPN configuration, but you can customize:

- **Network Settings**: Server IP range, DNS servers
- **Security**: Cipher suites, authentication methods
- **Client Limits**: Maximum concurrent connections
- **Routing**: Custom route pushes to clients

## 🚀 Deployment

### Production Deployment

1. **Prepare Environment**
```bash
# Set production environment variables
export FLASK_ENV=production
export SECRET_KEY="your-super-secure-secret-key"
export DATABASE_URL="postgresql://user:pass@localhost/openvpn"
```

2. **Deploy with Docker**
```bash
# Build and start services
docker-compose -f docker-compose.yml up -d

# Set up reverse proxy (nginx/traefik)
# Configure SSL certificates
# Set up monitoring
```

3. **Security Hardening**
```bash
# Change default passwords
# Configure firewall rules
# Set up fail2ban
# Enable log monitoring
```

### Scaling & High Availability

- **Load Balancing**: Multiple web instances behind load balancer
- **Database Clustering**: PostgreSQL primary/replica setup
- **Redis Clustering**: Redis Sentinel for high availability
- **Container Orchestration**: Kubernetes deployment manifests

## 🧪 Testing

### Running Tests

```bash
# Install test dependencies
pip install -r requirements.txt

# Run unit tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=app --cov-report=html

# Run specific test file
python -m pytest tests/test_api.py -v
```

### Test Coverage

The test suite covers:
- **API Endpoints**: All REST API functionality
- **Authentication**: Login, logout, 2FA workflows
- **Database Models**: User and client model operations
- **Validation**: Input validation and sanitization
- **Security**: Authentication and authorization

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes** with tests
4. **Run the test suite**: `pytest`
5. **Commit your changes**: `git commit -m 'Add amazing feature'`
6. **Push to your fork**: `git push origin feature/amazing-feature`
7. **Open a Pull Request**

### Code Standards

- **Python**: Follow PEP 8 with Black formatting
- **JavaScript**: ESLint with standard configuration
- **HTML/CSS**: Prettier formatting
- **Documentation**: Comprehensive docstrings and comments

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Documentation
- **API Documentation**: `/docs` endpoint when running
- **User Manual**: [docs/user-manual.md](docs/user-manual.md)
- **Admin Guide**: [docs/admin-guide.md](docs/admin-guide.md)

### Getting Help
- **GitHub Issues**: Report bugs and request features
- **Discussions**: Community support and questions
- **Wiki**: Additional documentation and tutorials

### Professional Support
For enterprise support, custom development, or consulting services, please contact us at [support@openvpn-manager.com](mailto:support@openvpn-manager.com).

## 🙏 Acknowledgments

- **OpenVPN Community**: For the excellent VPN software
- **Flask Team**: For the web framework
- **Tailwind CSS**: For the utility-first CSS framework
- **Alpine.js**: For lightweight JavaScript interactivity
- **All Contributors**: Who have helped improve this project

## 🛣️ Roadmap

### Version 1.1
- [ ] LDAP/Active Directory integration
- [ ] Advanced client grouping and policies
- [ ] Multi-server management
- [ ] Enhanced mobile interface

### Version 1.2
- [ ] WireGuard protocol support
- [ ] Advanced analytics dashboard
- [ ] Custom certificate templates
- [ ] API rate limiting per user

### Version 2.0
- [ ] Microservices architecture
- [ ] Kubernetes native deployment
- [ ] Plugin system for extensions
- [ ] Advanced automation workflows

---

**Made with ❤️ for the open-source community**

For more information, visit our [documentation](https://docs.openvpn-manager.com) or [website](https://openvpn-manager.com).
