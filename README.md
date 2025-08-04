# DNS Checker - Django-based DNS A-Record Change Monitor

A Django web application that automatically monitors DNS A-record changes for a list of domains and maintains a historical log of IP address changes.

## ✅ Implementation Status

**All core features have been implemented and ready for production deployment:**

- ✅ Domain management with is_active flag
- ✅ Automated DNS polling every 15 minutes using Celery Beat
- ✅ Change detection and historical logging
- ✅ Django Admin interface for management
- ✅ Celery-based asynchronous task processing
- ✅ Redis as message broker
- ✅ PostgreSQL/SQLite database support
- ✅ Management command for importing domains
- ✅ Error handling for DNS lookup failures
- ✅ Comprehensive logging
- ✅ **Production-ready Dokku deployment configuration**

## 🚀 Deployment Options

### Production Deployment (Dokku)

**Ready for production deployment on Dokku servers:**

1. **Quick Deploy:**
   ```bash
   git remote add dokku dokku@your-server.com:dns-checker
   git push dokku main
   ```

2. **Complete Setup:** Follow the comprehensive [Dokku Deployment Guide](DOKKU_DEPLOYMENT.md)

3. **Deployment Checklist:** Use the [Deployment Checklist](DEPLOYMENT_CHECKLIST.md)

### Local Development

1. **Setup the project:**
   ```bash
   ./run.sh setup
   ```

2. **Start Redis (required for Celery):**
   ```bash
   redis-server
   ```

3. **Start the services (in separate terminals):**
   ```bash
   # Terminal 1 - Celery Worker
   ./run.sh worker
   
   # Terminal 2 - Celery Beat Scheduler  
   ./run.sh beat
   
   # Terminal 3 - Django Server
   ./run.sh server
   ```

4. **Access Django Admin:**
   - Go to http://localhost:8000/admin/
   - Login: `admin` / `admin123`

## Features

- **Domain Management**: Add, edit, activate/deactivate domains through Django Admin
- **Automated Monitoring**: DNS checks every 15 minutes via Celery Beat
- **Change Detection**: Tracks IP address changes with historical logging
- **Admin Interface**: Full Django Admin with search, filtering, and bulk actions
- **Error Handling**: Graceful handling of DNS timeouts, NXDOMAIN, etc.
- **Management Commands**: Easy domain import and manual checking
- **Logging**: Comprehensive logging to file and console
- **Production Ready**: Configured for Dokku deployment with SSL, static files, etc.

## Production Features

- **Gunicorn WSGI Server**: Production-grade Python WSGI HTTP Server
- **WhiteNoise Static Files**: Efficient static file serving
- **PostgreSQL Support**: Production database with automatic URL parsing
- **SSL/TLS Ready**: Automatic HTTPS with Let's Encrypt
- **Environment Configuration**: Secure environment variable management
- **Process Scaling**: Separate web, worker, and beat processes
- **Health Monitoring**: Built-in Django health checks
- **Security Headers**: Production security configuration

## Quick Start (Development)

```bash
# Clone and setup
git clone <your-repo>
cd dns_checker

# Create virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Setup database and create admin user
python manage.py migrate
python manage.py createsuperuser

# Import sample domains
python manage.py import_domains sample_domains.txt

# Test production configuration
./test_production.sh all

# Start development services
./run.sh setup  # One-time setup
./run.sh server # Django server
```

## Quick Start (Production)

```bash
# On Dokku server
dokku apps:create dns-checker
dokku postgres:create dns-checker-db
dokku postgres:link dns-checker-db dns-checker
dokku redis:create dns-checker-redis  
dokku redis:link dns-checker-redis dns-checker

# Configure environment
dokku config:set dns-checker SECRET_KEY="your-secure-key"
dokku config:set dns-checker DEBUG=False
dokku config:set dns-checker ALLOWED_HOSTS="your-domain.com"

# Deploy
git remote add dokku dokku@your-server.com:dns-checker
git push dokku main

# Setup database
dokku run dns-checker python manage.py migrate
dokku run dns-checker python manage.py createsuperuser

# Scale processes
dokku ps:scale dns-checker web=1 worker=1 beat=1

# Enable SSL
dokku letsencrypt:enable dns-checker
```

## Usage

### Import Domains
```bash
# Import from file (one domain per line)
python manage.py import_domains domains.txt

# Import with options
python manage.py import_domains domains.txt --skip-existing --dry-run
```

### Manual Domain Checking
```bash
# Check all active domains
python manage.py check_domains --all

# Check specific domain
python manage.py check_domains --domain google.com

# Schedule checks via Celery
python manage.py check_domains
```

### Admin Interface
1. Navigate to http://localhost:8000/admin/ (or your production domain)
2. **Domains**: Add/edit domains, activate/deactivate monitoring
3. **Record Logs**: View historical DNS check results with filtering

## Database Models

### Domain
- `name`: Domain name (unique)
- `is_active`: Whether domain is being monitored
- `last_known_ips`: Comma-separated list of last known IPs
- `updated_at`: Last check timestamp
- `created_at`: When domain was added

### RecordLog
- `domain`: Foreign key to Domain
- `ips`: Comma-separated IPs found during check
- `is_change`: Whether IPs changed from previous check
- `timestamp`: When check was performed
- `error_message`: Error details if DNS lookup failed

## Celery Tasks

### Scheduled Tasks
- `schedule_domain_checks`: Runs every 15 minutes, dispatches individual checks
- `check_domain_a_records`: Checks DNS A records for a specific domain

### Manual Tasks
- `check_all_domains_now`: Check all active domains immediately

## Configuration

Key settings in `dns_checker/settings.py`:

```python
# Celery Beat Schedule - every 15 minutes
CELERY_BEAT_SCHEDULE = {
    'check-all-domains': {
        'task': 'monitor.tasks.schedule_domain_checks',
        'schedule': crontab(minute='*/15'),
    },
}

# Redis configuration
CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'

# Production settings
DEBUG = False
ALLOWED_HOSTS = ['your-domain.com']
STATIC_ROOT = BASE_DIR / 'staticfiles'
```

## Project Structure

```
dns_checker/
├── dns_checker/           # Django project settings
│   ├── __init__.py       # Celery app initialization
│   ├── settings.py       # Django settings with Celery config
│   ├── celery.py         # Celery configuration
│   └── urls.py           # URL routing
├── monitor/              # Main Django app
│   ├── models.py         # Domain and RecordLog models
│   ├── admin.py          # Django Admin configuration
│   ├── tasks.py          # Celery tasks for DNS checking
│   └── management/commands/
│       ├── import_domains.py    # Domain import command
│       └── check_domains.py     # Manual check command
├── requirements.txt      # Python dependencies
├── Procfile             # Process configuration for Dokku
├── runtime.txt          # Python version specification
├── sample_domains.txt    # Sample domains for testing
├── run.sh               # Helper script for development
├── test_production.sh   # Production testing script
├── DOKKU_DEPLOYMENT.md  # Complete deployment guide
├── DEPLOYMENT_CHECKLIST.md # Deployment checklist
└── README.md            # This file
```

## Dependencies

- **Django 5.2+**: Web framework
- **Celery 5.5+**: Asynchronous task queue
- **Redis 6.2+**: Message broker for Celery
- **dnspython 2.7+**: DNS resolution library
- **psycopg2-binary 2.9+**: PostgreSQL adapter
- **python-decouple 3.8+**: Environment variable management
- **gunicorn 23.0+**: Production WSGI server
- **whitenoise 6.9+**: Static file serving
- **dj-database-url 3.0+**: Database URL parsing

## Production Considerations

1. **Database**: Use PostgreSQL for production (automatically configured)
2. **Redis**: Configure Redis persistence and backup
3. **Celery**: Use proper process management (systemd, supervisor, or Dokku scaling)
4. **Logging**: Configure log rotation and external log aggregation
5. **Monitoring**: Set up monitoring for Celery workers and DNS check success rates
6. **Security**: Automatic HTTPS, security headers, and environment variable management
7. **Scaling**: Scale worker processes based on domain count and check frequency

## Testing

### Local Development Testing
```bash
# Test DNS functionality
python manage.py check_domains --domain google.com

# Test all sample domains
python manage.py check_domains --all

# Run production configuration tests
./test_production.sh all
```

### Production Deployment Testing
```bash
# On Dokku server after deployment
dokku run dns-checker python manage.py check_domains --domain google.com
dokku logs dns-checker --tail
```

## Monitoring

- **Application Health**: Django admin interface + process monitoring
- **DNS Checks**: RecordLog model tracks all checks and changes
- **Process Status**: Monitor web, worker, and beat processes
- **Error Tracking**: Comprehensive error logging and handling

## Support & Documentation

- **[Dokku Deployment Guide](DOKKU_DEPLOYMENT.md)**: Complete production deployment instructions
- **[Deployment Checklist](DEPLOYMENT_CHECKLIST.md)**: Step-by-step deployment verification
- **[Project Status](PROJECT_STATUS.md)**: Implementation status and features

## License

This project is created for DNS monitoring purposes. Modify as needed for your use case.

---

## 🎉 Ready for Production!

The DNS A-Record Monitor is now fully configured for production deployment on Dokku servers with automatic SSL, database management, and scalable Celery task processing.
