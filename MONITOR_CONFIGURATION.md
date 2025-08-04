# DNS Monitor Configuration Guide

## Configurable Periodic Monitoring

The DNS monitoring system now features configurable periodic checks that can be managed through the Django admin dashboard. This allows you to adjust monitoring frequency and settings without code changes or server restarts.

## Admin Dashboard Configuration

### Accessing Monitor Settings

1. Go to the Django admin panel: `https://your-domain/admin/`
2. Navigate to **Monitor** → **Monitor Settings**
3. Click on the settings entry to configure

### Available Settings

#### DNS Check Settings

- **Check Interval (Minutes)**: How often to check domains for DNS changes
  - Minimum: 1 minute
  - Default: 15 minutes
  - Examples: 5 (every 5 minutes), 60 (every hour), 1440 (daily)

- **Max Parallel Checks**: Maximum number of domains to check simultaneously
  - Default: 10
  - Prevents server overload with large domain lists
  - If you have more domains than this limit, they'll be checked in subsequent cycles

- **DNS Timeout (Seconds)**: Timeout for DNS queries
  - Default: 30 seconds
  - Increase for slow DNS servers
  - Decrease for faster response detection

#### Notification Settings

- **Email Notifications Enabled**: Toggle email notifications on/off
- **Notification Email**: Email address to receive DNS change alerts

## How It Works

### Dynamic Scheduling

1. **Database-Driven**: The system uses `django-celery-beat` to store periodic tasks in the database
2. **Real-Time Updates**: Changes to settings automatically update the Celery Beat schedule
3. **No Restart Required**: Settings take effect immediately without server restart

### Check Process

1. **Scheduler Task**: Runs at the configured interval
2. **Domain Selection**: Selects active domains (limited by max parallel checks)
3. **Individual Checks**: Dispatches separate tasks for each domain
4. **Change Detection**: Compares current IPs with previously stored IPs
5. **Notifications**: Sends email if changes detected (when enabled)

### Parallel Processing

- Domains are checked in parallel for efficiency
- Number of parallel checks is configurable
- Large domain lists are processed across multiple cycles

## Management Commands

### Initialize Settings

```bash
python manage.py init_monitor
```

Creates default settings if none exist and displays current configuration.

### Manual Domain Checks

```bash
# Check all domains immediately
python manage.py check_domains --sync

# Schedule checks for all domains
python manage.py check_domains --async
```

## Email Notifications

When enabled, the system sends email notifications for DNS changes with:

- Domain name that changed
- Previous IP addresses
- New IP addresses  
- Timestamp of change detection

### Email Configuration

Ensure your Django settings include email configuration:

```python
# Email settings (add to your settings.py)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'your-smtp-server.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'your-email@example.com'
EMAIL_HOST_PASSWORD = 'your-password'
DEFAULT_FROM_EMAIL = 'DNS Monitor <noreply@yourdomain.com>'
```

## API Integration

The configurable settings also affect API behavior:

- Domain checks triggered via API respect the timeout settings
- New domains added via API trigger immediate checks using current settings

## Monitoring and Troubleshooting

### Check Current Settings

Via Django shell:
```python
from monitor.models import MonitorSettings
settings = MonitorSettings.get_settings()
print(f"Check interval: {settings.check_interval_minutes} minutes")
print(f"Email notifications: {settings.email_notifications_enabled}")
```

### View Celery Beat Tasks

In admin panel: **Django Celery Beat** → **Periodic Tasks**

### Log Monitoring

Check application logs for:
- Scheduled check confirmations
- Individual domain check results
- Email notification status
- Error messages

## Best Practices

### Check Frequency

- **High-priority domains**: 5-15 minutes
- **Standard monitoring**: 15-30 minutes  
- **Low-priority domains**: 60+ minutes

### Parallel Checks

- Start with 10 parallel checks
- Increase gradually based on server performance
- Monitor system resources during peak checks

### Email Notifications

- Use a dedicated email address for notifications
- Consider email filtering rules for high-volume monitoring
- Test notifications with a small domain set first

## Upgrade Notes

### From Static Schedule

If upgrading from the previous static 15-minute schedule:

1. The system automatically creates default settings
2. Initial interval remains 15 minutes
3. You can immediately adjust settings via admin
4. Old `CELERY_BEAT_SCHEDULE` setting serves as fallback only

### Database Changes

The upgrade adds:
- `MonitorSettings` model for configuration
- `django-celery-beat` tables for dynamic scheduling
- Email notification capabilities

All existing domain monitoring continues unchanged during the upgrade.
