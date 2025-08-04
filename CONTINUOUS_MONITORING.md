# Continuous DNS Monitoring Configuration

## Overview

The DNS Checker now supports two monitoring modes:

1. **Periodic Monitoring** (Default): Scheduled checks at fixed intervals using Celery Beat
2. **Continuous Monitoring** (New): Continuous checking with configurable rate limiting

## Monitoring Modes

### Periodic Monitoring
- Uses Celery Beat scheduler for regular intervals
- Configurable check interval (minimum 1 minute)
- All active domains checked simultaneously at each interval
- Good for: Regular monitoring with predictable resource usage

### Continuous Monitoring
- Continuously loops through domains without fixed schedule
- Configurable rate limiting per domain (minimum 10 seconds)
- Domains checked as soon as rate limit allows
- Good for: Real-time monitoring with faster change detection

## Configuration

### Via Django Admin Panel
1. Navigate to: `Admin Panel > Monitor > Monitor Settings`
2. Configure the following fields:

#### Monitoring Mode
- **Continuous monitoring enabled**: Toggle between periodic and continuous modes

#### Periodic Monitoring Settings (when continuous disabled)
- **Check interval minutes**: How often to check all domains (minimum: 1 minute)

#### Continuous Monitoring Settings (when continuous enabled)
- **Min check interval seconds**: Minimum time between checks for the same domain (minimum: 10 seconds)

#### Performance Settings (applies to both modes)
- **Max parallel checks**: Maximum domains to check simultaneously
- **DNS timeout seconds**: Timeout for DNS queries

### Via Management Commands

#### Enable Continuous Monitoring
```bash
python manage.py start_continuous_monitoring --enable
```

#### Disable Continuous Monitoring
```bash
python manage.py start_continuous_monitoring --disable
```

#### Start Continuous Monitoring (if enabled)
```bash
python manage.py start_continuous_monitoring
```

#### Check Domains with Rate Limiting (one-time)
```bash
python manage.py check_with_rate_limit
```

## How It Works

### Continuous Monitoring Flow
1. System checks if continuous monitoring is enabled
2. Queries all active domains from database
3. Filters domains based on rate limiting (uses `updated_at` field)
4. Checks eligible domains in parallel batches
5. Updates domain `updated_at` timestamp after each check
6. Immediately starts next cycle (with small delay to prevent overwhelming)

### Rate Limiting Logic
- Each domain has an `updated_at` timestamp
- Domain can only be checked if: `current_time - updated_at >= min_check_interval_seconds`
- This ensures no domain is checked more frequently than the configured rate limit

### Performance Considerations
- Continuous monitoring respects `max_parallel_checks` setting
- Domains are processed in batches to avoid overwhelming the system
- Failed domains are retried according to Celery retry configuration
- Continuous monitoring can be stopped by disabling it in admin settings

## Production Deployment

### Dokku Procfile Configuration
The system supports both monitoring modes through the existing Procfile:

```procfile
web: gunicorn dns_checker.wsgi:application --bind 0.0.0.0:$PORT
worker: celery -A dns_checker worker --loglevel=info
beat: celery -A dns_checker beat --loglevel=info --scheduler=django_celery_beat.schedulers:DatabaseScheduler
```

### Switching Between Modes
1. **To enable continuous monitoring**:
   - Access Django admin panel in production
   - Go to Monitor Settings
   - Enable "Continuous monitoring enabled"
   - Save settings (this automatically starts continuous monitoring)

2. **To return to periodic monitoring**:
   - Access Django admin panel in production
   - Go to Monitor Settings
   - Disable "Continuous monitoring enabled"
   - Save settings (continuous monitoring will stop automatically)

### Monitoring Active Tasks
- Use Celery monitoring tools to track active tasks
- Check Django admin logs for monitoring activity
- Monitor system resources when using continuous mode

## API Compatibility

The existing API endpoints remain fully compatible:
- `POST /api/domains/` - Add new domain (triggers immediate check in both modes)
- `GET /api/domains/{domain_name}/` - Get domain data (works with both modes)
- `GET /api/domains/list/` - List all domains (works with both modes)

## Database Impact

### New Fields Added to MonitorSettings
- `continuous_monitoring_enabled`: Boolean flag for monitoring mode
- `min_check_interval_seconds`: Rate limiting configuration

### Domain Model Enhancement
- Added `can_be_checked_now()` method for rate limiting logic
- Uses existing `updated_at` field for rate limit calculations

## Recommended Settings

### For Real-time Monitoring
- **Continuous monitoring**: Enabled
- **Min check interval**: 60 seconds (for most domains)
- **Max parallel checks**: 10-20 (depending on server capacity)

### For Regular Monitoring
- **Continuous monitoring**: Disabled
- **Check interval**: 15 minutes (or as needed)
- **Max parallel checks**: 10 (sufficient for scheduled checks)

### For High-frequency Monitoring
- **Continuous monitoring**: Enabled
- **Min check interval**: 30 seconds (minimum recommended)
- **Max parallel checks**: 5-10 (to avoid overwhelming DNS servers)

## Troubleshooting

### Continuous Monitoring Not Starting
1. Check if it's enabled in Monitor Settings
2. Verify Celery worker is running
3. Check Django logs for error messages
4. Ensure database connectivity

### Rate Limiting Too Aggressive
1. Increase `min_check_interval_seconds` in settings
2. Monitor system load and adjust accordingly
3. Consider reducing `max_parallel_checks`

### High Resource Usage
1. Increase `min_check_interval_seconds`
2. Reduce `max_parallel_checks`
3. Switch to periodic monitoring for lower resource usage
4. Monitor DNS timeout settings

## Migration Notes

### Existing Installations
- New fields are added with safe defaults
- Continuous monitoring is disabled by default
- Existing periodic monitoring continues to work unchanged
- No manual intervention required for upgrades

### Production Upgrade Steps
1. Deploy new code
2. Run database migrations: `dokku run dns-checker python manage.py migrate`
3. Optionally configure continuous monitoring via admin panel
4. Test monitoring mode changes in admin interface
