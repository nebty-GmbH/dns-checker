# 🚀 Dokku Deployment Guide for DNS A-Record Monitor

This guide walks you through deploying the DNS A-Record Monitor to a Dokku server.

## Prerequisites

- Dokku server set up and running
- Domain name pointing to your Dokku server
- SSH access to your Dokku server

## 1. Server Setup (On Dokku Server)

### Install Required Plugins

```bash
# PostgreSQL plugin for database
sudo dokku plugin:install https://github.com/dokku/dokku-postgres.git

# Redis plugin for Celery broker
sudo dokku plugin:install https://github.com/dokku/dokku-redis.git

# Letsencrypt for SSL certificates
sudo dokku plugin:install https://github.com/dokku/dokku-letsencrypt.git
```

### Create the Application

```bash
# Create the app
dokku apps:create dns-checker

# Set domain
dokku domains:set dns-checker your-domain.com

# Create and link PostgreSQL database
dokku postgres:create dns-checker-db
dokku postgres:link dns-checker-db dns-checker

# Create and link Redis instance
dokku redis:create dns-checker-redis
dokku redis:link dns-checker-redis dns-checker
```

## 2. Configure Environment Variables

```bash
# Essential Django settings
dokku config:set dns-checker SECRET_KEY="your-very-secure-secret-key-here"
dokku config:set dns-checker DEBUG=False
dokku config:set dns-checker ALLOWED_HOSTS="your-domain.com,www.your-domain.com"
dokku config:set dns-checker DOKKU_DOMAIN="your-domain.com"

# Optional security settings (recommended for production)
dokku config:set dns-checker SECURE_SSL_REDIRECT=True
dokku config:set dns-checker SECURE_HSTS_SECONDS=31536000
```

## 3. Deploy the Application (From Your Local Machine)

### Add Dokku Remote

```bash
# In your project directory
git remote add dokku dokku@your-server.com:dns-checker
```

### Deploy

```bash
# Deploy to Dokku
git push dokku main

# Or if you're on a different branch
git push dokku your-branch:main
```

## 4. Post-Deployment Setup

### Run Database Migrations

```bash
# Run Django migrations
dokku run dns-checker python manage.py migrate

# Create Django superuser
dokku run dns-checker python manage.py createsuperuser

# Import sample domains (optional)
dokku run dns-checker python manage.py import_domains sample_domains.txt
```

### Scale Celery Processes

```bash
# Scale web process (if needed)
dokku ps:scale dns-checker web=1

# Scale worker process for DNS checking
dokku ps:scale dns-checker worker=1

# Scale beat process for scheduling
dokku ps:scale dns-checker beat=1
```

### Set Up SSL Certificate

```bash
# Configure Let's Encrypt
dokku letsencrypt:set dns-checker email your-email@example.com
dokku letsencrypt:enable dns-checker

# Auto-renew certificates
dokku letsencrypt:cron-job --add
```

## 5. Verify Deployment

### Check Application Status

```bash
# Check if all processes are running
dokku ps:report dns-checker

# Check logs
dokku logs dns-checker --tail

# Check specific process logs
dokku logs dns-checker --ps web
dokku logs dns-checker --ps worker
dokku logs dns-checker --ps beat
```

### Test the Application

1. **Web Interface**: Visit `https://your-domain.com/admin/`
2. **Login**: Use the superuser credentials you created
3. **Add Domains**: Add domains to monitor
4. **Check Logs**: Monitor the RecordLog to see DNS checks

### Test DNS Checking

```bash
# Manually trigger a domain check
dokku run dns-checker python manage.py check_domains --domain google.com

# Check all domains
dokku run dns-checker python manage.py check_domains --all
```

## 6. Monitoring and Maintenance

### View Process Status

```bash
# Check all processes
dokku ps:report dns-checker

# Restart specific processes if needed
dokku ps:restart dns-checker
dokku ps:restart dns-checker.worker.1
dokku ps:restart dns-checker.beat.1
```

### Database Management

```bash
# Backup database
dokku postgres:export dns-checker-db > backup.sql

# Access database console
dokku postgres:connect dns-checker-db
```

### Log Monitoring

```bash
# Follow live logs
dokku logs dns-checker --tail

# Check worker logs specifically
dokku logs dns-checker --ps worker --tail

# Check beat scheduler logs
dokku logs dns-checker --ps beat --tail
```

## 7. Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | Yes | - | Django secret key |
| `DEBUG` | No | False | Django debug mode |
| `ALLOWED_HOSTS` | Yes | - | Comma-separated allowed hosts |
| `DOKKU_DOMAIN` | No | - | Primary domain name |
| `DATABASE_URL` | Auto | - | Set automatically by postgres plugin |
| `REDIS_URL` | Auto | - | Set automatically by redis plugin |
| `SECURE_SSL_REDIRECT` | No | True | Force HTTPS redirect |
| `SECURE_HSTS_SECONDS` | No | 31536000 | HSTS max age |

## 8. Troubleshooting

### Common Issues

1. **Application won't start**:
   ```bash
   dokku logs dns-checker --tail
   # Check for missing environment variables or database connection issues
   ```

2. **Celery workers not processing tasks**:
   ```bash
   dokku logs dns-checker --ps worker --tail
   # Ensure Redis is connected and worker process is running
   ```

3. **Beat scheduler not running**:
   ```bash
   dokku logs dns-checker --ps beat --tail
   # Check if beat process is scaled to 1
   ```

4. **DNS lookups failing**:
   ```bash
   dokku run dns-checker python manage.py check_domains --domain google.com
   # Test DNS resolution from the container
   ```

### Useful Commands

```bash
# Restart application
dokku ps:restart dns-checker

# Scale processes
dokku ps:scale dns-checker worker=2 beat=1 web=1

# Check environment variables
dokku config dns-checker

# Access application shell
dokku run dns-checker python manage.py shell

# Import domains from local file
cat domains.txt | dokku run dns-checker python manage.py import_domains -
```

## 9. Updating the Application

```bash
# Deploy updates
git push dokku main

# Run migrations if needed
dokku run dns-checker python manage.py migrate

# Restart processes
dokku ps:restart dns-checker
```

## 10. Production Considerations

1. **Scaling**: Adjust worker count based on domain volume
2. **Monitoring**: Set up external monitoring for the application
3. **Backups**: Regular database backups
4. **Security**: Keep dependencies updated
5. **Logging**: Consider external log aggregation
6. **Alerts**: Set up alerts for DNS change detection

Your DNS A-Record Monitor is now ready for production use on Dokku! 🎉
