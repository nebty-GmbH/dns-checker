# 📋 Dokku Deployment Checklist

## Pre-Deployment

### ✅ Code Preparation
- [ ] All code committed to git repository
- [ ] Production dependencies added to requirements.txt
- [ ] Procfile created with web, worker, and beat processes
- [ ] Django settings configured for production
- [ ] Static files configuration added (WhiteNoise)
- [ ] Database URL parsing implemented
- [ ] Security settings configured

### ✅ Local Testing
- [ ] Run `./test_production.sh` to verify production configuration
- [ ] Test with DEBUG=False locally
- [ ] Verify static files collection works
- [ ] Test Celery tasks functionality
- [ ] Run Django security checks

## Dokku Server Setup

### ✅ Server Prerequisites
- [ ] Dokku installed and configured
- [ ] Domain name configured and pointing to server
- [ ] SSH access to Dokku server established

### ✅ Required Plugins
- [ ] Install postgres plugin: `dokku plugin:install https://github.com/dokku/dokku-postgres.git`
- [ ] Install redis plugin: `dokku plugin:install https://github.com/dokku/dokku-redis.git`
- [ ] Install letsencrypt plugin: `dokku plugin:install https://github.com/dokku/dokku-letsencrypt.git`

### ✅ Application Setup
- [ ] Create app: `dokku apps:create dns-checker`
- [ ] Set domain: `dokku domains:set dns-checker your-domain.com`
- [ ] Create PostgreSQL database: `dokku postgres:create dns-checker-db`
- [ ] Link database: `dokku postgres:link dns-checker-db dns-checker`
- [ ] Create Redis instance: `dokku redis:create dns-checker-redis`
- [ ] Link Redis: `dokku redis:link dns-checker-redis dns-checker`

## Environment Configuration

### ✅ Required Environment Variables
- [ ] `SECRET_KEY`: Generate secure secret key
- [ ] `DEBUG`: Set to False
- [ ] `ALLOWED_HOSTS`: Set to your domain(s)
- [ ] `DOKKU_DOMAIN`: Set to primary domain

### ✅ Environment Commands
```bash
dokku config:set dns-checker SECRET_KEY="your-secure-secret-key"
dokku config:set dns-checker DEBUG=False
dokku config:set dns-checker ALLOWED_HOSTS="your-domain.com,www.your-domain.com"
dokku config:set dns-checker DOKKU_DOMAIN="your-domain.com"
```

## Deployment

### ✅ Deploy Application
- [ ] Add Dokku remote: `git remote add dokku dokku@your-server.com:dns-checker`
- [ ] Deploy: `git push dokku main`
- [ ] Verify deployment succeeded

### ✅ Post-Deployment Setup
- [ ] Run migrations: `dokku run dns-checker python manage.py migrate`
- [ ] Create superuser: `dokku run dns-checker python manage.py createsuperuser`
- [ ] Import domains: `dokku run dns-checker python manage.py import_domains sample_domains.txt`

### ✅ Process Scaling
- [ ] Scale web process: `dokku ps:scale dns-checker web=1`
- [ ] Scale worker process: `dokku ps:scale dns-checker worker=1`
- [ ] Scale beat process: `dokku ps:scale dns-checker beat=1`

## SSL Configuration

### ✅ SSL Certificate
- [ ] Set email: `dokku letsencrypt:set dns-checker email your-email@example.com`
- [ ] Enable SSL: `dokku letsencrypt:enable dns-checker`
- [ ] Auto-renew: `dokku letsencrypt:cron-job --add`

## Verification

### ✅ Application Health
- [ ] Check processes: `dokku ps:report dns-checker`
- [ ] Verify all processes running (web, worker, beat)
- [ ] Check logs: `dokku logs dns-checker --tail`

### ✅ Functionality Tests
- [ ] Access web interface: `https://your-domain.com/admin/`
- [ ] Login with superuser credentials
- [ ] Add test domain in admin
- [ ] Manual DNS check: `dokku run dns-checker python manage.py check_domains --domain google.com`
- [ ] Verify RecordLog entries are created

### ✅ Celery Verification
- [ ] Check worker logs: `dokku logs dns-checker --ps worker --tail`
- [ ] Check beat logs: `dokku logs dns-checker --ps beat --tail`
- [ ] Verify scheduled tasks are running (check every 15 minutes)

## Monitoring Setup

### ✅ Log Monitoring
- [ ] Set up log rotation if needed
- [ ] Configure external log monitoring (optional)
- [ ] Set up alerts for application errors

### ✅ Health Monitoring
- [ ] Monitor process uptime
- [ ] Monitor DNS check success rate
- [ ] Monitor database performance
- [ ] Monitor Redis connectivity

## Production Maintenance

### ✅ Backup Strategy
- [ ] Database backup schedule: `dokku postgres:export dns-checker-db`
- [ ] Test backup restoration process
- [ ] Document backup procedures

### ✅ Update Process
- [ ] Document deployment update process
- [ ] Test update procedure in staging
- [ ] Plan for zero-downtime deployments

### ✅ Security
- [ ] Regular security updates
- [ ] Monitor for dependency vulnerabilities
- [ ] Review access logs
- [ ] Audit user access

## Troubleshooting Reference

### ✅ Common Commands
```bash
# Check application status
dokku ps:report dns-checker

# View logs
dokku logs dns-checker --tail
dokku logs dns-checker --ps worker
dokku logs dns-checker --ps beat

# Restart application
dokku ps:restart dns-checker

# Check configuration
dokku config dns-checker

# Access shell
dokku run dns-checker python manage.py shell

# Manual domain check
dokku run dns-checker python manage.py check_domains --all
```

### ✅ Emergency Procedures
- [ ] How to restart services
- [ ] How to rollback deployment
- [ ] How to scale processes
- [ ] Emergency contact information

## Success Criteria

### ✅ Deployment Complete When:
- [ ] All processes (web, worker, beat) are running
- [ ] HTTPS is working with valid certificate
- [ ] Admin interface is accessible
- [ ] DNS checks are working automatically every 15 minutes
- [ ] RecordLog shows successful DNS checks
- [ ] Domain management works through admin
- [ ] Error handling is working (test with invalid domain)

## Documentation

### ✅ Team Documentation
- [ ] Update team with new production URLs
- [ ] Share admin credentials securely
- [ ] Document operational procedures
- [ ] Create runbook for common tasks

---

## 🎉 Deployment Complete!

Once all items are checked, your DNS A-Record Monitor is successfully deployed and ready for production use.

**Admin URL**: https://your-domain.com/admin/
**Monitoring**: Check RecordLog for DNS changes every 15 minutes
**Management**: Use Django admin for domain management
