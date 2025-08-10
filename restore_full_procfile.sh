#!/bin/bash

# Script to restore full functionality after safe deployment

echo "🔄 Restoring Full Procfile with Background Tasks"
echo "==============================================="

# Check if backup exists
if [ ! -f Procfile.backup ]; then
    echo "❌ No Procfile.backup found. Creating standard Procfile..."
    cat > Procfile << EOF
web: gunicorn dns_checker.wsgi --log-file -
worker: celery -A dns_checker worker --loglevel=info
beat: celery -A dns_checker beat --loglevel=info
release: python manage.py migrate --noinput
EOF
else
    # Restore from backup
    cp Procfile.backup Procfile
    echo "✅ Restored Procfile from backup"
fi

# Commit the full Procfile
git add Procfile
git commit -m "restore: full Procfile with background tasks"

echo ""
echo "🚀 Deploying with full configuration..."
git push dokku main

# Check deployment status
if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Full deployment successful!"
    echo ""
    echo "📝 Verify functionality:"
    echo "   1. Check web interface is working"
    echo "   2. Check background monitoring is running"
    echo "   3. Monitor logs: dokku logs dns-checker -t"
    echo ""
    echo "🎯 Your DNS monitoring is now fully operational!"
else
    echo ""
    echo "❌ Full deployment failed. You may need to:"
    echo "   1. Check database connectivity"
    echo "   2. Check Redis connectivity"
    echo "   3. Review Dokku logs: dokku logs dns-checker"
    exit 1
fi
