#!/bin/bash

# Safe deployment script for DNS Checker when database is unlinked

echo "🚨 Safe Deployment Mode - Database and Background Tasks Disabled"
echo "================================================================"

# Backup current Procfile
if [ -f Procfile ]; then
    cp Procfile Procfile.backup
    echo "✅ Backed up current Procfile to Procfile.backup"
fi

# Use safe Procfile (web only)
cp Procfile.safe Procfile
echo "✅ Using safe Procfile (web process only)"

# Set environment variable to disable monitoring
export DISABLE_MONITORING=true

# Commit the safe Procfile
git add Procfile
git commit -m "temp: use safe Procfile for deployment without database"

echo ""
echo "🚀 Deploying with safe configuration..."
git push dokku main

# Check deployment status
if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Safe deployment successful!"
    echo ""
    echo "📝 Next steps:"
    echo "   1. Your app is now running with SQLite (web interface only)"
    echo "   2. No background monitoring is running"
    echo "   3. When ready to restore full functionality:"
    echo "      - Relink your PostgreSQL database"
    echo "      - Relink Redis if needed"
    echo "      - Run: ./restore_full_procfile.sh"
    echo ""
    echo "🌐 Your web interface should be accessible now"
else
    echo ""
    echo "❌ Deployment failed. Restoring original Procfile..."
    if [ -f Procfile.backup ]; then
        cp Procfile.backup Procfile
        git add Procfile
        git commit -m "restore: revert to original Procfile after failed deployment"
    fi
    exit 1
fi
