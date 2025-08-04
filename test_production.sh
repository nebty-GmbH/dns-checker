#!/bin/bash

# Production Test Script
# This script helps test the production configuration locally

set -e

echo "🧪 Testing Production Configuration Locally"
echo "============================================"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "Please run: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Install production dependencies if not already installed
echo "📦 Installing production dependencies..."
pip install -r requirements.txt

# Set production-like environment variables
export SECRET_KEY="test-production-secret-key-12345"
export DEBUG=False
export ALLOWED_HOSTS="localhost,127.0.0.1,0.0.0.0"
export DATABASE_URL=""  # Use SQLite for testing
export REDIS_URL="redis://localhost:6379/1"  # Use different Redis DB

echo "✅ Environment configured for production testing"

# Function to test database
test_database() {
    echo "🗄️  Testing database connection..."
    python manage.py check --database default
    echo "✅ Database connection OK"
}

# Function to test static files
test_static_files() {
    echo "📁 Testing static files collection..."
    python manage.py collectstatic --noinput --clear
    echo "✅ Static files collected successfully"
}

# Function to test Celery configuration
test_celery() {
    echo "🔄 Testing Celery configuration..."
    
    # Test Celery can import tasks
    python -c "
from monitor.tasks import check_domain_a_records, schedule_domain_checks
print('✅ Celery tasks imported successfully')
"
    
    # Test Redis connection
    python -c "
import redis
import os
redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379/1')
r = redis.from_url(redis_url)
r.ping()
print('✅ Redis connection OK')
"
}

# Function to test DNS functionality
test_dns() {
    echo "🔍 Testing DNS functionality..."
    python manage.py check_domains --domain google.com
    echo "✅ DNS checking functionality OK"
}

# Function to run security checks
test_security() {
    echo "🔒 Running security checks..."
    python manage.py check --deploy
}

# Main test menu
case "${1:-all}" in
    "database")
        test_database
        ;;
    "static")
        test_static_files
        ;;
    "celery")
        test_celery
        ;;
    "dns")
        test_dns
        ;;
    "security")
        test_security
        ;;
    "all")
        echo "🚀 Running all production tests..."
        test_database
        test_static_files
        test_celery
        test_dns
        test_security
        echo ""
        echo "🎉 All tests passed! Ready for production deployment."
        echo ""
        echo "Next steps:"
        echo "1. Set up Dokku server with postgres and redis plugins"
        echo "2. Follow DOKKU_DEPLOYMENT.md for complete deployment guide"
        echo "3. Set production environment variables"
        echo "4. Deploy with: git push dokku main"
        ;;
    "help"|*)
        echo "Usage: $0 [test]"
        echo ""
        echo "Tests:"
        echo "  database  - Test database configuration"
        echo "  static    - Test static files collection"
        echo "  celery    - Test Celery configuration"
        echo "  dns       - Test DNS functionality"
        echo "  security  - Run Django security checks"
        echo "  all       - Run all tests (default)"
        echo "  help      - Show this help message"
        ;;
esac
