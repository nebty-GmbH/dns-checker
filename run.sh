#!/bin/bash

# DNS Checker Setup and Run Script
# This script helps you get started with the DNS A-Record Change Monitor

set -e

echo "🔍 DNS A-Record Change Monitor Setup"
echo "======================================"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "Please run: python3 -m venv venv"
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

echo "✅ Virtual environment activated"

# Check if Redis is running
if ! pgrep -x "redis-server" > /dev/null; then
    echo "⚠️  Redis server is not running!"
    echo "Please start Redis with: redis-server"
    echo "Or install Redis: brew install redis (macOS) or apt-get install redis-server (Ubuntu)"
fi

# Function to create superuser if needed
create_superuser() {
    echo "👤 Creating Django superuser..."
    python manage.py createsuperuser --noinput --username admin --email admin@example.com || true
}

# Function to run the Django development server
run_server() {
    echo "🚀 Starting Django development server..."
    echo "Access the admin at: http://localhost:8000/admin/"
    echo "Username: admin"
    echo "Press Ctrl+C to stop"
    python manage.py runserver
}

# Function to run Celery worker
run_worker() {
    echo "🔄 Starting Celery worker..."
    echo "Press Ctrl+C to stop"
    celery -A dns_checker worker --loglevel=info
}

# Function to run Celery beat scheduler
run_beat() {
    echo "⏰ Starting Celery Beat scheduler..."
    echo "This will check domains every 15 minutes"
    echo "Press Ctrl+C to stop"
    celery -A dns_checker beat --loglevel=info
}

# Function to check all domains manually
check_domains() {
    echo "🔍 Checking all active domains..."
    python manage.py check_domains --all
}

# Function to import domains from file
import_domains() {
    if [ -z "$1" ]; then
        echo "Usage: $0 import /path/to/domains.txt"
        exit 1
    fi
    echo "📥 Importing domains from $1..."
    python manage.py import_domains "$1"
}

# Main menu
case "${1:-help}" in
    "setup")
        echo "🔧 Setting up DNS Checker..."
        python manage.py migrate
        create_superuser
        if [ -f "sample_domains.txt" ]; then
            python manage.py import_domains sample_domains.txt
        fi
        echo "✅ Setup complete!"
        echo "Run './run.sh server' to start the Django server"
        ;;
    "server")
        run_server
        ;;
    "worker")
        run_worker
        ;;
    "beat")
        run_beat
        ;;
    "check")
        check_domains
        ;;
    "import")
        import_domains "$2"
        ;;
    "help"|*)
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  setup          - Initial setup (migrate, create superuser, import sample domains)"
        echo "  server         - Start Django development server"
        echo "  worker         - Start Celery worker"
        echo "  beat           - Start Celery Beat scheduler"
        echo "  check          - Check all domains manually"
        echo "  import [file]  - Import domains from text file"
        echo "  help           - Show this help message"
        echo ""
        echo "For production, you'll need to run worker and beat in separate terminals:"
        echo "Terminal 1: ./run.sh worker"
        echo "Terminal 2: ./run.sh beat"
        echo "Terminal 3: ./run.sh server"
        ;;
esac
