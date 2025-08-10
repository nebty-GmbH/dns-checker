#!/bin/bash

# Production Cleanup Script for DNS Checker
# Safely cleans up no-change RecordLog entries to reduce disk I/O

set -e  # Exit on any error

echo "🧹 DNS Checker Database Cleanup Script"
echo "======================================"

# Configuration
KEEP_DAYS=7
BATCH_SIZE=1000
DRY_RUN=false
FORCE=false
BACKGROUND=true

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --sync)
            BACKGROUND=false
            shift
            ;;
        --days)
            KEEP_DAYS="$2"
            shift 2
            ;;
        --batch-size)
            BATCH_SIZE="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --dry-run      Show what would be deleted without deleting"
            echo "  --force        Skip confirmation prompts"
            echo "  --sync         Run synchronously instead of background task"
            echo "  --days N       Keep records from last N days (default: 7)"
            echo "  --batch-size N Process N records per batch (default: 1000)"
            echo "  --help         Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --dry-run                    # See what would be cleaned"
            echo "  $0 --days 3 --force            # Clean records older than 3 days"
            echo "  $0 --sync --batch-size 500     # Run synchronously with smaller batches"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo "📋 Configuration:"
echo "   Keep records from last: $KEEP_DAYS days"
echo "   Batch size: $BATCH_SIZE"
echo "   Mode: $([ "$BACKGROUND" = true ] && echo "Background task" || echo "Synchronous")"
echo "   Dry run: $DRY_RUN"
echo ""

# Check if Django is available
if ! python manage.py check --quiet; then
    echo "❌ Django check failed. Make sure you're in the correct directory and environment."
    exit 1
fi

# Build command arguments
CMD_ARGS="--keep-recent-days $KEEP_DAYS --batch-size $BATCH_SIZE"

if [ "$DRY_RUN" = true ]; then
    CMD_ARGS="$CMD_ARGS --dry-run"
fi

if [ "$FORCE" = true ]; then
    CMD_ARGS="$CMD_ARGS --force"
fi

if [ "$BACKGROUND" = true ] && [ "$DRY_RUN" = false ]; then
    CMD_ARGS="$CMD_ARGS --background"
fi

echo "🚀 Running cleanup command..."
echo "Command: python manage.py cleanup_no_change_logs $CMD_ARGS"
echo ""

# Execute the cleanup
python manage.py cleanup_no_change_logs $CMD_ARGS

echo ""
echo "✅ Cleanup script completed!"

# Show follow-up instructions for background tasks
if [ "$BACKGROUND" = true ] && [ "$DRY_RUN" = false ]; then
    echo ""
    echo "📊 Monitor background task with:"
    echo "   celery -A dns_checker inspect active"
    echo "   tail -f dns_checker.log | grep cleanup"
    echo ""
    echo "🔍 Check task status with:"
    echo "   python manage.py shell -c \"from monitor.tasks import cleanup_no_change_logs_background; print('Task registered:', hasattr(cleanup_no_change_logs_background, 'delay'))\""
fi

echo ""
echo "🎯 Next steps:"
echo "   1. Monitor disk I/O: iostat -x 1"
echo "   2. Check database size reduction"
echo "   3. Verify continuous monitoring still works"
echo "   4. Consider running cleanup regularly (weekly/monthly)"
