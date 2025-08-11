# Database Cleanup Implementation

## 🎯 **Problem Solved**

After implementing smart change detection, your database contains millions of unnecessary RecordLog entries where `is_change=False`. These entries are consuming massive disk space and contributing to the I/O overload.

## 🛠️ **Solutions Provided**

### **1. Management Command (Small to Medium Datasets)**
```bash
# Test what would be cleaned up
python manage.py cleanup_no_change_logs --dry-run

# Clean up records older than 7 days (default)
python manage.py cleanup_no_change_logs

# Clean up records older than 3 days with smaller batches
python manage.py cleanup_no_change_logs --keep-recent-days 3 --batch-size 500

# Force cleanup without prompts
python manage.py cleanup_no_change_logs --force
```

### **2. Background Celery Task (Large Datasets - RECOMMENDED)**
```bash
# Queue background cleanup task (non-blocking)
python manage.py cleanup_no_change_logs --background

# Monitor background task progress
celery -A dns_checker inspect active
tail -f dns_checker.log | grep cleanup
```

### **3. Production Script (Easy Deployment)**
```bash
# Test what would be cleaned
./production_cleanup.sh --dry-run

# Run production cleanup (background by default)
./production_cleanup.sh --force

# Run synchronously with custom settings
./production_cleanup.sh --sync --days 3 --batch-size 500
```

## 🔒 **Safety Features**

### **Data Preservation**
- ✅ **All change records preserved** (`is_change=True`)
- ✅ **All error records preserved** (important for debugging)
- ✅ **Most recent entry per domain preserved** (maintains consistency)
- ✅ **Recent records preserved** (configurable, default 7 days)

### **Performance Protection**
- ✅ **Batched processing** (default 1000 records per batch)
- ✅ **Transaction safety** (rollback on errors)
- ✅ **Progress tracking** (for background tasks)
- ✅ **Database breathing room** (delays between batches)

### **Operational Safety**
- ✅ **Dry-run mode** (test before executing)
- ✅ **Confirmation prompts** (prevent accidents)
- ✅ **Comprehensive logging** (audit trail)
- ✅ **Error handling** (graceful failures)

## 📊 **Expected Impact**

### **For 20k Domains with Continuous Monitoring**

**Before Cleanup:**
- RecordLog entries: ~10-50 million
- Database size: 5-25 GB
- Daily growth: 1-5 GB

**After Cleanup:**
- RecordLog entries: ~100k-1M (95%+ reduction)
- Database size: 100-500 MB (90%+ reduction)
- Daily growth: 50-200 MB (90%+ reduction)

## 🚀 **Deployment Recommendations**

### **Phase 1: Test Run**
```bash
# On staging server
./production_cleanup.sh --dry-run
```

### **Phase 2: Small Cleanup**
```bash
# Clean recent data first (safer)
./production_cleanup.sh --days 1 --force
```

### **Phase 3: Full Cleanup**
```bash
# Clean older data (main space savings)
./production_cleanup.sh --days 7 --force
```

### **Phase 4: Monitor Results**
```bash
# Check database size reduction
du -sh /path/to/database

# Monitor disk I/O improvement
iostat -x 1

# Verify functionality
tail -f dns_checker.log
```

## ⚙️ **Background Task Monitoring**

### **Check Task Status**
```bash
# List active tasks
celery -A dns_checker inspect active

# Check task progress
celery -A dns_checker events

# View task results
python manage.py shell -c "
from django_celery_results.models import TaskResult
recent_tasks = TaskResult.objects.filter(task_name__contains='cleanup').order_by('-date_created')[:5]
for task in recent_tasks:
    print(f'{task.task_id}: {task.status} - {task.result}')
"
```

### **Task Progress Example**
```json
{
  "state": "PROGRESS",
  "meta": {
    "current": 50000,
    "total": 200000,
    "batch": 50,
    "percentage": 25
  }
}
```

## 🔄 **Ongoing Maintenance**

### **Weekly Cleanup (Recommended)**
```bash
# Add to crontab
0 2 * * 0 cd /path/to/dns_checker && ./production_cleanup.sh --force --days 7
```

### **Monthly Deep Cleanup**
```bash
# Add to crontab
0 3 1 * * cd /path/to/dns_checker && ./production_cleanup.sh --force --days 30
```

## 🚨 **Troubleshooting**

### **If Background Task Fails**
```bash
# Check Celery worker status
systemctl status celery-worker

# Restart workers
systemctl restart celery-worker

# Clear failed tasks
celery -A dns_checker purge
```

### **If Database Locks Occur**
```bash
# Reduce batch size
./production_cleanup.sh --batch-size 100

# Run during low-traffic hours
./production_cleanup.sh --force
```

### **If Too Much Data Lost**
```bash
# Restore from backup
# The script preserves important data, but backups are always recommended

# Verify preserved data
python manage.py shell -c "
from monitor.models import RecordLog
print('Change records:', RecordLog.objects.filter(is_change=True).count())
print('Error records:', RecordLog.objects.exclude(error_message__isnull=True).count())
"
```

## 📈 **Success Metrics**

After cleanup, you should see:
- ✅ **Disk I/O reduced from 1.5-2 GBps to <500 MBps**
- ✅ **Database size reduced by 80-95%**
- ✅ **Faster database queries**
- ✅ **Reduced backup times**
- ✅ **Server responsiveness improved**
- ✅ **Real-time monitoring still functional**

The cleanup tools provided handle the massive data inconsistency safely while preserving all critical monitoring functionality!
