#!/usr/bin/env python
"""
Script to debug production database snapshot issues
"""
import os
from datetime import timedelta

import django
from django.utils import timezone

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dns_checker.settings")
django.setup()

from monitor.models import Domain, DomainSnapshot, RecordLog  # noqa: E402

print("=== PRODUCTION DATABASE ANALYSIS ===")
print(f"Total domains: {Domain.objects.count()}")
print(f"Active domains: {Domain.objects.filter(is_active=True).count()}")
print(f"Total record logs: {RecordLog.objects.count()}")
print(f"Total snapshots: {DomainSnapshot.objects.count()}")
print()

# Look for IP changes without snapshots
print("=== IP CHANGES WITHOUT SNAPSHOTS ===")
total_changes = RecordLog.objects.filter(is_change=True).count()
changes_without_snapshots = RecordLog.objects.filter(
    is_change=True, snapshot__isnull=True
).count()

print(f"Total IP changes: {total_changes}")
print(f"IP changes without snapshots: {changes_without_snapshots}")

if total_changes > 0:
    missing_percentage = changes_without_snapshots / total_changes * 100
    print(f"Missing snapshot percentage: {missing_percentage:.1f}%")
print()

# Show recent changes without snapshots
print("Recent 5 changes without snapshots:")
recent_changes_no_snapshots = RecordLog.objects.filter(
    is_change=True, snapshot__isnull=True
).order_by("-timestamp")[:5]

for log in recent_changes_no_snapshots:
    print(f"  {log.domain.name}: {log.timestamp} - {log.ips}")
print()

# Check existing snapshots
print("=== EXISTING SNAPSHOTS ANALYSIS ===")
snapshots_with_record_log = DomainSnapshot.objects.filter(
    record_log__isnull=False
).count()
initial_snapshots = DomainSnapshot.objects.filter(is_initial_snapshot=True).count()
change_snapshots = DomainSnapshot.objects.filter(is_initial_snapshot=False).count()

print(f"Snapshots linked to record logs: {snapshots_with_record_log}")
print(f"Initial snapshots: {initial_snapshots}")
print(f"Change snapshots: {change_snapshots}")
print()

# Check recent activity
print("=== RECENT ACTIVITY (Last 24 hours) ===")
last_24h = timezone.now() - timedelta(hours=24)
recent_logs = RecordLog.objects.filter(timestamp__gte=last_24h)
recent_changes = recent_logs.filter(is_change=True)
recent_snapshots = DomainSnapshot.objects.filter(timestamp__gte=last_24h)

print(f"Logs in last 24h: {recent_logs.count()}")
print(f"Changes in last 24h: {recent_changes.count()}")
print(f"Snapshots in last 24h: {recent_snapshots.count()}")
