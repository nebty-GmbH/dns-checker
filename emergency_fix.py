#!/usr/bin/env python
"""
Emergency fix for DNS Checker disk I/O issues.

This script implements immediate optimizations to reduce database writes
and improve performance on staging servers with high domain counts.
"""

import os
import sys

import django

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dns_checker.settings")
django.setup()

from monitor.models import MonitorSettings  # noqa: E402


def emergency_fix():
    """Apply emergency fixes to reduce disk I/O"""
    print("🚨 APPLYING EMERGENCY FIXES...")

    # Get or create settings
    settings = MonitorSettings.get_settings()

    # Disable continuous monitoring immediately
    settings.continuous_monitoring_enabled = False

    # Increase check intervals dramatically
    settings.check_interval_minutes = 60  # From 15 to 60 minutes
    settings.min_check_interval_seconds = 3600  # From 60 to 1 hour

    # Reduce parallel checks
    settings.max_parallel_checks = 5  # From 10 to 5

    # Increase DNS timeout to reduce retries
    settings.dns_timeout_seconds = 10  # Reduced from 30 to 10

    settings.save()

    print("✅ Emergency fixes applied:")
    print("   - Continuous monitoring: DISABLED")
    print(f"   - Check interval: {settings.check_interval_minutes} minutes")
    print(f"   - Min check interval: {settings.min_check_interval_seconds} seconds")
    print(f"   - Max parallel checks: {settings.max_parallel_checks}")
    print(f"   - DNS timeout: {settings.dns_timeout_seconds} seconds")

    print("\n🔄 NEXT STEPS:")
    print("1. Restart Celery workers: sudo systemctl restart celery")
    print("2. Restart Celery beat: sudo systemctl restart celery-beat")
    print("3. Monitor system load and disk I/O")


if __name__ == "__main__":
    emergency_fix()
