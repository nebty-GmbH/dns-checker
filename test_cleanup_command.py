#!/usr/bin/env python3
"""
Test script for the cleanup_no_change_logs management command.
This helps verify the cleanup works correctly before running on production data.
"""

import os
from datetime import timedelta

import django
from django.core.management import call_command
from django.utils import timezone

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dns_checker.settings")
django.setup()

from monitor.models import Domain, RecordLog  # noqa: E402


def create_test_data():
    """Create test data to verify cleanup works correctly."""
    print("🧪 Creating test data...")

    # Create test domain
    domain, created = Domain.objects.get_or_create(
        name="test-cleanup.example.com",
        defaults={"is_active": True, "last_known_ips": "192.168.1.1"},
    )

    if created:
        print(f"   Created test domain: {domain.name}")
    else:
        print(f"   Using existing test domain: {domain.name}")

    # Create test RecordLog entries
    now = timezone.now()

    # Old entries that should be cleaned up
    old_no_change_entries = []
    for i in range(5):
        entry = RecordLog.objects.create(
            domain=domain,
            ips="192.168.1.1",
            is_change=False,
            timestamp=now - timedelta(days=10 + i),
        )
        old_no_change_entries.append(entry)

    # Recent entries that should be kept
    recent_no_change = RecordLog.objects.create(
        domain=domain,
        ips="192.168.1.1",
        is_change=False,
        timestamp=now - timedelta(days=3),
    )

    # Change entries that should always be kept
    change_entry = RecordLog.objects.create(
        domain=domain,
        ips="192.168.1.2",
        is_change=True,
        timestamp=now - timedelta(days=15),
    )

    # Error entries that should always be kept
    error_entry = RecordLog.objects.create(
        domain=domain,
        ips="",
        is_change=False,
        error_message="DNS timeout",
        timestamp=now - timedelta(days=12),
    )

    print(
        f"   Created {len(old_no_change_entries)} old no-change entries (should be cleaned)"
    )
    print("   Created 1 recent no-change entry (should be kept)")
    print("   Created 1 change entry (should be kept)")
    print("   Created 1 error entry (should be kept)")

    return domain, old_no_change_entries, recent_no_change, change_entry, error_entry


def test_dry_run():
    """Test the dry run functionality."""
    print("\n🔍 Testing dry run...")

    call_command(
        "cleanup_no_change_logs",
        "--dry-run",
        "--keep-recent-days=7",
        "--domain-id=1",  # Assuming test domain has ID 1
        verbosity=2,
    )


def test_actual_cleanup():
    """Test the actual cleanup with a specific domain."""
    print("\n🗑️  Testing actual cleanup...")

    # Get count before cleanup
    before_count = RecordLog.objects.filter(
        domain__name="test-cleanup.example.com"
    ).count()

    print(f"   Records before cleanup: {before_count}")

    # Run cleanup for test domain only
    test_domain = Domain.objects.filter(name="test-cleanup.example.com").first()
    if test_domain:
        call_command(
            "cleanup_no_change_logs",
            "--keep-recent-days=7",
            f"--domain-id={test_domain.pk}",
            "--force",
            verbosity=2,
        )

        # Get count after cleanup
        after_count = RecordLog.objects.filter(
            domain__name="test-cleanup.example.com"
        ).count()

        print(f"   Records after cleanup: {after_count}")
        print(f"   Records deleted: {before_count - after_count}")

        # Verify what remains
        remaining = RecordLog.objects.filter(
            domain__name="test-cleanup.example.com"
        ).order_by("-timestamp")

        print("   Remaining entries:")
        for entry in remaining:
            entry_type = "CHANGE" if entry.is_change else "NO-CHANGE"
            if entry.error_message:
                entry_type = "ERROR"
            days_ago = (timezone.now() - entry.timestamp).days
            print(f"     - {entry_type} from {days_ago} days ago")


def cleanup_test_data():
    """Remove test data."""
    print("\n🧹 Cleaning up test data...")

    test_domain = Domain.objects.filter(name="test-cleanup.example.com").first()
    if test_domain:
        RecordLog.objects.filter(domain=test_domain).delete()
        test_domain.delete()
        print("   Test data removed")


def main():
    """Run the test suite."""
    print("🧪 Testing cleanup_no_change_logs management command")
    print("=" * 60)

    try:
        # Create test data
        create_test_data()

        # Test dry run
        test_dry_run()

        # Test actual cleanup
        test_actual_cleanup()

        print("\n✅ All tests completed successfully!")

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback

        traceback.print_exc()

    finally:
        # Always clean up test data
        cleanup_test_data()


if __name__ == "__main__":
    main()
