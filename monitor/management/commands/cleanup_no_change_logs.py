"""
Management command to clean up RecordLog entries that have no changes.

This command removes RecordLog entries where is_change=False to reduce database size
and improve performance after implementing smart change detection.
"""

import logging
from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from monitor.models import Domain, RecordLog

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = """
    Clean up RecordLog entries that have no changes (is_change=False).

    This command helps reduce database size after implementing smart change detection.
    It preserves:
    - All entries where is_change=True (actual changes)
    - All entries with error_messages (errors are important)
    - The most recent entry for each domain (for consistency)
    - Recent entries (configurable via --keep-recent-days)
    """

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be deleted without actually deleting",
        )
        parser.add_argument(
            "--keep-recent-days",
            type=int,
            default=7,
            help="Keep no-change entries from the last N days (default: 7)",
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=1000,
            help="Number of records to delete per batch (default: 1000)",
        )
        parser.add_argument(
            "--domain-id",
            type=int,
            help="Clean up only for a specific domain ID",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Skip confirmation prompt",
        )
        parser.add_argument(
            "--background",
            action="store_true",
            help="Run as background Celery task (recommended for large datasets)",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        keep_recent_days = options["keep_recent_days"]
        batch_size = options["batch_size"]
        domain_id = options.get("domain_id")
        force = options["force"]
        background = options["background"]

        self.stdout.write(
            self.style.SUCCESS("🧹 Starting cleanup of no-change RecordLog entries")
        )

        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    "DRY RUN MODE - No actual deletions will be performed"
                )
            )

        # Calculate cutoff date
        cutoff_date = timezone.now() - timedelta(days=keep_recent_days)

        self.stdout.write(f"📅 Keeping entries newer than: {cutoff_date}")
        self.stdout.write(f"📦 Batch size: {batch_size}")

        try:
            # Build the base query for records to potentially delete
            base_query = RecordLog.objects.filter(
                is_change=False,  # Only no-change entries
                error_message__isnull=True,  # Exclude error entries
                timestamp__lt=cutoff_date,  # Only older entries
            )

            # Filter by domain if specified
            if domain_id:
                base_query = base_query.filter(domain_id=domain_id)
                self.stdout.write(f"🎯 Filtering for domain ID: {domain_id}")

            # Get total count
            total_candidates = base_query.count()

            if total_candidates == 0:
                self.stdout.write(
                    self.style.SUCCESS(
                        "✅ No records found that match cleanup criteria!"
                    )
                )
                return

            self.stdout.write(
                f"📊 Found {total_candidates:,} candidate records for deletion"
            )

            # Show some statistics
            self._show_statistics(domain_id, cutoff_date)

            # Get records that should be preserved (most recent per domain)
            self.stdout.write("🔍 Identifying records to preserve...")
            preserved_ids = self._get_records_to_preserve(domain_id, cutoff_date)

            # Exclude preserved records from deletion
            records_to_delete = base_query.exclude(id__in=preserved_ids)
            final_delete_count = records_to_delete.count()

            self.stdout.write(
                f"🛡️  Preserving {len(preserved_ids):,} most recent entries per domain"
            )
            self.stdout.write(
                f"🗑️  Final deletion count: {final_delete_count:,} records"
            )

            if final_delete_count == 0:
                self.stdout.write(
                    self.style.SUCCESS(
                        "✅ No records to delete after applying preservation rules!"
                    )
                )
                return

            # Estimate space savings
            self._estimate_space_savings(final_delete_count)

            # Handle background execution
            if background:
                if domain_id:
                    self.stdout.write(
                        self.style.ERROR(
                            "Background mode doesn't support --domain-id filter"
                        )
                    )
                    return

                if not force:
                    self.stdout.write(
                        self.style.WARNING(
                            f"\n🚀 This will queue a background task to delete {final_delete_count:,} records"
                        )
                    )
                    confirm = input("Queue background cleanup task? (y/N): ")
                    if confirm.lower() != "y":
                        self.stdout.write("❌ Operation cancelled")
                        return

                # Import the background task
                from monitor.tasks import cleanup_no_change_logs_background

                # Queue the background task
                task = cleanup_no_change_logs_background.delay(
                    days=keep_recent_days,
                    batch_size=batch_size,
                    keep_errors=True,  # Always keep errors for safety
                )

                self.stdout.write(
                    self.style.SUCCESS(
                        f"✅ Background cleanup task queued!\n"
                        f"   Task ID: {task.id}\n"
                        f"   Monitor with: celery -A dns_checker inspect active\n"
                        f"   Check logs for progress updates"
                    )
                )
                return

            # Confirmation for synchronous execution
            if not force and not dry_run:
                self.stdout.write(
                    self.style.WARNING(
                        f"\n⚠️  This will permanently delete {final_delete_count:,} RecordLog entries"
                    )
                )
                confirm = input("Continue? (y/N): ")
                if confirm.lower() != "y":
                    self.stdout.write("❌ Operation cancelled")
                    return

            # Perform the cleanup
            if dry_run:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"✅ DRY RUN: Would delete {final_delete_count:,} records"
                    )
                )
            else:
                deleted_count = self._perform_cleanup(records_to_delete, batch_size)
                self.stdout.write(
                    self.style.SUCCESS(
                        f"✅ Successfully deleted {deleted_count:,} no-change RecordLog entries"
                    )
                )

        except Exception as e:
            logger.exception("Error during cleanup")
            raise CommandError(f"Cleanup failed: {str(e)}")

    def _show_statistics(self, domain_id, cutoff_date):
        """Show database statistics before cleanup."""
        self.stdout.write("\n📈 Database Statistics:")

        # Total records
        total_records = RecordLog.objects.count()
        self.stdout.write(f"   Total RecordLog entries: {total_records:,}")

        # Records by type
        change_records = RecordLog.objects.filter(is_change=True).count()
        no_change_records = RecordLog.objects.filter(is_change=False).count()
        error_records = RecordLog.objects.filter(error_message__isnull=False).count()

        self.stdout.write(f"   Change records (preserved): {change_records:,}")
        self.stdout.write(f"   No-change records: {no_change_records:,}")
        self.stdout.write(f"   Error records (preserved): {error_records:,}")

        # Recent vs old
        recent_records = RecordLog.objects.filter(timestamp__gte=cutoff_date).count()
        old_records = RecordLog.objects.filter(timestamp__lt=cutoff_date).count()

        self.stdout.write(
            f"   Recent records (last {cutoff_date.strftime('%Y-%m-%d')}): {recent_records:,}"
        )
        self.stdout.write(f"   Older records: {old_records:,}")

    def _get_records_to_preserve(self, domain_id, cutoff_date):
        """Get IDs of records that should be preserved."""
        # For each domain, find the most recent no-change entry (even if old)
        # This ensures we don't lose the last known state

        domain_filter = {}
        if domain_id:
            domain_filter["id"] = domain_id

        domains = Domain.objects.filter(**domain_filter)
        preserved_ids = []

        for domain in domains:
            # Get the most recent no-change entry for this domain
            most_recent = (
                RecordLog.objects.filter(
                    domain=domain,
                    is_change=False,
                    error_message__isnull=True,
                )
                .order_by("-timestamp")
                .first()
            )

            if most_recent:
                preserved_ids.append(most_recent.pk)

        return preserved_ids

    def _estimate_space_savings(self, delete_count):
        """Estimate database space savings."""
        # Rough estimate: each RecordLog entry is about 200-500 bytes
        # Including indexes and overhead
        avg_size_bytes = 350
        estimated_savings_mb = (delete_count * avg_size_bytes) / (1024 * 1024)

        self.stdout.write(f"💾 Estimated space savings: ~{estimated_savings_mb:.1f} MB")

    def _perform_cleanup(self, records_to_delete, batch_size):
        """Perform the actual cleanup in batches."""
        total_deleted = 0

        self.stdout.write("🗑️  Starting deletion in batches...")

        while True:
            with transaction.atomic():
                # Get a batch of IDs to delete
                batch_ids = list(
                    records_to_delete.values_list("id", flat=True)[:batch_size]
                )

                if not batch_ids:
                    break

                # Delete the batch
                deleted_count, _ = RecordLog.objects.filter(id__in=batch_ids).delete()
                total_deleted += deleted_count

                self.stdout.write(
                    f"   Deleted batch: {deleted_count:,} records (total: {total_deleted:,})",
                    ending="\r",
                )

        self.stdout.write("")  # New line after progress updates
        return total_deleted
