import time

from django.core.management.base import BaseCommand
from django.db import models

from monitor.models import IPWhoisInfo
from monitor.tasks import fetch_ip_whois_info


class Command(BaseCommand):
    help = """
    Refresh WHOIS records to update missing organization data.

    This command uses the improved WHOIS parsing to update existing records
    that may have missing organization, ISP, or country information due to
    the previous parsing limitations with RDAP responses.
    """

    def add_arguments(self, parser):
        parser.add_argument(
            "--missing-org-only",
            action="store_true",
            help="Only update records where organization is None/empty",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be updated without making changes",
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=50,
            help="Number of records to process in each batch (default: 50)",
        )
        parser.add_argument(
            "--delay",
            type=float,
            default=1.0,
            help="Delay in seconds between WHOIS lookups to avoid rate limiting (default: 1.0)",
        )
        parser.add_argument(
            "--max-records",
            type=int,
            help="Maximum number of records to process (useful for testing)",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Skip confirmation prompt and proceed automatically",
        )

    def handle(self, *args, **options):
        self.stdout.write("=== WHOIS Records Refresh Command ===")

        # Build the queryset based on options
        queryset = IPWhoisInfo.objects.all()

        if options["missing_org_only"]:
            queryset = queryset.filter(
                models.Q(organization__isnull=True)
                | models.Q(organization="")
                | models.Q(organization="None")
            )
            self.stdout.write("Filtering to records with missing organization data...")

        # Order by update time to prioritize older records
        queryset = queryset.order_by("updated_at")

        total_count = queryset.count()

        if total_count == 0:
            self.stdout.write(
                self.style.WARNING("No records found matching the criteria.")
            )
            return

        # Apply max_records limit if specified
        if options["max_records"]:
            queryset = queryset[: options["max_records"]]
            process_count = min(total_count, options["max_records"])
            self.stdout.write(
                f"Processing {process_count} of {total_count} records (limited by --max-records)"
            )
        else:
            process_count = total_count
            self.stdout.write(f"Found {total_count} records to process")

        if options["dry_run"]:
            self.stdout.write(
                self.style.WARNING("DRY RUN MODE - No changes will be made")
            )

        # Show some sample records
        self.stdout.write("\nSample records to be processed:")
        for record in queryset[:5]:
            self.stdout.write(
                f"  {record.ip_address} - ASN: {record.asn}, Org: '{record.organization}', "
                f"Country: '{record.country}', Updated: {record.updated_at}"
            )
        if total_count > 5:
            self.stdout.write(f"  ... and {total_count - 5} more")

        if not options["dry_run"]:
            # Confirm before proceeding (unless --force is used)
            if not options["force"]:
                confirm = input(f"\nProceed to update {process_count} records? [y/N]: ")
                if confirm.lower() != "y":
                    self.stdout.write("Operation cancelled.")
                    return

        # Process records
        self.stdout.write("\nStarting WHOIS refresh...")
        self.stdout.write(f"Batch size: {options['batch_size']}")
        self.stdout.write(f"Delay between requests: {options['delay']} seconds")

        updated_count = 0
        error_count = 0
        skipped_count = 0
        batch_num = 0

        # Process in batches
        batch_size = options["batch_size"]

        for i in range(0, process_count, batch_size):
            batch_num += 1
            batch_end = min(i + batch_size, process_count)
            batch_records = list(queryset[i:batch_end])

            self.stdout.write(
                f"\nProcessing batch {batch_num} ({i+1}-{batch_end} of {process_count})..."
            )

            for j, record in enumerate(batch_records, 1):
                try:
                    if options["dry_run"]:
                        self.stdout.write(
                            f"  [{i+j}] Would refresh: {record.ip_address} "
                            f"(ASN: {record.asn}, Org: '{record.organization}')"
                        )
                        updated_count += 1
                        continue

                    # Perform the actual WHOIS lookup
                    self.stdout.write(
                        f"  [{i+j}] Refreshing {record.ip_address}...", ending=""
                    )

                    # Create a signature for the celery task
                    task = fetch_ip_whois_info.s(record.ip_address)
                    result = task.apply()

                    if result.successful() and result.result.get("success"):
                        whois_info = result.result.get("whois_info", {})
                        old_org = record.organization
                        new_org = whois_info.get("organization")

                        # Check if we got useful new data
                        if new_org and new_org != old_org:
                            self.stdout.write(
                                self.style.SUCCESS(
                                    f" Updated! '{old_org}' -> '{new_org}'"
                                )
                            )
                            updated_count += 1
                        elif new_org == old_org:
                            self.stdout.write(" No change")
                            skipped_count += 1
                        else:
                            self.stdout.write(" Still no organization data")
                            skipped_count += 1
                    else:
                        error_msg = (
                            result.result.get("error", "Unknown error")
                            if result.result
                            else "Task failed"
                        )
                        self.stdout.write(self.style.ERROR(f" Error: {error_msg}"))
                        error_count += 1

                    # Rate limiting delay
                    if options["delay"] > 0:
                        time.sleep(options["delay"])

                except Exception as e:
                    self.stdout.write(self.style.ERROR(f" Exception: {str(e)}"))
                    error_count += 1

                # Progress indicator
                if (i + j) % 10 == 0:
                    self.stdout.write(
                        f"    Progress: {i+j}/{process_count} records processed"
                    )

        # Final summary
        self.stdout.write("\n" + "=" * 50)
        self.stdout.write("REFRESH SUMMARY")
        self.stdout.write("=" * 50)

        if options["dry_run"]:
            self.stdout.write(f"Records that would be processed: {updated_count}")
        else:
            self.stdout.write(f"Successfully updated: {updated_count}")
            self.stdout.write(f"No change needed: {skipped_count}")
            self.stdout.write(f"Errors encountered: {error_count}")
            self.stdout.write(
                f"Total processed: {updated_count + skipped_count + error_count}"
            )

            if updated_count > 0:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"\n✓ Successfully refreshed {updated_count} WHOIS records!"
                    )
                )

            if error_count > 0:
                self.stdout.write(
                    self.style.WARNING(
                        f"\n⚠ {error_count} records had errors during refresh"
                    )
                )
