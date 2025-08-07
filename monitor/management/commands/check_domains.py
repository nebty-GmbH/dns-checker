from django.core.management.base import BaseCommand

from monitor.models import Domain
from monitor.tasks import check_all_domains_now, check_domain_a_records


class Command(BaseCommand):
    """
    Django management command to manually check domains for testing.

    Usage:
        python manage.py check_domains  # Check all active domains
        python manage.py check_domains --domain example.com  # Check specific domain
    """

    help = "Manually check DNS A records for domains"

    def add_arguments(self, parser):
        parser.add_argument(
            "--domain", type=str, help="Check a specific domain by name"
        )
        parser.add_argument(
            "--all", action="store_true", help="Check all active domains", default=False
        )

    def handle(self, *args, **options):
        domain_name = options.get("domain")
        check_all = options.get("all")

        if domain_name:
            # Check specific domain
            try:
                domain = Domain.objects.get(name=domain_name)
                self.stdout.write(f"Checking domain: {domain.name}")

                # Run the task synchronously for immediate feedback
                result = check_domain_a_records(domain.id)

                if result["success"]:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"✓ {domain.name}: {', '.join(result['ips'])} "
                            f"({'CHANGED' if result['is_change'] else 'NO CHANGE'})"
                        )
                    )
                else:
                    self.stdout.write(
                        self.style.ERROR(f"✗ {domain.name}: {result['error']}")
                    )

            except Domain.DoesNotExist:
                self.stdout.write(
                    self.style.ERROR(f"Domain '{domain_name}' not found in database")
                )

        elif check_all:
            # Check all active domains
            self.stdout.write("Checking all active domains...")
            result = check_all_domains_now()

            self.stdout.write("\nResults:")
            self.stdout.write(f"  Total domains: {result['total_domains']}")
            self.stdout.write(f"  Successful: {result['successful_checks']}")
            self.stdout.write(f"  Failed: {result['failed_checks']}")
            self.stdout.write(f"  Changes detected: {result['changes_detected']}")

            # Show detailed results
            for domain_result in result["results"]:
                if domain_result["success"]:
                    status = (
                        "CHANGED"
                        if domain_result.get("is_change", False)
                        else "NO CHANGE"
                    )
                    ips = ", ".join(domain_result.get("ips", []))
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"  ✓ {domain_result['domain']}: {ips} ({status})"
                        )
                    )
                else:
                    self.stdout.write(
                        self.style.ERROR(
                            f"  ✗ {domain_result['domain']}: {domain_result['error']}"
                        )
                    )

        else:
            # Default: check all active domains using Celery tasks
            active_domains = Domain.objects.filter(is_active=True)

            if not active_domains.exists():
                self.stdout.write(
                    self.style.WARNING("No active domains found to check")
                )
                return

            self.stdout.write(
                f"Scheduling checks for {active_domains.count()} active domains..."
            )

            scheduled = 0
            for domain in active_domains:
                try:
                    check_domain_a_records.delay(domain.id)
                    scheduled += 1
                    self.stdout.write(f"  Scheduled: {domain.name}")
                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(
                            f"  Failed to schedule {domain.name}: {str(e)}"
                        )
                    )

            self.stdout.write(
                self.style.SUCCESS(f"\nScheduled {scheduled} domain checks!")
            )
            self.stdout.write("Check the RecordLog in Django admin for results.")
