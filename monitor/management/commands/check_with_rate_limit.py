from django.core.management.base import BaseCommand
from monitor.models import MonitorSettings
from monitor.tasks import check_domains_with_rate_limiting


class Command(BaseCommand):
    help = 'Check domains with rate limiting (respects minimum check intervals)'

    def handle(self, *args, **options):
        settings = MonitorSettings.get_settings()
        
        self.stdout.write("Starting rate-limited domain checks...")
        self.stdout.write(
            f"Rate limit: {settings.min_check_interval_seconds} seconds between checks for same domain"
        )
        
        # Start the rate-limited check task
        result = check_domains_with_rate_limiting.delay()
        
        self.stdout.write(
            self.style.SUCCESS(
                f"Rate-limited domain check started!\n"
                f"Task ID: {result.id}\n"
                f"This will only check domains that haven't been checked within the last {settings.min_check_interval_seconds} seconds."
            )
        )
        
        self.stdout.write(
            self.style.WARNING(
                "\nNote: Use this command when you want to check domains immediately but still respect rate limits.\n"
                "For continuous monitoring, use: python manage.py start_continuous_monitoring"
            )
        )
