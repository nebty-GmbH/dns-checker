from django.core.management.base import BaseCommand
from monitor.models import MonitorSettings


class Command(BaseCommand):
    help = 'Initialize default monitor settings and periodic tasks'

    def handle(self, *args, **options):
        self.stdout.write("Initializing DNS monitor settings...")
        
        # Create default settings if they don't exist
        settings = MonitorSettings.get_settings()
        
        self.stdout.write(
            self.style.SUCCESS(
                f"Monitor settings initialized successfully!\n"
                f"Monitoring mode: {'Continuous' if settings.continuous_monitoring_enabled else 'Periodic'}\n"
                f"Check interval: {settings.check_interval_minutes} minutes (periodic mode)\n"
                f"Rate limit: {settings.min_check_interval_seconds} seconds (continuous mode)\n"
                f"Email notifications: {'Enabled' if settings.email_notifications_enabled else 'Disabled'}\n"
                f"Max parallel checks: {settings.max_parallel_checks}\n"
                f"DNS timeout: {settings.dns_timeout_seconds} seconds"
            )
        )
        
        # Start continuous monitoring if enabled
        if settings.continuous_monitoring_enabled:
            try:
                from monitor.tasks import start_continuous_monitoring
                start_continuous_monitoring.delay()
                self.stdout.write(
                    self.style.SUCCESS(
                        "✓ Continuous monitoring started!"
                    )
                )
            except Exception as e:
                self.stdout.write(
                    self.style.WARNING(
                        f"⚠ Could not start continuous monitoring: {e}\n"
                        f"You can start it manually later via the admin panel or by running:\n"
                        f"python manage.py start_continuous_monitoring"
                    )
                )
        
        self.stdout.write(
            self.style.WARNING(
                "\nYou can configure these settings via the Django admin panel:\n"
                "Admin Panel > Monitor > Monitor Settings\n\n"
                "Available monitoring modes:\n"
                "• Continuous: Checks domains continuously with rate limiting\n"
                "• Periodic: Checks all domains at fixed intervals"
            )
        )
