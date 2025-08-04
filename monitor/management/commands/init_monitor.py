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
                f"Check interval: {settings.check_interval_minutes} minutes\n"
                f"Email notifications: {'Enabled' if settings.email_notifications_enabled else 'Disabled'}\n"
                f"Max parallel checks: {settings.max_parallel_checks}\n"
                f"DNS timeout: {settings.dns_timeout_seconds} seconds"
            )
        )
        
        self.stdout.write(
            self.style.WARNING(
                "\nYou can now configure these settings via the Django admin panel:\n"
                "Admin Panel > Monitor > Monitor Settings"
            )
        )
