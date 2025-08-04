from django.core.management.base import BaseCommand
from monitor.models import MonitorSettings
from monitor.tasks import start_continuous_monitoring


class Command(BaseCommand):
    help = 'Start continuous DNS monitoring'

    def add_arguments(self, parser):
        parser.add_argument(
            '--enable', 
            action='store_true',
            help='Enable continuous monitoring in settings'
        )
        parser.add_argument(
            '--disable', 
            action='store_true',
            help='Disable continuous monitoring in settings'
        )

    def handle(self, *args, **options):
        settings = MonitorSettings.get_settings()
        
        if options['enable']:
            settings.continuous_monitoring_enabled = True
            settings.save()
            self.stdout.write(
                self.style.SUCCESS("Continuous monitoring enabled in settings.")
            )
            
        elif options['disable']:
            settings.continuous_monitoring_enabled = False
            settings.save()
            self.stdout.write(
                self.style.SUCCESS("Continuous monitoring disabled in settings.")
            )
            return
        
        if not settings.continuous_monitoring_enabled:
            self.stdout.write(
                self.style.WARNING(
                    "Continuous monitoring is disabled in settings. Use --enable to enable it first."
                )
            )
            return
        
        self.stdout.write("Starting continuous DNS monitoring...")
        
        # Start the continuous monitoring task
        result = start_continuous_monitoring.delay()
        
        self.stdout.write(
            self.style.SUCCESS(
                f"Continuous monitoring started successfully!\n"
                f"Task ID: {result.id}\n"
                f"Rate limit: {settings.min_check_interval_seconds} seconds between checks for same domain\n"
                f"Max parallel checks: {settings.max_parallel_checks}\n"
                f"DNS timeout: {settings.dns_timeout_seconds} seconds"
            )
        )
        
        self.stdout.write(
            self.style.WARNING(
                "\nNote: You can also start/stop continuous monitoring via the Django admin panel:\n"
                "Admin Panel > Monitor > Monitor Settings > Continuous monitoring enabled"
            )
        )
