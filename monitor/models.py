from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
import secrets


class Domain(models.Model):
    """Model to store domains to be monitored for DNS A-record changes."""
    
    name = models.CharField(
        max_length=255, 
        unique=True,
        help_text="Domain name to monitor (e.g., google.com)"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this domain is currently being monitored"
    )
    last_known_ips = models.TextField(
        null=True, 
        blank=True,
        help_text="Comma-separated list of last known IP addresses"
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="Last time this domain was checked"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When this domain was added to monitoring"
    )

    class Meta:
        ordering = ['name']
        verbose_name = 'Domain'
        verbose_name_plural = 'Domains'

    def __str__(self):
        return self.name

    def get_last_known_ips_list(self):
        """Return the last known IPs as a list."""
        if self.last_known_ips:
            return [ip.strip() for ip in self.last_known_ips.split(',') if ip.strip()]
        return []

    def set_last_known_ips_list(self, ip_list):
        """Set the last known IPs from a list."""
        if ip_list:
            # Sort the IPs for consistent comparison
            sorted_ips = sorted(set(str(ip).strip() for ip in ip_list))
            self.last_known_ips = ','.join(sorted_ips)
        else:
            self.last_known_ips = ''
    
    def can_be_checked_now(self):
        """Check if domain can be checked now based on rate limiting."""
        from monitor.models import MonitorSettings
        settings = MonitorSettings.get_settings()
        
        if not self.updated_at:
            return True
        
        from django.utils import timezone
        time_since_check = timezone.now() - self.updated_at
        min_interval = timezone.timedelta(seconds=settings.min_check_interval_seconds)
        
        return time_since_check >= min_interval


class RecordLog(models.Model):
    """Model to store historical DNS record check results."""
    
    domain = models.ForeignKey(
        Domain,
        on_delete=models.CASCADE,
        related_name='record_logs',
        help_text="Domain that was checked"
    )
    ips = models.TextField(
        help_text="Comma-separated list of IP addresses found during this check"
    )
    is_change = models.BooleanField(
        default=False,
        help_text="Whether the IPs changed from the previous check"
    )
    timestamp = models.DateTimeField(
        auto_now_add=True,
        help_text="When this check was performed"
    )
    error_message = models.TextField(
        null=True,
        blank=True,
        help_text="Error message if DNS lookup failed"
    )

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Record Log'
        verbose_name_plural = 'Record Logs'
        indexes = [
            models.Index(fields=['domain', '-timestamp']),
            models.Index(fields=['is_change', '-timestamp']),
        ]

    def __str__(self):
        status = "CHANGED" if self.is_change else "NO CHANGE"
        if self.error_message:
            status = "ERROR"
        return f"{self.domain.name} - {status} - {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"

    def get_ips_list(self):
        """Return the IPs as a list."""
        if self.ips:
            return [ip.strip() for ip in self.ips.split(',') if ip.strip()]
        return []

    def set_ips_list(self, ip_list):
        """Set the IPs from a list."""
        if ip_list:
            # Sort the IPs for consistent storage
            sorted_ips = sorted(set(str(ip).strip() for ip in ip_list))
            self.ips = ','.join(sorted_ips)
        else:
            self.ips = ''


class APIKey(models.Model):
    """
    API Key model for API authentication
    """
    name = models.CharField(max_length=100, help_text="Human-readable name for this API key")
    key = models.CharField(max_length=64, unique=True, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_keys')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "API Key"
        verbose_name_plural = "API Keys"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({'Active' if self.is_active else 'Inactive'})"

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        super().save(*args, **kwargs)

    @staticmethod
    def generate_key():
        """Generate a secure API key"""
        return secrets.token_urlsafe(48)

    def mask_key(self):
        """Return a masked version of the key for display"""
        if len(self.key) >= 8:
            return f"{self.key[:4]}...{self.key[-4:]}"
        return "****"


class MonitorSettings(models.Model):
    """
    Global settings for the DNS monitoring system
    """
    # Singleton pattern - only one instance should exist
    
    # Periodic monitoring settings (for scheduled checks)
    check_interval_minutes = models.PositiveIntegerField(
        default=15,
        help_text="How often to check domains for DNS changes (in minutes). Minimum: 1 minute."
    )
    
    # Continuous monitoring settings
    continuous_monitoring_enabled = models.BooleanField(
        default=True,
        help_text="Enable continuous monitoring (starts new cycle immediately after completion)"
    )
    min_check_interval_seconds = models.PositiveIntegerField(
        default=60,
        help_text="Minimum seconds between checks for the same domain (rate limiting). Minimum: 10 seconds"
    )
    
    # Notification settings
    email_notifications_enabled = models.BooleanField(
        default=False,
        help_text="Whether to send email notifications when DNS changes are detected"
    )
    notification_email = models.EmailField(
        blank=True,
        null=True,
        help_text="Email address to send notifications to"
    )
    
    # Performance settings
    max_parallel_checks = models.PositiveIntegerField(
        default=10,
        help_text="Maximum number of domains to check in parallel"
    )
    dns_timeout_seconds = models.PositiveIntegerField(
        default=30,
        help_text="Timeout for DNS queries in seconds"
    )
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Monitor Settings"
        verbose_name_plural = "Monitor Settings"
    
    def __str__(self):
        if self.continuous_monitoring_enabled:
            return f"DNS Monitor Settings (Continuous monitoring with {self.min_check_interval_seconds}s rate limit)"
        else:
            return f"DNS Monitor Settings (Check every {self.check_interval_minutes} minutes)"
    
    def save(self, *args, **kwargs):
        # Ensure minimum check interval
        if self.check_interval_minutes < 1:
            self.check_interval_minutes = 1
        
        # Ensure minimum rate limiting interval
        if self.min_check_interval_seconds < 10:
            self.min_check_interval_seconds = 10
        
        # Singleton pattern - delete other instances
        if not self.pk:
            MonitorSettings.objects.all().delete()
        
        super().save(*args, **kwargs)
        
        # Update Celery Beat schedule when settings change
        self._update_celery_schedule()
        
        # Start or stop continuous monitoring based on settings
        self._manage_continuous_monitoring()
    
    def _update_celery_schedule(self):
        """Update the Celery Beat schedule with new interval"""
        try:
            from django_celery_beat.models import PeriodicTask, IntervalSchedule
            
            # Get or create interval schedule
            schedule, created = IntervalSchedule.objects.get_or_create(
                every=self.check_interval_minutes,
                period=IntervalSchedule.MINUTES,
            )
            
            # Update or create the periodic task
            task, created = PeriodicTask.objects.get_or_create(
                name='DNS Domain Checks',
                defaults={
                    'task': 'monitor.tasks.schedule_domain_checks',
                    'interval': schedule,
                    'enabled': True,
                }
            )
            
            if not created:
                # Update existing task
                task.interval = schedule
                task.enabled = True
                task.save()
                
        except ImportError:
            # django-celery-beat not installed, use settings-based schedule
            pass
    
    def _manage_continuous_monitoring(self):
        """Start or stop continuous monitoring based on settings"""
        if self.continuous_monitoring_enabled:
            # Start continuous monitoring task
            from monitor.tasks import start_continuous_monitoring
            start_continuous_monitoring.delay()
        # Note: Stopping continuous monitoring is handled by the task itself
        # when it checks the settings at the beginning of each cycle
    
    @classmethod
    def get_settings(cls):
        """Get the current settings instance, creating default if none exists"""
        settings, created = cls.objects.get_or_create(
            defaults={
                'check_interval_minutes': 15,
                'continuous_monitoring_enabled': True,
                'min_check_interval_seconds': 60,
                'email_notifications_enabled': False,
                'max_parallel_checks': 10,
                'dns_timeout_seconds': 30,
            }
        )
        return settings
