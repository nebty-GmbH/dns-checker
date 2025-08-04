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
