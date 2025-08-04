from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.utils import timezone
from .models import Domain, RecordLog, APIKey, MonitorSettings


@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    """Admin configuration for Domain model."""
    
    list_display = ['name', 'is_active', 'last_known_ips_display', 'updated_at', 'created_at', 'record_count']
    list_filter = ['is_active', 'created_at', 'updated_at']
    search_fields = ['name']
    list_editable = ['is_active']
    readonly_fields = ['created_at', 'updated_at', 'record_count', 'last_check_status']
    
    fieldsets = (
        (None, {
            'fields': ('name', 'is_active')
        }),
        ('DNS Information', {
            'fields': ('last_known_ips', 'last_check_status'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'record_count'),
            'classes': ('collapse',)
        }),
    )
    
    def last_known_ips_display(self, obj):
        """Display last known IPs with better formatting."""
        if obj.last_known_ips:
            ips = obj.get_last_known_ips_list()
            if len(ips) <= 3:
                return ', '.join(ips)
            else:
                return f"{', '.join(ips[:3])}... (+{len(ips)-3} more)"
        return "Not checked yet"
    last_known_ips_display.short_description = 'Last Known IPs'
    
    def record_count(self, obj):
        """Count of record logs for this domain."""
        count = obj.record_logs.count()
        if count > 0:
            url = reverse('admin:monitor_recordlog_changelist') + f'?domain__id__exact={obj.id}'
            return format_html('<a href="{}">{} logs</a>', url, count)
        return "0 logs"
    record_count.short_description = 'Record Logs'
    
    def last_check_status(self, obj):
        """Display the status of the last check."""
        last_log = obj.record_logs.first()
        if last_log:
            if last_log.error_message:
                return format_html('<span style="color: red;">ERROR: {}</span>', last_log.error_message[:50])
            elif last_log.is_change:
                return format_html('<span style="color: orange;">CHANGED</span>')
            else:
                return format_html('<span style="color: green;">OK</span>')
        return "Never checked"
    last_check_status.short_description = 'Last Check Status'
    
    actions = ['check_domains_now', 'activate_domains', 'deactivate_domains']
    
    def check_domains_now(self, request, queryset):
        """Action to manually trigger DNS checks for selected domains."""
        from .tasks import check_domain_a_records
        
        checked_count = 0
        for domain in queryset:
            try:
                check_domain_a_records.delay(domain.id)
                checked_count += 1
            except Exception as e:
                self.message_user(request, f"Failed to schedule check for {domain.name}: {str(e)}", level='ERROR')
        
        self.message_user(request, f"Scheduled DNS checks for {checked_count} domains.")
    check_domains_now.short_description = "Check selected domains now"
    
    def activate_domains(self, request, queryset):
        """Action to activate selected domains."""
        updated = queryset.update(is_active=True)
        self.message_user(request, f"Activated {updated} domains.")
    activate_domains.short_description = "Activate selected domains"
    
    def deactivate_domains(self, request, queryset):
        """Action to deactivate selected domains."""
        updated = queryset.update(is_active=False)
        self.message_user(request, f"Deactivated {updated} domains.")
    deactivate_domains.short_description = "Deactivate selected domains"


@admin.register(RecordLog)
class RecordLogAdmin(admin.ModelAdmin):
    """Admin configuration for RecordLog model."""
    
    list_display = ['domain', 'ips_display', 'is_change', 'timestamp', 'status']
    list_filter = ['is_change', 'timestamp', 'domain']
    search_fields = ['domain__name', 'ips']
    readonly_fields = ['domain', 'ips', 'is_change', 'timestamp', 'error_message']
    date_hierarchy = 'timestamp'
    
    fieldsets = (
        (None, {
            'fields': ('domain', 'timestamp')
        }),
        ('DNS Results', {
            'fields': ('ips', 'is_change')
        }),
        ('Error Information', {
            'fields': ('error_message',),
            'classes': ('collapse',)
        }),
    )
    
    def ips_display(self, obj):
        """Display IPs with better formatting."""
        if obj.ips:
            ips = obj.get_ips_list()
            if len(ips) <= 2:
                return ', '.join(ips)
            else:
                return f"{', '.join(ips[:2])}... (+{len(ips)-2} more)"
        return "No IPs found"
    ips_display.short_description = 'IP Addresses'
    
    def status(self, obj):
        """Display status with color coding."""
        if obj.error_message:
            return format_html('<span style="color: red; font-weight: bold;">ERROR</span>')
        elif obj.is_change:
            return format_html('<span style="color: orange; font-weight: bold;">CHANGED</span>')
        else:
            return format_html('<span style="color: green;">OK</span>')
    status.short_description = 'Status'
    
    def has_add_permission(self, request):
        """Disable adding new record logs manually."""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Make record logs read-only."""
        return False
    
    def has_delete_permission(self, request, obj=None):
        """Allow deletion of old logs."""
        return True


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    """Admin configuration for API Key model."""
    
    list_display = ['name', 'user', 'is_active', 'masked_key', 'created_at', 'last_used']
    list_filter = ['is_active', 'created_at', 'last_used', 'user']
    search_fields = ['name', 'user__username']
    list_editable = ['is_active']
    readonly_fields = ['key', 'created_at', 'last_used', 'full_key_display']
    
    fieldsets = (
        (None, {
            'fields': ('name', 'user', 'is_active')
        }),
        ('API Key Information', {
            'fields': ('full_key_display', 'key'),
            'description': 'The API key will be generated automatically when you save. Make sure to copy it as it will not be shown in full again.'
        }),
        ('Usage Information', {
            'fields': ('created_at', 'last_used'),
            'classes': ('collapse',)
        }),
    )
    
    def masked_key(self, obj):
        """Display masked version of the API key."""
        return obj.mask_key()
    masked_key.short_description = 'API Key'
    
    def full_key_display(self, obj):
        """Display full API key only when creating/just created."""
        if obj.pk and obj.key:
            return format_html(
                '<div style="background: #f8f9fa; padding: 10px; border: 1px solid #dee2e6; border-radius: 4px;">'
                '<strong>Full API Key:</strong><br>'
                '<code style="font-size: 14px; color: #495057;">{}</code><br>'
                '<small style="color: #6c757d;">⚠️ Copy this key now - it will not be shown in full again!</small>'
                '</div>',
                obj.key
            )
        return "API key will be generated when you save this record."
    full_key_display.short_description = 'Generated API Key'
    
    def save_model(self, request, obj, form, change):
        """Update last_used when key is used via admin."""
        if not change:  # Creating new API key
            obj.user = obj.user or request.user
        super().save_model(request, obj, form, change)


@admin.register(MonitorSettings)
class MonitorSettingsAdmin(admin.ModelAdmin):
    """Admin configuration for Monitor Settings."""
    
    list_display = ['check_interval_display', 'email_notifications_enabled', 'notification_email', 'updated_at']
    
    fieldsets = (
        ('DNS Check Settings', {
            'fields': ('check_interval_minutes', 'max_parallel_checks', 'dns_timeout_seconds'),
            'description': 'Configure how often and how DNS checks are performed.'
        }),
        ('Notification Settings', {
            'fields': ('email_notifications_enabled', 'notification_email'),
            'description': 'Configure email notifications for DNS changes.'
        }),
        ('System Information', {
            'fields': ('updated_at',),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ['updated_at']
    
    def check_interval_display(self, obj):
        """Display check interval with units"""
        if obj.check_interval_minutes == 1:
            return "1 minute"
        elif obj.check_interval_minutes < 60:
            return f"{obj.check_interval_minutes} minutes"
        elif obj.check_interval_minutes == 60:
            return "1 hour"
        else:
            hours = obj.check_interval_minutes // 60
            minutes = obj.check_interval_minutes % 60
            if minutes == 0:
                return f"{hours} hours"
            else:
                return f"{hours}h {minutes}m"
    check_interval_display.short_description = 'Check Interval'
    
    def has_add_permission(self, request):
        """Only allow one settings instance"""
        return not MonitorSettings.objects.exists()
    
    def has_delete_permission(self, request, obj=None):
        """Don't allow deletion of settings"""
        return False
    
    def save_model(self, request, obj, form, change):
        """Save with custom message"""
        super().save_model(request, obj, form, change)
        self.message_user(
            request, 
            f"Settings updated successfully. DNS checks will now run every {obj.check_interval_minutes} minutes.",
            level='SUCCESS'
        )


# Customize admin site headers
admin.site.site_header = 'DNS A-Record Monitor'
admin.site.site_title = 'DNS Monitor Admin'
admin.site.index_title = 'DNS A-Record Change Monitor Administration'
