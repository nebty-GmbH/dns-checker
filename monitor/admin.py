from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import Domain, RecordLog


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


# Customize admin site headers
admin.site.site_header = 'DNS A-Record Monitor'
admin.site.site_title = 'DNS Monitor Admin'
admin.site.index_title = 'DNS A-Record Change Monitor Administration'
