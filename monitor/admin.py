from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.utils import timezone
from .models import Domain, RecordLog, APIKey, MonitorSettings, DomainSnapshot, IPWhoisInfo, RecordLogIPInfo


@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    """Admin configuration for Domain model."""
    
    list_display = ['name', 'is_active', 'last_known_ips_display', 'updated_at', 'created_at', 'record_count', 'snapshot_count']
    list_filter = ['is_active', 'created_at', 'updated_at']
    search_fields = ['name']
    list_editable = ['is_active']
    readonly_fields = ['created_at', 'updated_at', 'record_count', 'snapshot_count', 'last_check_status']
    
    fieldsets = (
        (None, {
            'fields': ('name', 'is_active')
        }),
        ('DNS Information', {
            'fields': ('last_known_ips', 'last_check_status'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'record_count', 'snapshot_count'),
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
    
    def snapshot_count(self, obj):
        """Count of snapshots for this domain."""
        count = obj.snapshots.count()
        if count > 0:
            url = reverse('admin:monitor_domainsnapshot_changelist') + f'?domain__id__exact={obj.id}'
            return format_html('<a href="{}">{} snapshots</a>', url, count)
        return "0 snapshots"
    snapshot_count.short_description = 'Snapshots'
    
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
    
    list_display = ['domain', 'ips_display', 'is_change', 'timestamp', 'status', 'has_snapshot', 'ip_info_count']
    list_filter = ['is_change', 'timestamp', 'domain']
    search_fields = ['domain__name', 'ips']
    readonly_fields = ['domain', 'ips', 'is_change', 'timestamp', 'error_message', 'snapshot_link', 'ip_info_summary']
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
        ('Associated Snapshot', {
            'fields': ('snapshot_link',),
            'classes': ('collapse',)
        }),
        ('IP Information', {
            'fields': ('ip_info_summary',),
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
    
    def has_snapshot(self, obj):
        """Display if this record log has an associated snapshot."""
        try:
            if hasattr(obj, 'snapshot') and obj.snapshot:
                return format_html('<span style="color: green;">Yes</span>')
            else:
                return format_html('<span style="color: gray;">No</span>')
        except:
            return format_html('<span style="color: gray;">No</span>')
    has_snapshot.short_description = 'Snapshot'
    has_snapshot.boolean = True
    
    def snapshot_link(self, obj):
        """Display link to associated snapshot if it exists."""
        try:
            if hasattr(obj, 'snapshot') and obj.snapshot:
                url = reverse('admin:monitor_domainsnapshot_change', args=[obj.snapshot.id])
                return format_html('<a href="{}">View Snapshot</a>', url)
            else:
                return "No snapshot"
        except:
            return "No snapshot"
    snapshot_link.short_description = 'Associated Snapshot'
    
    def ip_info_count(self, obj):
        """Display count of associated IP information."""
        count = obj.ip_info_entries.count()
        if count > 0:
            url = reverse('admin:monitor_recordlogipinfo_changelist') + f'?record_log__id__exact={obj.id}'
            return format_html('<a href="{}">{} IPs</a>', url, count)
        return "0 IPs"
    ip_info_count.short_description = 'IP Info'
    
    def ip_info_summary(self, obj):
        """Display summary of IP WHOIS information."""
        ip_info_entries = obj.ip_info_entries.all()
        if not ip_info_entries:
            return "No IP information available"
        
        summary_lines = []
        for entry in ip_info_entries:
            whois = entry.ip_whois_info
            line = f"• {entry.ip_address}: {whois.display_info}"
            summary_lines.append(line)
        
        summary_text = "\n".join(summary_lines)
        return format_html('<pre style="font-size: 12px; margin: 0;">{}</pre>', summary_text)
    ip_info_summary.short_description = 'IP WHOIS Summary'
    
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
    
    list_display = ['monitoring_mode_display', 'check_interval_display', 'rate_limit_display', 'email_notifications_enabled', 'updated_at']
    
    fieldsets = (
        ('Monitoring Mode', {
            'fields': ('continuous_monitoring_enabled',),
            'description': 'Choose between periodic scheduled checks or continuous monitoring.'
        }),
        ('Periodic Monitoring Settings', {
            'fields': ('check_interval_minutes',),
            'description': 'Configure scheduled DNS checks (only used when continuous monitoring is disabled).',
            'classes': ('collapse',)
        }),
        ('Continuous Monitoring Settings', {
            'fields': ('min_check_interval_seconds',),
            'description': 'Configure rate limiting for continuous monitoring (only used when continuous monitoring is enabled).',
            'classes': ('collapse',)
        }),
        ('Performance Settings', {
            'fields': ('max_parallel_checks', 'dns_timeout_seconds'),
            'description': 'Configure system performance and DNS timeout settings.'
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
    
    def monitoring_mode_display(self, obj):
        """Display the current monitoring mode"""
        if obj.continuous_monitoring_enabled:
            return format_html('<span style="color: green;">Continuous</span>')
        else:
            return format_html('<span style="color: blue;">Periodic</span>')
    monitoring_mode_display.short_description = 'Mode'
    
    def check_interval_display(self, obj):
        """Display check interval with units"""
        if obj.continuous_monitoring_enabled:
            return "N/A (Continuous)"
        
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
    check_interval_display.short_description = 'Periodic Interval'
    
    def rate_limit_display(self, obj):
        """Display rate limiting with units"""
        if not obj.continuous_monitoring_enabled:
            return "N/A (Periodic)"
        
        if obj.min_check_interval_seconds < 60:
            return f"{obj.min_check_interval_seconds}s"
        elif obj.min_check_interval_seconds == 60:
            return "1 min"
        elif obj.min_check_interval_seconds < 3600:
            minutes = obj.min_check_interval_seconds // 60
            seconds = obj.min_check_interval_seconds % 60
            if seconds == 0:
                return f"{minutes} min"
            else:
                return f"{minutes}m {seconds}s"
        else:
            hours = obj.min_check_interval_seconds // 3600
            remainder = obj.min_check_interval_seconds % 3600
            minutes = remainder // 60
            if minutes == 0:
                return f"{hours}h"
            else:
                return f"{hours}h {minutes}m"
    rate_limit_display.short_description = 'Rate Limit'
    
    def has_add_permission(self, request):
        """Only allow one settings instance"""
        return not MonitorSettings.objects.exists()
    
    def has_delete_permission(self, request, obj=None):
        """Don't allow deletion of settings"""
        return False
    
    def save_model(self, request, obj, form, change):
        """Save with custom message"""
        super().save_model(request, obj, form, change)
        
        if obj.continuous_monitoring_enabled:
            message = f"Settings updated successfully. Continuous monitoring enabled with {obj.min_check_interval_seconds}s rate limiting."
        else:
            message = f"Settings updated successfully. Periodic DNS checks will run every {obj.check_interval_minutes} minutes."
        
        self.message_user(request, message, level='SUCCESS')


@admin.register(DomainSnapshot)
class DomainSnapshotAdmin(admin.ModelAdmin):
    """Admin configuration for DomainSnapshot model."""
    
    list_display = ['domain', 'timestamp', 'snapshot_type', 'status_code', 'content_size', 'response_time_display', 'has_error']
    list_filter = ['is_initial_snapshot', 'status_code', 'timestamp', 'domain']
    search_fields = ['domain__name', 'error_message']
    readonly_fields = ['domain', 'record_log', 'timestamp', 'content_size', 'content_preview_display', 'html_content_display']
    
    fieldsets = (
        (None, {
            'fields': ('domain', 'record_log', 'is_initial_snapshot', 'timestamp')
        }),
        ('Snapshot Data', {
            'fields': ('status_code', 'response_time_ms', 'content_size', 'error_message'),
        }),
        ('HTML Content', {
            'fields': ('content_preview_display', 'html_content_display'),
            'classes': ('collapse',)
        }),
    )
    
    def snapshot_type(self, obj):
        """Display snapshot type with color coding."""
        if obj.is_initial_snapshot:
            return format_html('<span style="color: green; font-weight: bold;">Initial</span>')
        else:
            return format_html('<span style="color: orange; font-weight: bold;">IP Change</span>')
    snapshot_type.short_description = 'Type'
    
    def content_size(self, obj):
        """Display content size in human readable format."""
        size = obj.content_length
        if size == 0:
            return "No content"
        elif size < 1024:
            return f"{size} bytes"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.1f} MB"
    content_size.short_description = 'Content Size'
    
    def response_time_display(self, obj):
        """Display response time with units."""
        if obj.response_time_ms is None:
            return "N/A"
        elif obj.response_time_ms < 1000:
            return f"{obj.response_time_ms}ms"
        else:
            return f"{obj.response_time_ms / 1000:.1f}s"
    response_time_display.short_description = 'Response Time'
    
    def has_error(self, obj):
        """Display error status."""
        if obj.error_message:
            return format_html('<span style="color: red;">Yes</span>')
        else:
            return format_html('<span style="color: green;">No</span>')
    has_error.short_description = 'Error'
    has_error.boolean = True
    
    def content_preview_display(self, obj):
        """Display a preview of the HTML content."""
        if not obj.html_content:
            return "No content"
        preview = obj.content_preview
        return format_html('<pre style="white-space: pre-wrap; font-size: 12px; max-height: 200px; overflow-y: auto;">{}</pre>', preview)
    content_preview_display.short_description = 'Content Preview'
    
    def html_content_display(self, obj):
        """Display full HTML content in a text area."""
        if not obj.html_content:
            return "No content"
        return format_html('<textarea readonly style="width: 100%; height: 400px; font-family: monospace; font-size: 12px;">{}</textarea>', obj.html_content)
    html_content_display.short_description = 'Full HTML Content'
    
    def has_add_permission(self, request):
        """Don't allow manual addition of snapshots."""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Make snapshots read-only."""
        return False


@admin.register(IPWhoisInfo)
class IPWhoisInfoAdmin(admin.ModelAdmin):
    """Admin configuration for IPWhoisInfo model."""
    
    list_display = ['ip_address', 'organization_display', 'asn_display', 'country_display', 'registry', 'updated_at', 'has_error']
    list_filter = ['country', 'registry', 'updated_at', 'created_at']
    search_fields = ['ip_address', 'organization', 'asn', 'asn_description', 'isp']
    readonly_fields = ['ip_address', 'created_at', 'updated_at', 'display_info_formatted']
    
    fieldsets = (
        (None, {
            'fields': ('ip_address', 'display_info_formatted')
        }),
        ('ASN Information', {
            'fields': ('asn', 'asn_description', 'registry'),
        }),
        ('Organization Information', {
            'fields': ('organization', 'isp'),
        }),
        ('Location Information', {
            'fields': ('country', 'country_code', 'network_cidr'),
        }),
        ('System Information', {
            'fields': ('created_at', 'updated_at', 'error_message'),
            'classes': ('collapse',)
        }),
    )
    
    def organization_display(self, obj):
        """Display organization with truncation."""
        if obj.organization:
            org = obj.organization
            if len(org) > 30:
                return f"{org[:30]}..."
            return org
        return "Unknown"
    organization_display.short_description = 'Organization'
    
    def asn_display(self, obj):
        """Display ASN information."""
        if obj.asn:
            asn = obj.asn.replace('AS', '') if obj.asn.startswith('AS') else obj.asn
            return f"AS{asn}"
        return "Unknown"
    asn_display.short_description = 'ASN'
    
    def country_display(self, obj):
        """Display country with flag if available."""
        if obj.country:
            country_text = obj.country
            if obj.country_code:
                country_text += f" ({obj.country_code})"
            return country_text
        return "Unknown"
    country_display.short_description = 'Country'
    
    def has_error(self, obj):
        """Display error status."""
        if obj.error_message:
            return format_html('<span style="color: red;">Yes</span>')
        else:
            return format_html('<span style="color: green;">No</span>')
    has_error.short_description = 'Error'
    has_error.boolean = True
    
    def display_info_formatted(self, obj):
        """Display formatted WHOIS information."""
        return format_html('<div style="font-family: monospace; background: #f8f8f8; padding: 10px; border-radius: 4px;">{}</div>', obj.display_info)
    display_info_formatted.short_description = 'WHOIS Summary'
    
    def has_add_permission(self, request):
        """Don't allow manual addition of WHOIS info."""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Make WHOIS info read-only."""
        return False


@admin.register(RecordLogIPInfo)
class RecordLogIPInfoAdmin(admin.ModelAdmin):
    """Admin configuration for RecordLogIPInfo model."""
    
    list_display = ['record_log_domain', 'ip_address', 'organization_info', 'asn_info', 'country_info', 'timestamp']
    list_filter = ['timestamp', 'ip_whois_info__country', 'ip_whois_info__registry']
    search_fields = ['ip_address', 'record_log__domain__name', 'ip_whois_info__organization', 'ip_whois_info__asn']
    readonly_fields = ['record_log', 'ip_whois_info', 'ip_address', 'timestamp', 'whois_detail_link']
    
    fieldsets = (
        (None, {
            'fields': ('record_log', 'ip_address', 'timestamp')
        }),
        ('WHOIS Information', {
            'fields': ('ip_whois_info', 'whois_detail_link'),
        }),
    )
    
    def record_log_domain(self, obj):
        """Display the domain name from the record log."""
        return obj.record_log.domain.name
    record_log_domain.short_description = 'Domain'
    record_log_domain.admin_order_field = 'record_log__domain__name'
    
    def organization_info(self, obj):
        """Display organization information."""
        if obj.ip_whois_info.organization:
            org = obj.ip_whois_info.organization
            if len(org) > 25:
                return f"{org[:25]}..."
            return org
        return "Unknown"
    organization_info.short_description = 'Organization'
    
    def asn_info(self, obj):
        """Display ASN information."""
        if obj.ip_whois_info.asn:
            asn = obj.ip_whois_info.asn.replace('AS', '') if obj.ip_whois_info.asn.startswith('AS') else obj.ip_whois_info.asn
            return f"AS{asn}"
        return "Unknown"
    asn_info.short_description = 'ASN'
    
    def country_info(self, obj):
        """Display country information."""
        if obj.ip_whois_info.country:
            return obj.ip_whois_info.country
        return "Unknown"
    country_info.short_description = 'Country'
    
    def whois_detail_link(self, obj):
        """Display link to detailed WHOIS information."""
        if obj.ip_whois_info:
            url = reverse('admin:monitor_ipwhoisinfo_change', args=[obj.ip_whois_info.id])
            return format_html('<a href="{}">View WHOIS Details</a>', url)
        return "No WHOIS data"
    whois_detail_link.short_description = 'WHOIS Details'
    
    def has_add_permission(self, request):
        """Don't allow manual addition."""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Make read-only."""
        return False


# Customize admin site headers
admin.site.site_header = 'DNS A-Record Monitor'
admin.site.site_title = 'DNS Monitor Admin'
admin.site.index_title = 'DNS A-Record Change Monitor Administration'
