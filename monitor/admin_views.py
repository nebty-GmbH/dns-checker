"""
Enhanced admin views for DNS Checker providing comprehensive domain analysis.
"""

import logging
from datetime import datetime, timedelta
from django.contrib import admin
from django.contrib.admin.views.main import ChangeList
from django.core.paginator import Paginator
from django.db import models
from django.db.models import Count, Q, Max, Min, Avg
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, get_object_or_404
from django.urls import path, reverse
from django.utils import timezone
from django.utils.html import format_html
from django.utils.safestring import mark_safe

from .models import Domain, RecordLog, DomainSnapshot, IPWhoisInfo, RecordLogIPInfo

logger = logging.getLogger(__name__)


class EnhancedDomainChangeList(ChangeList):
    """Enhanced changelist for domains with additional metrics and filtering."""
    
    def get_queryset(self, request):
        """Add annotations for domain metrics."""
        qs = super().get_queryset(request)
        
        # Add comprehensive annotations
        qs = qs.annotate(
            total_checks=Count('record_logs'),
            total_changes=Count('record_logs', filter=Q(record_logs__is_change=True)),
            last_change_date=Max('record_logs__timestamp', filter=Q(record_logs__is_change=True)),
            first_check_date=Min('record_logs__timestamp'),
            avg_check_interval=Avg('record_logs__timestamp'),
            total_snapshots=Count('snapshots'),
            total_ips_seen=Count('record_logs__ip_info_entries__ip_address', distinct=True),
            recent_changes=Count(
                'record_logs', 
                filter=Q(
                    record_logs__is_change=True,
                    record_logs__timestamp__gte=timezone.now() - timedelta(days=7)
                )
            ),
        )
        
        return qs


def enhanced_domain_dashboard(request):
    """Enhanced domain dashboard with comprehensive analytics."""
    
    # Get domains with comprehensive metrics
    domains = Domain.objects.annotate(
        total_checks=Count('record_logs'),
        total_changes=Count('record_logs', filter=Q(record_logs__is_change=True)),
        last_change_date=Max('record_logs__timestamp', filter=Q(record_logs__is_change=True)),
        first_check_date=Min('record_logs__timestamp'),
        total_snapshots=Count('snapshots'),
        total_ips_seen=Count('record_logs__ip_info_entries__ip_address', distinct=True),
        recent_changes=Count(
            'record_logs', 
            filter=Q(
                record_logs__is_change=True,
                record_logs__timestamp__gte=timezone.now() - timedelta(days=7)
            )
        ),
        last_7_days_checks=Count(
            'record_logs',
            filter=Q(record_logs__timestamp__gte=timezone.now() - timedelta(days=7))
        ),
        error_count=Count('record_logs', filter=Q(record_logs__error_message__isnull=False)),
    ).prefetch_related('record_logs', 'snapshots').order_by('-updated_at')
    
    # Apply filters
    search_query = request.GET.get('search', '')
    status_filter = request.GET.get('status', 'all')
    activity_filter = request.GET.get('activity', 'all')
    change_filter = request.GET.get('changes', 'all')
    
    if search_query:
        domains = domains.filter(
            Q(name__icontains=search_query) |
            Q(last_known_ips__icontains=search_query)
        )
    
    if status_filter == 'active':
        domains = domains.filter(is_active=True)
    elif status_filter == 'inactive':
        domains = domains.filter(is_active=False)
    
    if activity_filter == 'recent':
        domains = domains.filter(updated_at__gte=timezone.now() - timedelta(days=7))
    elif activity_filter == 'stale':
        domains = domains.filter(updated_at__lt=timezone.now() - timedelta(days=7))
    
    if change_filter == 'changed':
        domains = domains.filter(recent_changes__gt=0)
    elif change_filter == 'stable':
        domains = domains.filter(recent_changes=0)
    elif change_filter == 'suspicious':
        # More than 2 changes in last 7 days could be suspicious
        domains = domains.filter(recent_changes__gt=2)
    
    # Pagination
    paginator = Paginator(domains, 25)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    # Summary statistics
    total_domains = Domain.objects.count()
    active_domains = Domain.objects.filter(is_active=True).count()
    domains_with_recent_changes = Domain.objects.annotate(
        recent_changes=Count(
            'record_logs',
            filter=Q(
                record_logs__is_change=True,
                record_logs__timestamp__gte=timezone.now() - timedelta(days=7)
            )
        )
    ).filter(recent_changes__gt=0).count()
    
    total_checks_today = RecordLog.objects.filter(
        timestamp__gte=timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
    ).count()
    
    context = {
        'title': 'Enhanced Domain Dashboard',
        'domains': page_obj,
        'search_query': search_query,
        'status_filter': status_filter,
        'activity_filter': activity_filter,
        'change_filter': change_filter,
        'summary_stats': {
            'total_domains': total_domains,
            'active_domains': active_domains,
            'domains_with_recent_changes': domains_with_recent_changes,
            'total_checks_today': total_checks_today,
        },
        'has_filters': any([search_query, status_filter != 'all', activity_filter != 'all', change_filter != 'all']),
    }
    
    return render(request, 'admin/monitor/enhanced_domain_dashboard.html', context)


def domain_timeline_view(request, domain_id):
    """Comprehensive domain timeline view showing all activities."""
    
    domain = get_object_or_404(Domain, id=domain_id)
    
    # Get all record logs with related data
    record_logs = RecordLog.objects.filter(domain=domain).prefetch_related(
        'ip_info_entries__ip_whois_info',
        'snapshot'
    ).order_by('-timestamp')
    
    # Get domain snapshots
    snapshots = DomainSnapshot.objects.filter(domain=domain).order_by('-timestamp')
    
    # Create unified timeline
    timeline_events = []
    
    # Add record logs to timeline
    for log in record_logs:
        event_type = 'change' if log.is_change else 'check'
        if log.error_message:
            event_type = 'error'
            
        timeline_events.append({
            'type': event_type,
            'timestamp': log.timestamp,
            'title': f"DNS {'Change' if log.is_change else 'Check'}" + (f" (Error)" if log.error_message else ""),
            'data': log,
            'ips': log.get_ips_list(),
            'ip_info': log.ip_info_entries.all(),
            'has_snapshot': hasattr(log, 'snapshot') and log.snapshot,
            'error': log.error_message,
        })
    
    # Add snapshots to timeline
    for snapshot in snapshots:
        timeline_events.append({
            'type': 'snapshot',
            'timestamp': snapshot.timestamp,
            'title': f"{'Initial' if snapshot.is_initial_snapshot else 'Change'} Snapshot",
            'data': snapshot,
            'content_length': snapshot.content_length,
            'status_code': snapshot.status_code,
            'response_time': snapshot.response_time_ms,
            'error': snapshot.error_message,
        })
    
    # Sort timeline by timestamp (newest first)
    timeline_events.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Domain statistics
    domain_stats = {
        'total_checks': record_logs.count(),
        'total_changes': record_logs.filter(is_change=True).count(),
        'total_snapshots': snapshots.count(),
        'first_check': record_logs.aggregate(first=Min('timestamp'))['first'],
        'last_check': record_logs.aggregate(last=Max('timestamp'))['last'],
        'unique_ips': record_logs.values('ips').distinct().count(),
        'error_rate': record_logs.filter(error_message__isnull=False).count() / max(record_logs.count(), 1) * 100,
        'change_frequency': record_logs.filter(is_change=True).count() / max(record_logs.count(), 1) * 100,
    }
    
    # Recent activity (last 30 days)
    thirty_days_ago = timezone.now() - timedelta(days=30)
    recent_logs = record_logs.filter(timestamp__gte=thirty_days_ago)
    recent_stats = {
        'checks': recent_logs.count(),
        'changes': recent_logs.filter(is_change=True).count(),
        'errors': recent_logs.filter(error_message__isnull=False).count(),
    }
    
    context = {
        'title': f'Domain Timeline: {domain.name}',
        'domain': domain,
        'timeline_events': timeline_events[:100],  # Limit to last 100 events for performance
        'domain_stats': domain_stats,
        'recent_stats': recent_stats,
        'total_events': len(timeline_events),
    }
    
    return render(request, 'admin/monitor/domain_timeline.html', context)


def domain_export_view(request):
    """Export domain data for investigation reports."""
    
    domain_ids = request.GET.getlist('domain_ids')
    export_format = request.GET.get('format', 'json')
    
    if not domain_ids:
        return JsonResponse({'error': 'No domains selected'}, status=400)
    
    domains = Domain.objects.filter(id__in=domain_ids).prefetch_related(
        'record_logs__ip_info_entries__ip_whois_info',
        'snapshots'
    )
    
    export_data = []
    
    for domain in domains:
        domain_data = {
            'name': domain.name,
            'is_active': domain.is_active,
            'created_at': domain.created_at.isoformat(),
            'updated_at': domain.updated_at.isoformat(),
            'last_known_ips': domain.get_last_known_ips_list(),
            'record_logs': [],
            'snapshots': [],
        }
        
        # Add record logs
        for log in domain.record_logs.all()[:50]:  # Limit for performance
            log_data = {
                'timestamp': log.timestamp.isoformat(),
                'ips': log.get_ips_list(),
                'is_change': log.is_change,
                'error_message': log.error_message,
                'ip_whois_info': []
            }
            
            # Add IP WHOIS information
            for ip_info in log.ip_info_entries.all():
                if ip_info.ip_whois_info:
                    whois = ip_info.ip_whois_info
                    log_data['ip_whois_info'].append({
                        'ip_address': ip_info.ip_address,
                        'organization': whois.organization,
                        'asn': whois.asn,
                        'country': whois.country,
                        'isp': whois.isp,
                    })
            
            domain_data['record_logs'].append(log_data)
        
        # Add snapshots
        for snapshot in domain.snapshots.all()[:10]:  # Limit for performance
            snapshot_data = {
                'timestamp': snapshot.timestamp.isoformat(),
                'is_initial_snapshot': snapshot.is_initial_snapshot,
                'status_code': snapshot.status_code,
                'content_length': snapshot.content_length,
                'response_time_ms': snapshot.response_time_ms,
                'error_message': snapshot.error_message,
            }
            domain_data['snapshots'].append(snapshot_data)
        
        export_data.append(domain_data)
    
    if export_format == 'json':
        response = JsonResponse({
            'domains': export_data,
            'exported_at': timezone.now().isoformat(),
            'total_domains': len(export_data),
        }, json_dumps_params={'indent': 2})
        
        response['Content-Disposition'] = f'attachment; filename="domains_export_{timezone.now().strftime("%Y%m%d_%H%M%S")}.json"'
        return response
    
    # Add more export formats as needed (CSV, etc.)
    return JsonResponse({'error': 'Unsupported export format'}, status=400)


def bulk_domain_actions(request):
    """Handle bulk actions on domains."""
    
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    
    action = request.POST.get('action')
    domain_ids = request.POST.getlist('domain_ids')
    
    if not domain_ids:
        return JsonResponse({'error': 'No domains selected'}, status=400)
    
    domains = Domain.objects.filter(id__in=domain_ids)
    
    if action == 'activate':
        count = domains.update(is_active=True)
        return JsonResponse({'success': f'Activated {count} domains'})
    
    elif action == 'deactivate':
        count = domains.update(is_active=False)
        return JsonResponse({'success': f'Deactivated {count} domains'})
    
    elif action == 'check_now':
        # Import here to avoid circular imports
        try:
            from .tasks import check_domain_a_records
            
            scheduled_count = 0
            for domain in domains:
                try:
                    check_domain_a_records.delay(domain.id)
                    scheduled_count += 1
                except Exception as e:
                    logger.error(f"Failed to schedule check for domain {domain.name}: {e}")
            
            return JsonResponse({'success': f'Scheduled DNS checks for {scheduled_count} domains'})
        
        except ImportError:
            return JsonResponse({'error': 'DNS check task not available'}, status=500)
    
    else:
        return JsonResponse({'error': 'Unknown action'}, status=400)