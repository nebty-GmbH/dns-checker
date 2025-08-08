"""
URL patterns for enhanced admin views.
"""

from django.urls import path
from . import admin_views

app_name = 'monitor_admin'

urlpatterns = [
    path('enhanced-dashboard/', admin_views.enhanced_domain_dashboard, name='enhanced_domain_dashboard'),
    path('domain/<int:domain_id>/timeline/', admin_views.domain_timeline_view, name='domain_timeline'),
    path('domain/export/', admin_views.domain_export_view, name='domain_export'),
    path('domain/bulk-actions/', admin_views.bulk_domain_actions, name='bulk_domain_actions'),
]