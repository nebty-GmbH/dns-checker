from django.urls import path
from .api_views import (
    DomainCreateAPIView, DomainDetailAPIView, DomainListAPIView,
    DomainSnapshotListAPIView, DomainSnapshotDetailAPIView,
    IPWhoisInfoListAPIView, IPWhoisInfoDetailAPIView
)

app_name = 'monitor_api'

urlpatterns = [
    # Create new domain
    path('domains/', DomainCreateAPIView.as_view(), name='domain-create'),
    
    # Get specific domain data
    path('domains/<str:domain_name>/', DomainDetailAPIView.as_view(), name='domain-detail'),
    
    # List all domains (optional)
    path('domains/list/', DomainListAPIView.as_view(), name='domain-list'),
    
    # Snapshot endpoints
    path('domains/<str:domain_name>/snapshots/', DomainSnapshotListAPIView.as_view(), name='domain-snapshots'),
    path('snapshots/<int:snapshot_id>/', DomainSnapshotDetailAPIView.as_view(), name='snapshot-detail'),
    
    # WHOIS endpoints
    path('whois/', IPWhoisInfoListAPIView.as_view(), name='whois-list'),
    path('whois/<str:ip_address>/', IPWhoisInfoDetailAPIView.as_view(), name='whois-detail'),
]
