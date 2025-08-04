from django.urls import path
from .api_views import DomainCreateAPIView, DomainDetailAPIView, DomainListAPIView

app_name = 'monitor_api'

urlpatterns = [
    # Create new domain
    path('domains/', DomainCreateAPIView.as_view(), name='domain-create'),
    
    # Get specific domain data
    path('domains/<str:domain_name>/', DomainDetailAPIView.as_view(), name='domain-detail'),
    
    # List all domains (optional)
    path('domains/list/', DomainListAPIView.as_view(), name='domain-list'),
]
