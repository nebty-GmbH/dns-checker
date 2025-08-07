from django.shortcuts import get_object_or_404
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .authentication import APIKeyAuthentication
from .models import Domain, DomainSnapshot, IPWhoisInfo
from .serializers import (
    DomainCreateSerializer,
    DomainDetailSerializer,
    DomainSerializer,
    DomainSnapshotDetailSerializer,
    DomainSnapshotSerializer,
    IPWhoisInfoSerializer,
)


class DomainCreateAPIView(generics.CreateAPIView):
    """
    API endpoint to create a new domain for monitoring.

    POST /api/domains/
    {
        "name": "example.com",
        "is_active": true
    }
    """

    queryset = Domain.objects.all()
    serializer_class = DomainCreateSerializer
    authentication_classes = [APIKeyAuthentication]
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        """Save the domain and trigger initial check"""
        domain = serializer.save()

        # Trigger an immediate check for the new domain
        from .tasks import check_domain_a_records

        check_domain_a_records.delay(domain.id)

        return domain

    def create(self, request, *args, **kwargs):
        """Override create to return detailed domain info"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        domain = self.perform_create(serializer)

        # Return detailed domain information
        detail_serializer = DomainDetailSerializer(domain)
        headers = self.get_success_headers(detail_serializer.data)
        return Response(
            detail_serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )


class DomainDetailAPIView(generics.RetrieveAPIView):
    """
    API endpoint to get detailed information about a specific domain.

    GET /api/domains/{domain_name}/
    """

    serializer_class = DomainDetailSerializer
    authentication_classes = [APIKeyAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = "name"
    lookup_url_kwarg = "domain_name"

    def get_queryset(self):
        return Domain.objects.all()

    def get_object(self):
        """Get domain by name (case-insensitive)"""
        domain_name = self.kwargs["domain_name"].lower()
        return get_object_or_404(Domain, name=domain_name)


class DomainListAPIView(generics.ListAPIView):
    """
    API endpoint to list all domains (optional, for convenience).

    GET /api/domains/list/
    """

    queryset = Domain.objects.all()
    serializer_class = DomainSerializer
    authentication_classes = [APIKeyAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Optionally filter by active status"""
        queryset = Domain.objects.all()
        is_active = self.request.query_params.get("is_active", None)
        if is_active is not None:
            is_active = is_active.lower() in ["true", "1"]
            queryset = queryset.filter(is_active=is_active)
        return queryset.order_by("name")


class DomainSnapshotListAPIView(generics.ListAPIView):
    """
    API endpoint to list snapshots for a specific domain.

    GET /api/domains/{domain_name}/snapshots/
    """

    serializer_class = DomainSnapshotSerializer
    authentication_classes = [APIKeyAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Get snapshots for the specified domain"""
        domain_name = self.kwargs["domain_name"].lower()
        domain = get_object_or_404(Domain, name=domain_name)
        return domain.snapshots.all().order_by("-timestamp")


class DomainSnapshotDetailAPIView(generics.RetrieveAPIView):
    """
    API endpoint to get detailed information about a specific snapshot.

    GET /api/snapshots/{snapshot_id}/
    """

    serializer_class = DomainSnapshotDetailSerializer
    authentication_classes = [APIKeyAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = "id"
    lookup_url_kwarg = "snapshot_id"

    def get_queryset(self):
        return DomainSnapshot.objects.all()


class IPWhoisInfoListAPIView(generics.ListAPIView):
    """
    API endpoint to list all WHOIS information.

    GET /api/whois/
    """

    queryset = IPWhoisInfo.objects.all().order_by("-created_at")
    serializer_class = IPWhoisInfoSerializer
    authentication_classes = [APIKeyAuthentication]
    permission_classes = [IsAuthenticated]


class IPWhoisInfoDetailAPIView(generics.RetrieveAPIView):
    """
    API endpoint to get WHOIS information for a specific IP.

    GET /api/whois/{ip_address}/
    """

    serializer_class = IPWhoisInfoSerializer
    authentication_classes = [APIKeyAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = "ip_address"
    lookup_url_kwarg = "ip_address"

    def get_queryset(self):
        return IPWhoisInfo.objects.all()
