#!/usr/bin/env python
"""
Test script to demonstrate duplicate domain handling behavior.
"""
import os

import django

# Setup Django environment
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dns_checker.settings")
django.setup()

from monitor.models import Domain  # noqa: E402
from monitor.serializers import DomainCreateSerializer  # noqa: E402


def test_duplicate_handling():
    """Test how the system handles duplicate domains."""
    print("Testing duplicate domain handling...\n")

    # Test domain name
    test_domain = "test-example.com"

    # Clean up any existing test domain
    Domain.objects.filter(name=test_domain).delete()
    print(f"Cleaned up any existing '{test_domain}' domain")

    print("\n1. Testing first domain creation:")
    try:
        # Create first domain using the serializer (like the API does)
        serializer1 = DomainCreateSerializer(
            data={"name": test_domain, "is_active": True}
        )
        if serializer1.is_valid():
            domain1 = serializer1.save()
            print(f"✅ Successfully created domain: {domain1.name} (ID: {domain1.id})")
        else:
            print(f"❌ Failed to create first domain: {serializer1.errors}")
    except Exception as e:
        print(f"❌ Exception creating first domain: {e}")

    print("\n2. Testing duplicate domain creation:")
    try:
        # Try to create the same domain again
        serializer2 = DomainCreateSerializer(
            data={"name": test_domain, "is_active": True}
        )
        if serializer2.is_valid():
            domain2 = serializer2.save()
            print(
                f"❌ UNEXPECTED: Created duplicate domain: {domain2.name} "
                f"(ID: {domain2.id})"
            )
        else:
            print(f"✅ Correctly prevented duplicate: {serializer2.errors}")
    except Exception as e:
        print(f"✅ Exception prevented duplicate creation: {e}")

    print("\n3. Testing case-insensitive duplicate:")
    try:
        # Try to create with different case
        upper_domain = test_domain.upper()
        serializer3 = DomainCreateSerializer(
            data={"name": upper_domain, "is_active": True}
        )
        if serializer3.is_valid():
            domain3 = serializer3.save()
            print(
                f"❌ UNEXPECTED: Created case-variant domain: {domain3.name} "
                f"(ID: {domain3.id})"
            )
        else:
            print(
                f"✅ Correctly prevented case-variant duplicate: {serializer3.errors}"
            )
    except Exception as e:
        print(f"✅ Exception prevented case-variant duplicate: {e}")

    print("\n4. Database uniqueness constraint test:")
    try:
        # Try to create directly in the database (bypassing serializer validation)
        domain_direct = Domain(name=test_domain, is_active=True)
        domain_direct.save()
        print(f"❌ UNEXPECTED: Database allowed duplicate domain: {domain_direct.name}")
    except Exception as e:
        print(f"✅ Database constraint prevented duplicate: {e}")

    print("\n5. Current domains in database:")
    domains = Domain.objects.filter(name__icontains="test-example")
    for domain in domains:
        print(f"  - {domain.name} (ID: {domain.id}, Active: {domain.is_active})")

    # Clean up
    Domain.objects.filter(name=test_domain).delete()
    print(f"\n✅ Cleaned up test domain '{test_domain}'")


if __name__ == "__main__":
    test_duplicate_handling()
