#!/usr/bin/env python
"""Test script to trigger domain checks and monitor snapshots."""

import os
import sys

import django

# Add the project directory to the path
sys.path.append("/workspace")

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dns_checker.settings")
django.setup()

# Django imports must come after django.setup()
from monitor.models import Domain, DomainSnapshot  # noqa: E402
from monitor.tasks import check_domain_a_records  # noqa: E402

print("=== TESTING SNAPSHOT FUNCTIONALITY ===")

# Get current snapshot count
initial_snapshots = DomainSnapshot.objects.count()
initial_change_snapshots = DomainSnapshot.objects.filter(
    is_initial_snapshot=False
).count()

print(f"Initial snapshots: {initial_snapshots}")
print(f"Initial change snapshots: {initial_change_snapshots}")

# Get a few active domains to trigger checks
domains = list(Domain.objects.filter(is_active=True)[:3])
print(f"\nTriggering checks for {len(domains)} domains:")

for domain in domains:
    print(f"  - {domain.name}")
    check_domain_a_records.delay(domain.name)

print("\nChecks triggered. Wait 30 seconds then check for new snapshots...")
