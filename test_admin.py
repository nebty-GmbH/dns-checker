#!/usr/bin/env python
"""
Test script to check if the RecordLog admin view works without 500 errors.
"""

import os
import sys

import django
from django.contrib.auth.models import User
from django.test import Client

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dns_checker.settings")
django.setup()

# Create test client
client = Client()

# Try to create or get a superuser for testing
try:
    user = User.objects.filter(is_superuser=True).first()
    if not user:
        user = User.objects.create_superuser("admin", "admin@example.com", "admin123")
        print("Created test superuser: admin / admin123")
    else:
        print(f"Using existing superuser: {user.username}")
except Exception as e:
    print(f"Error with user setup: {e}")
    sys.exit(1)

# Login
login_response = client.login(username=user.username, password="admin123")
if not login_response:
    print("Failed to login - trying with existing user")
    # Try with any existing superuser
    for user in User.objects.filter(is_superuser=True):
        # We can't know the password, so let's force login
        client.force_login(user)
        break

print("Testing admin views...")

# Test main admin page
try:
    response = client.get("/admin/")
    print(f"Admin index: HTTP {response.status_code}")
    if response.status_code != 200:
        print(f"Error accessing admin index: {response.content}")
except Exception as e:
    print(f"Error accessing admin index: {e}")

# Test RecordLog list view
try:
    response = client.get("/admin/monitor/recordlog/")
    print(f"RecordLog list: HTTP {response.status_code}")
    if response.status_code == 500:
        print("ERROR: RecordLog admin still returns 500!")
        print(f"Response content: {response.content[:500]}")
    elif response.status_code == 200:
        print("SUCCESS: RecordLog admin works now!")
    else:
        print(f"Unexpected status code: {response.status_code}")
        print(f"Response content: {response.content[:200]}")
except Exception as e:
    print(f"Error accessing RecordLog admin: {e}")

# Test RecordLogIPInfo list view
try:
    response = client.get("/admin/monitor/recordlogipinfo/")
    print(f"RecordLogIPInfo list: HTTP {response.status_code}")
    if response.status_code == 500:
        print("ERROR: RecordLogIPInfo admin returns 500!")
    elif response.status_code == 200:
        print("SUCCESS: RecordLogIPInfo admin works!")
except Exception as e:
    print(f"Error accessing RecordLogIPInfo admin: {e}")

# Test other admin views
for model in ["domain", "ipwhoisinfo", "domainsnapshot"]:
    try:
        response = client.get(f"/admin/monitor/{model}/")
        print(f"{model} admin: HTTP {response.status_code}")
    except Exception as e:
        print(f"Error accessing {model} admin: {e}")

print("Test completed.")
