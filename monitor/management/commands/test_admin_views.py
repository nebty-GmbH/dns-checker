#!/usr/bin/env python
"""
Django management command to test admin views for 500 errors.
"""

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.test import Client


class Command(BaseCommand):
    help = "Test admin views to ensure they work without 500 errors"

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("Testing admin views..."))

        # Create test client
        client = Client()

        # Try to get a superuser for testing
        try:
            user = User.objects.filter(is_superuser=True).first()
            if not user:
                user = User.objects.create_superuser(
                    "testadmin", "test@example.com", "testpass123"
                )
                self.stdout.write("Created test superuser: testadmin / testpass123")
            else:
                self.stdout.write(f"Using existing superuser: {user.username}")
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error with user setup: {e}"))
            return

        # Force login (we don't know the password of existing users)
        client.force_login(user)

        # Test main admin page
        try:
            response = client.get("/admin/")
            self.stdout.write(f"Admin index: HTTP {response.status_code}")
            if response.status_code != 200:
                self.stdout.write(
                    self.style.ERROR(f"Admin index error: {response.status_code}")
                )
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error accessing admin index: {e}"))

        # Test RecordLog list view - this is where the 500 error was happening
        try:
            response = client.get("/admin/monitor/recordlog/")
            if response.status_code == 500:
                self.stdout.write(
                    self.style.ERROR("STILL BROKEN: RecordLog admin returns 500!")
                )
                # Try to get more details from the response
                content_str = response.content.decode("utf-8", errors="ignore")
                if "Traceback" in content_str:
                    lines = content_str.split("\n")
                    for i, line in enumerate(lines):
                        if "Traceback" in line:
                            # Print the traceback
                            traceback_lines = lines[i : i + 20]  # Get next 20 lines
                            for tb_line in traceback_lines:
                                if tb_line.strip():
                                    self.stdout.write(f"  {tb_line}")
                            break
            elif response.status_code == 200:
                self.stdout.write(
                    self.style.SUCCESS("SUCCESS: RecordLog admin works now!")
                )
            else:
                self.stdout.write(
                    self.style.WARNING(f"RecordLog list: HTTP {response.status_code}")
                )
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error accessing RecordLog admin: {e}"))

        # Test RecordLogIPInfo list view
        try:
            response = client.get("/admin/monitor/recordlogipinfo/")
            if response.status_code == 500:
                self.stdout.write(
                    self.style.ERROR("RecordLogIPInfo admin returns 500!")
                )
            elif response.status_code == 200:
                self.stdout.write(self.style.SUCCESS("RecordLogIPInfo admin works!"))
            else:
                self.stdout.write(f"RecordLogIPInfo list: HTTP {response.status_code}")
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"Error accessing RecordLogIPInfo admin: {e}")
            )

        # Test other admin views to make sure we didn't break anything
        models_to_test = [
            "domain",
            "ipwhoisinfo",
            "domainsnapshot",
            "apikey",
            "monitorsettings",
        ]
        for model in models_to_test:
            try:
                response = client.get(f"/admin/monitor/{model}/")
                if response.status_code == 200:
                    self.stdout.write(f"{model} admin: ✓ OK")
                else:
                    self.stdout.write(
                        self.style.WARNING(
                            f"{model} admin: HTTP {response.status_code}"
                        )
                    )
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"Error accessing {model} admin: {e}")
                )

        self.stdout.write(self.style.SUCCESS("Admin view testing completed."))
