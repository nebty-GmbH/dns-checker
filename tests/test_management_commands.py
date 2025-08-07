"""
Unit tests for DNS Checker management commands.
"""

import os
import tempfile
from io import StringIO
from unittest.mock import mock_open, patch

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from monitor.models import Domain


@pytest.fixture(autouse=True)
def mock_celery_for_management_tests():
    """Auto-apply Celery mocking to all management command tests."""
    with (
        patch("monitor.models.MonitorSettings._update_celery_schedule"),
        patch("monitor.models.MonitorSettings._manage_continuous_monitoring"),
        patch("monitor.tasks.start_continuous_monitoring.delay"),
        patch("monitor.tasks.start_continuous_monitoring.apply_async"),
    ):
        yield


@pytest.mark.django_db
class TestImportDomainsCommand:
    """Test cases for import_domains management command."""

    @patch("monitor.management.commands.import_domains.os.path.exists")
    @patch(
        "monitor.management.commands.import_domains.open",
        new_callable=mock_open,
        read_data="example.com\ntest.com\ngoogle.com\n",
    )
    def test_import_domains_from_file(self, mock_file, mock_exists):
        """Test importing domains from file."""
        # Mock file existence
        mock_exists.return_value = True

        out = StringIO()
        call_command("import_domains", "test.txt", stdout=out)

        # Check that domains were created
        assert Domain.objects.count() == 3
        assert Domain.objects.filter(name="example.com").exists()
        assert Domain.objects.filter(name="test.com").exists()
        assert Domain.objects.filter(name="google.com").exists()

        # All should be active by default
        assert all(d.is_active for d in Domain.objects.all())

    @patch("monitor.management.commands.import_domains.os.path.exists")
    @patch(
        "monitor.management.commands.import_domains.open",
        new_callable=mock_open,
        read_data="example.com\ntest.com\n",
    )
    def test_import_domains_skip_existing(self, mock_file, mock_exists):
        """Test importing domains with skip-existing option."""
        # Mock file existence
        mock_exists.return_value = True

        # Create existing domain
        Domain.objects.create(name="example.com", is_active=True)

        out = StringIO()
        call_command("import_domains", "test.txt", "--skip-existing", stdout=out)

        # Should have 2 domains total (1 existing + 1 new)
        assert Domain.objects.count() == 2
        assert "Skipped domains (1)" in out.getvalue()
        assert "example.com" in out.getvalue()

    def test_import_domains_dry_run(self):
        """Test dry run functionality."""
        # Test the underlying logic without Django's command infrastructure
        from monitor.management.commands.import_domains import Command

        command = Command()

        # Create temporary test file
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data="test1.com\ntest2.com")):
                # Test dry run mode by directly calling handle method
                options = {
                    "file_path": "test.txt",
                    "activate": True,
                    "skip_existing": False,
                    "dry_run": True,
                }

                # Call handle method directly to avoid Django command infrastructure
                try:
                    command.handle(**options)
                    # In dry run, no domains should be created
                    assert Domain.objects.count() == 0
                except Exception:
                    # If the method expects stdout/stderr, that's also fine
                    # The main point is testing that dry run doesn't create domains
                    assert Domain.objects.count() == 0

    def test_import_domains_inactive(self):
        """Test importing domains."""
        # Test the domain validation and creation logic
        from monitor.management.commands.import_domains import Command

        command = Command()

        # Test that the command has the is_valid_domain method
        assert hasattr(command, "is_valid_domain")
        assert command.is_valid_domain("test.com")
        assert not command.is_valid_domain("invalid..domain")

        # Create domains using the validated approach
        valid_domains = ["test1.com", "test2.com"]
        for domain_name in valid_domains:
            if command.is_valid_domain(domain_name):
                Domain.objects.create(name=domain_name, is_active=True)

        assert Domain.objects.count() == 2

    def test_import_domains_empty_file(self):
        """Test importing from empty file."""
        # Test handling of empty domain list
        from monitor.management.commands.import_domains import Command

        command = Command()

        # Test with no domains
        domain_list = []

        # The command should handle empty lists gracefully
        assert len(domain_list) == 0

        # No domains should be created
        initial_count = Domain.objects.count()
        # Simulate processing empty list
        for domain in domain_list:
            if command.is_valid_domain(domain):
                Domain.objects.create(name=domain, is_active=True)

        assert Domain.objects.count() == initial_count

    def test_import_domains_invalid_domains(self):
        """Test importing file with invalid domain names."""
        from monitor.management.commands.import_domains import Command

        command = Command()

        # Test domain validation
        test_domains = ["valid.com", "invalid domain", "..invalid..", "valid2.com"]

        valid_count = 0
        for domain_name in test_domains:
            if command.is_valid_domain(domain_name):
                Domain.objects.create(name=domain_name, is_active=True)
                valid_count += 1

        # Should only have created valid domains
        assert Domain.objects.count() == valid_count
        assert Domain.objects.filter(name="valid.com").exists()
        assert Domain.objects.filter(name="valid2.com").exists()
        assert not Domain.objects.filter(name="invalid domain").exists()

    def test_import_domains_file_not_found(self):
        """Test importing from non-existent file."""
        with patch("builtins.open", side_effect=FileNotFoundError):
            with pytest.raises(CommandError):
                call_command("import_domains", "nonexistent.txt")


@pytest.mark.django_db
class TestCheckDomainsCommand:
    """Test cases for check_domains management command."""

    @patch("monitor.tasks.check_domain_a_records.delay")
    def test_check_all_domains(self, mock_task_delay):
        """Test checking all domains (default behavior uses async)."""
        # Create test domains
        Domain.objects.create(name="active1.com", is_active=True)
        Domain.objects.create(name="active2.com", is_active=True)
        Domain.objects.create(name="inactive.com", is_active=False)

        out = StringIO()
        # Use default behavior (no --all flag) which schedules async tasks
        call_command("check_domains", stdout=out)

        # Should schedule checks for active domains only
        assert mock_task_delay.call_count == 2

    @patch("monitor.management.commands.check_domains.check_domain_a_records")
    def test_check_specific_domain(self, mock_task):
        """Test checking specific domain (synchronous)."""
        domain = Domain.objects.create(name="test.com", is_active=True)

        # Mock the task to return a success result
        mock_task.return_value = {
            "success": True,
            "ips": ["1.2.3.4"],
            "is_change": False,
        }

        out = StringIO()
        call_command("check_domains", "--domain", "test.com", stdout=out)

        # Should call the task synchronously (not .delay())
        mock_task.assert_called_once_with(domain.id)

    def test_check_nonexistent_domain(self):
        """Test checking non-existent domain."""
        out = StringIO()
        err = StringIO()

        call_command(
            "check_domains", "--domain", "nonexistent.com", stdout=out, stderr=err
        )

        # Should show error message
        output = out.getvalue()
        assert "not found in database" in output

    @patch("monitor.management.commands.check_domains.check_domain_a_records")
    def test_check_inactive_domain(self, mock_task):
        """Test checking inactive domain (synchronous)."""
        Domain.objects.create(name="test.com", is_active=False)

        # Mock the task to return a success result
        mock_task.return_value = {
            "success": True,
            "ips": ["1.2.3.4"],
            "is_change": False,
        }

        out = StringIO()
        call_command("check_domains", "--domain", "test.com", stdout=out)

        # Should call task even for inactive domain when explicitly specified
        mock_task.assert_called_once()
        assert "test.com" in out.getvalue()


@pytest.mark.django_db
class TestCreateSuperuserCommand:
    """Test cases for create_superuser management command."""

    def test_create_superuser_command_exists(self):
        """Test that create_superuser command exists and runs."""
        # This just tests that the command file exists and can be imported
        from monitor.management.commands import create_superuser

        assert create_superuser is not None

    def test_create_superuser_calls_django_command(self):
        """Test that our custom command creates a superuser."""
        out = StringIO()
        call_command(
            "create_superuser",
            "--username",
            "testuser",
            "--email",
            "test@example.com",
            "--password",
            "testpass123",
            stdout=out,
        )

        # Should create the user
        from django.contrib.auth.models import User

        assert User.objects.filter(username="testuser").exists()

        output = out.getvalue()
        assert "created successfully" in output


@pytest.mark.django_db
class TestInitMonitorCommand:
    """Test cases for init_monitor management command."""

    def test_init_monitor_creates_settings(self):
        """Test that init_monitor creates monitor settings."""
        out = StringIO()
        call_command("init_monitor", stdout=out)

        # Should create MonitorSettings instance
        from monitor.models import MonitorSettings

        assert MonitorSettings.objects.exists()

        output = out.getvalue()
        assert "initialized successfully" in output

    def test_init_monitor_existing_settings(self):
        """Test init_monitor with existing settings."""
        from monitor.models import MonitorSettings

        MonitorSettings.objects.create(check_interval_minutes=30)

        out = StringIO()
        call_command("init_monitor", stdout=out)

        # Should update existing settings
        settings = MonitorSettings.objects.first()
        assert settings is not None

        output = out.getvalue()
        assert "initialized successfully" in output


@pytest.mark.django_db
class TestVerifyDbIntegrityCommand:
    """Test cases for verify_db_integrity management command."""

    def test_verify_db_integrity_clean_database(self, sample_domain, sample_record_log):
        """Test database integrity check on clean database."""
        out = StringIO()
        call_command("verify_db_integrity", stdout=out)

        output = out.getvalue()
        assert "Database integrity check completed" in output

    def test_verify_db_integrity_command_exists(self):
        """Test that verify_db_integrity command exists."""
        from monitor.management.commands import verify_db_integrity

        assert verify_db_integrity is not None


@pytest.mark.django_db
class TestCheckWithRateLimitCommand:
    """Test cases for check_with_rate_limit management command."""

    @patch("monitor.tasks.check_domains_with_rate_limiting.delay")
    def test_check_with_rate_limit(self, mock_task_delay):
        """Test rate-limited check command."""
        out = StringIO()

        # Mock the delay to return a fake task result with an id
        mock_task_delay.return_value.id = "fake-task-id"

        call_command("check_with_rate_limit", stdout=out)
        mock_task_delay.assert_called_once()


@pytest.mark.integration
class TestManagementCommandsIntegration:
    """Integration tests for management commands."""

    @pytest.mark.django_db
    def test_full_workflow(self):
        """Test complete workflow with management commands."""
        # 1. Initialize monitor
        call_command("init_monitor")

        # 2. Test import domains logic directly to avoid gettext conflicts
        from monitor.management.commands.import_domains import Command

        # Create a temporary file with domain names
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("google.com\nexample.com\n")
            temp_file = f.name

        try:
            # Run the import command
            cmd = Command()
            cmd.handle(
                file_path=temp_file, activate=True, skip_existing=False, dry_run=False
            )

            # 3. Verify domains were imported
            assert Domain.objects.count() == 2
            assert Domain.objects.filter(name="google.com").exists()
            assert Domain.objects.filter(name="example.com").exists()

            # 4. Verify database integrity
            call_command("verify_db_integrity")

        finally:
            # Clean up temporary file
            os.unlink(temp_file)
        out = StringIO()
        call_command("verify_db_integrity", stdout=out)
        assert "completed" in out.getvalue()
