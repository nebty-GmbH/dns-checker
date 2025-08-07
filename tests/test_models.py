"""
Unit tests for DNS Checker models.
"""

from unittest.mock import patch

import pytest
from django.db import IntegrityError

from monitor.models import Domain, MonitorSettings, RecordLog


@pytest.mark.django_db
class TestDomain:
    """Test cases for Domain model."""

    def test_create_domain(self):
        """Test creating a domain."""
        domain = Domain.objects.create(
            name="test.com", is_active=True, last_known_ips="1.2.3.4"
        )
        assert domain.name == "test.com"
        assert domain.is_active is True
        assert domain.last_known_ips == "1.2.3.4"
        assert domain.created_at is not None
        assert domain.updated_at is not None

    def test_domain_unique_name(self):
        """Test that domain names must be unique."""
        Domain.objects.create(name="test.com")
        with pytest.raises(IntegrityError):
            Domain.objects.create(name="test.com")

    def test_domain_str_representation(self):
        """Test domain string representation."""
        domain = Domain.objects.create(name="test.com")
        assert str(domain) == "test.com"

    def test_domain_ordering(self):
        """Test that domains are ordered by name."""
        Domain.objects.create(name="zebra.com")
        Domain.objects.create(name="alpha.com")
        Domain.objects.create(name="beta.com")

        domains = list(Domain.objects.all())
        names = [d.name for d in domains]
        assert names == ["alpha.com", "beta.com", "zebra.com"]


@pytest.mark.django_db
class TestRecordLog:
    """Test cases for RecordLog model."""

    def test_create_record_log(self, sample_domain):
        """Test creating a record log."""
        record_log = RecordLog.objects.create(
            domain=sample_domain,
            ips="1.2.3.4,5.6.7.8",
            is_change=True,
            error_message="",
        )
        assert record_log.domain == sample_domain
        assert record_log.ips == "1.2.3.4,5.6.7.8"
        assert record_log.is_change is True
        assert record_log.error_message == ""
        assert record_log.timestamp is not None

    def test_record_log_str_representation(self, sample_domain):
        """Test record log string representation."""
        record_log = RecordLog.objects.create(
            domain=sample_domain, ips="1.2.3.4", is_change=False
        )
        str_repr = str(record_log)
        assert sample_domain.name in str_repr
        assert "NO CHANGE" in str_repr
        assert record_log.timestamp.strftime("%Y-%m-%d %H:%M:%S") in str_repr

    def test_record_log_str_with_error(self, sample_domain):
        """Test record log string representation with error."""
        record_log = RecordLog.objects.create(
            domain=sample_domain, ips="", error_message="DNS timeout"
        )
        str_repr = str(record_log)
        assert "ERROR" in str_repr

    def test_record_log_ordering(self, sample_domain):
        """Test that record logs are ordered by timestamp descending."""
        # Create logs with different timestamps
        old_log = RecordLog.objects.create(domain=sample_domain, ips="1.1.1.1")
        new_log = RecordLog.objects.create(domain=sample_domain, ips="2.2.2.2")

        logs = list(RecordLog.objects.all())
        assert logs[0] == new_log  # Most recent first
        assert logs[1] == old_log


@pytest.mark.django_db
class TestMonitorSettings:
    """Test cases for MonitorSettings model."""

    @patch("monitor.models.MonitorSettings._update_celery_schedule")
    @patch("monitor.models.MonitorSettings._manage_continuous_monitoring")
    def test_create_monitor_settings(
        self, mock_manage_monitoring, mock_update_schedule
    ):
        """Test creating monitor settings."""
        settings = MonitorSettings.objects.create(
            check_interval_minutes=15,
            continuous_monitoring_enabled=True,
            min_check_interval_seconds=60,
            max_parallel_checks=5,
            dns_timeout_seconds=10,
            email_notifications_enabled=True,
        )
        assert settings.check_interval_minutes == 15
        assert settings.continuous_monitoring_enabled is True
        assert settings.min_check_interval_seconds == 60
        assert settings.max_parallel_checks == 5
        assert settings.dns_timeout_seconds == 10
        assert settings.email_notifications_enabled is True

    @patch("monitor.models.MonitorSettings._update_celery_schedule")
    @patch("monitor.models.MonitorSettings._manage_continuous_monitoring")
    def test_monitor_settings_str_continuous(
        self, mock_manage_monitoring, mock_update_schedule
    ):
        """Test string representation for continuous monitoring."""
        settings = MonitorSettings.objects.create(
            continuous_monitoring_enabled=True, min_check_interval_seconds=60
        )
        str_repr = str(settings)
        assert "Continuous monitoring" in str_repr
        assert "60s rate limit" in str_repr

    @patch("monitor.models.MonitorSettings._update_celery_schedule")
    @patch("monitor.models.MonitorSettings._manage_continuous_monitoring")
    def test_monitor_settings_str_periodic(
        self, mock_manage_monitoring, mock_update_schedule
    ):
        """Test string representation for periodic monitoring."""
        settings = MonitorSettings.objects.create(
            continuous_monitoring_enabled=False, check_interval_minutes=15
        )
        str_repr = str(settings)
        assert "Check every 15 minutes" in str_repr

    @patch("monitor.models.MonitorSettings._update_celery_schedule")
    @patch("monitor.models.MonitorSettings._manage_continuous_monitoring")
    def test_monitor_settings_singleton(
        self, mock_manage_monitoring, mock_update_schedule
    ):
        """Test that only one MonitorSettings instance can exist."""
        settings1 = MonitorSettings.objects.create(check_interval_minutes=20)
        assert MonitorSettings.objects.count() == 1

        # Create another instance - should replace the first one
        settings2 = MonitorSettings.objects.create(check_interval_minutes=30)
        assert MonitorSettings.objects.count() == 1
        assert settings2.check_interval_minutes == 30

        # Verify the first instance was deleted
        with pytest.raises(MonitorSettings.DoesNotExist):
            settings1.refresh_from_db()
