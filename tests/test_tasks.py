"""
Unit tests for DNS Checker Celery tasks.
"""

from unittest.mock import Mock, patch

import pytest

from monitor.models import Domain
from monitor.tasks import check_domain_a_records, schedule_domain_checks


@pytest.mark.django_db
@pytest.mark.celery
class TestDNSCheckTasks:
    """Test cases for DNS checking tasks."""

    def test_check_domain_a_records_success(
        self, sample_domain, mock_dns_query, mock_monitor_settings
    ):
        """Test successful DNS A record check."""
        result = check_domain_a_records(sample_domain.id)

        assert result["success"] is True
        assert result["domain"] == sample_domain.name
        assert "1.2.3.4" in result["ips"]
        assert "5.6.7.8" in result["ips"]

    def test_check_domain_nonexistent(self, mock_monitor_settings):
        """Test checking non-existent domain."""
        result = check_domain_a_records(99999)

        assert result["success"] is False
        assert "does not exist" in result["error"].lower()

    @patch("dns.resolver.Resolver.resolve")
    def test_check_inactive_domain(
        self, mock_resolve, inactive_domain, mock_monitor_settings
    ):
        """Test checking inactive domain (should still process if called directly)."""
        # Mock DNS to return empty results
        mock_answer = Mock()
        mock_answer.__str__ = Mock(return_value="192.168.1.1")
        mock_resolve.return_value = [mock_answer]

        result = check_domain_a_records(inactive_domain.id)

        # The task should succeed even for inactive domains since it doesn't check activity
        # The activity check is done at the scheduling level
        assert result["success"] is True
        assert result["domain"] == inactive_domain.name


@pytest.mark.django_db
@pytest.mark.celery
class TestSchedulingTasks:
    """Test cases for task scheduling."""

    @patch("monitor.tasks.check_domain_a_records.delay")
    def test_schedule_domain_checks(self, mock_task_delay, monitor_settings):
        """Test scheduling domain checks."""
        # Create test domains
        Domain.objects.create(name="active1.com", is_active=True)
        Domain.objects.create(name="active2.com", is_active=True)
        Domain.objects.create(name="inactive.com", is_active=False)

        result = schedule_domain_checks()

        assert result["success"] is True
        assert result["scheduled_tasks"] == 2  # Only active domains
        assert mock_task_delay.call_count == 2
