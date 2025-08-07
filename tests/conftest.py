"""
Pytest configuration and common fixtures for DNS Checker tests.
"""

from unittest.mock import Mock, patch

import factory
import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from factory.declarations import Sequence, SubFactory

from monitor.models import Domain, MonitorSettings, RecordLog

User = get_user_model()


@pytest.fixture(autouse=True)
def mock_all_celery_tasks():
    """Auto-apply comprehensive Celery task mocking to ALL tests."""
    with (
        patch("monitor.tasks.start_continuous_monitoring.delay") as mock_start_delay,
        patch(
            "monitor.tasks.start_continuous_monitoring.apply_async"
        ) as mock_start_async,
        patch("monitor.tasks.check_domain_a_records.delay") as mock_check_delay,
        patch("monitor.tasks.check_domain_a_records.apply_async") as mock_check_async,
        patch("monitor.tasks.schedule_domain_checks.delay") as mock_schedule_delay,
        patch(
            "monitor.tasks.schedule_domain_checks.apply_async"
        ) as mock_schedule_async,
        patch("monitor.models.MonitorSettings._update_celery_schedule"),
        patch("monitor.models.MonitorSettings._manage_continuous_monitoring"),
    ):

        # Configure mock return values
        mock_start_delay.return_value = Mock(id="mock-start-delay")
        mock_start_async.return_value = Mock(id="mock-start-async")
        mock_check_delay.return_value = Mock(id="mock-check-delay")
        mock_check_async.return_value = Mock(id="mock-check-async")
        mock_schedule_delay.return_value = Mock(id="mock-schedule-delay")
        mock_schedule_async.return_value = Mock(id="mock-schedule-async")

        yield {
            "start_delay": mock_start_delay,
            "start_async": mock_start_async,
            "check_delay": mock_check_delay,
            "check_async": mock_check_async,
            "schedule_delay": mock_schedule_delay,
            "schedule_async": mock_schedule_async,
        }


@pytest.fixture
def client():
    """Django test client."""
    return Client()


@pytest.fixture
def admin_user():
    """Create an admin user for tests."""
    return User.objects.create_superuser(
        username="admin", email="admin@test.com", password="testpass123"
    )


@pytest.fixture
def regular_user():
    """Create a regular user for tests."""
    return User.objects.create_user(
        username="testuser", email="test@test.com", password="testpass123"
    )


@pytest.fixture
def authenticated_client(client, admin_user):
    """Client logged in as admin user."""
    client.force_login(admin_user)
    return client


@pytest.fixture
def sample_domain():
    """Create a sample domain for testing."""
    return Domain.objects.create(
        name="example.com", is_active=True, last_known_ips="1.2.3.4,5.6.7.8"
    )


@pytest.fixture
def inactive_domain():
    """Create an inactive domain for testing."""
    return Domain.objects.create(
        name="inactive.com", is_active=False, last_known_ips=""
    )


@pytest.fixture
def sample_record_log(sample_domain):
    """Create a sample record log for testing."""
    return RecordLog.objects.create(
        domain=sample_domain, ips="1.2.3.4,5.6.7.8", is_change=False, error_message=""
    )


@pytest.fixture
def monitor_settings():
    """Create monitor settings for testing."""
    settings, created = MonitorSettings.objects.get_or_create(
        id=1,
        defaults={
            "check_interval_minutes": 1,
            "continuous_monitoring_enabled": False,
            "min_check_interval_seconds": 5,
            "max_parallel_checks": 2,
            "dns_timeout_seconds": 2,
            "email_notifications_enabled": False,
        },
    )
    return settings


@pytest.fixture
def mock_dns_query():
    """Mock DNS query responses."""
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        # Create mock DNS answer objects that return IP strings when converted
        mock_answer1 = Mock()
        mock_answer1.__str__ = Mock(return_value="1.2.3.4")
        mock_answer2 = Mock()
        mock_answer2.__str__ = Mock(return_value="5.6.7.8")

        mock_resolve.return_value = [mock_answer1, mock_answer2]
        yield mock_resolve


@pytest.fixture
def mock_failing_dns_query():
    """Mock failing DNS query."""
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        from dns.resolver import NXDOMAIN

        mock_resolve.side_effect = NXDOMAIN()
        yield mock_resolve


@pytest.fixture
def mock_celery_task():
    """Mock Celery task execution."""
    with patch("celery.app.task.Task.apply_async") as mock_apply:
        mock_result = Mock()
        mock_result.id = "test-task-id"
        mock_apply.return_value = mock_result
        yield mock_apply


@pytest.fixture
def mock_monitor_settings():
    """Mock MonitorSettings to prevent celery schedule updates."""
    with patch("monitor.models.MonitorSettings._update_celery_schedule"):
        with patch("monitor.models.MonitorSettings._manage_continuous_monitoring"):
            with patch("monitor.models.MonitorSettings.get_settings") as mock_get:
                settings = MonitorSettings(
                    check_interval_minutes=15,
                    continuous_monitoring_enabled=True,
                    dns_timeout_seconds=10,
                    min_check_interval_seconds=60,
                    max_parallel_checks=10,
                )
                mock_get.return_value = settings
                yield settings


# Factory for creating test data
class DomainFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Domain

    name = Sequence(lambda n: f"test{n}.example.com")
    is_active = True
    last_known_ips = "1.2.3.4"


class RecordLogFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = RecordLog

    domain = SubFactory(DomainFactory)
    ips = "1.2.3.4,5.6.7.8"
    is_change = False
    error_message = ""


@pytest.fixture
def domain_factory():
    """Domain factory for creating test domains."""
    return DomainFactory


@pytest.fixture
def record_log_factory():
    """RecordLog factory for creating test record logs."""
    return RecordLogFactory
