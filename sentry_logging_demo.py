#!/usr/bin/env python
"""
Sentry Logging Demo Script

This script demonstrates how to use Sentry logging in the DNS Checker project.
It shows both traditional Python logging (captured by Sentry's LoggingIntegration)
and direct Sentry structured logging using sentry_sdk.logger.

Run this script to test Sentry logging functionality.
"""

import logging
import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.append(str(project_root))

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dns_checker.settings")

import django  # noqa: E402

django.setup()

# Import Sentry logger after Django setup
from sentry_sdk import logger as sentry_logger  # noqa: E402

# Setup traditional Python logger
logger = logging.getLogger("sentry_demo")


def demo_traditional_logging():
    """Demonstrate traditional Python logging that will be captured by Sentry."""
    print("=== Traditional Python Logging (captured by Sentry) ===")

    # These logs will be captured by Sentry's LoggingIntegration
    logger.debug(
        "This is a debug message - may not appear in Sentry based on level config"
    )
    logger.info("DNS monitoring system started successfully")
    logger.warning("High memory usage detected: 85%")
    logger.error("Failed to connect to Redis server")
    logger.critical("Database connection pool exhausted")


def demo_sentry_structured_logging():
    """Demonstrate Sentry's structured logging capabilities."""
    print("=== Sentry Structured Logging ===")

    # Sentry structured logging with placeholder syntax
    sentry_logger.info(
        "Domain DNS check completed for {domain_name}", domain_name="example.com"
    )

    sentry_logger.warning(
        "DNS resolution timeout for domain {domain_name} after {timeout_seconds} seconds",
        domain_name="slow-dns.example.com",
        timeout_seconds=30,
    )

    sentry_logger.error(
        "Payment processing failed for order {order_id} with amount {amount}",
        order_id="or_2342",
        amount=99.99,
    )

    # Sentry logging with additional attributes
    sentry_logger.error(
        "DNS check failed with multiple issues",
        attributes={
            "domain_name": "problematic.example.com",
            "domain_id": 12345,
            "error_type": "NXDOMAIN",
            "retry_count": 3,
            "dns_server": "8.8.8.8",
            "user_id": 67890,
            "team": "dns-monitoring",
        },
    )


def demo_contextual_logging():
    """Demonstrate logging in different contexts."""
    print("=== Contextual Logging Examples ===")

    # Simulate domain monitoring task
    domain_name = "test.example.com"
    domain_id = 123

    try:
        # Simulate DNS check
        sentry_logger.info(
            "Starting DNS A record check for {domain_name}",
            domain_name=domain_name,
            attributes={
                "domain_id": domain_id,
                "check_type": "A_records",
                "scheduled": True,
            },
        )

        # Simulate successful resolution
        resolved_ips = ["192.168.1.1", "192.168.1.2"]
        sentry_logger.info(
            "DNS resolution successful for {domain_name}",
            domain_name=domain_name,
            attributes={
                "domain_id": domain_id,
                "resolved_ips": resolved_ips,
                "ip_count": len(resolved_ips),
                "response_time_ms": 150,
            },
        )

    except Exception as e:
        # Simulate error handling
        sentry_logger.error(
            "DNS check failed for {domain_name}: {error_message}",
            domain_name=domain_name,
            error_message=str(e),
            attributes={
                "domain_id": domain_id,
                "error_type": type(e).__name__,
                "retry_eligible": True,
            },
        )


def main():
    """Main demonstration function."""
    print("Sentry Logging Demonstration")
    print("=" * 40)

    # Check if Sentry is configured
    from django.conf import settings

    if not getattr(settings, "SENTRY_DSN", None):
        print("⚠️  Sentry DSN not configured. Logs will only appear in console.")
        print("   Set SENTRY_DSN in .env file to see logs in Sentry.")
    else:
        print("✅ Sentry is configured and ready to capture logs.")

    print()

    # Run demonstrations
    demo_traditional_logging()
    print()

    demo_sentry_structured_logging()
    print()

    demo_contextual_logging()
    print()

    print("Demo completed. Check your Sentry dashboard for captured logs!")
    print("Note: Logs may take a few moments to appear in Sentry.")


if __name__ == "__main__":
    main()
