"""
Test settings for DNS Checker project.
Optimized for fast test execution with in-memory database.
"""

from .settings import *  # noqa: F403,F401

# Database configuration for tests
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}


# Disable migrations for faster tests
class DisableMigrations:
    def __contains__(self, item):
        return True

    def __getitem__(self, item):
        return None


MIGRATION_MODULES = DisableMigrations()

# Celery configuration for tests
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
CELERY_BROKER_URL = "memory://"
CELERY_RESULT_BACKEND = "cache+memory://"

# Security settings for tests
SECRET_KEY = "test-secret-key-not-for-production"
DEBUG = True
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",  # Fast for tests
]

# Logging configuration for tests
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "WARNING",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "WARNING",
    },
}

# Email backend for tests
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"

# Static files
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
}

# Cache for tests
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}

# DNS timeout for tests (shorter)
DNS_TIMEOUT_SECONDS = 2

# Test-specific monitor settings
MONITOR_SETTINGS_DEFAULTS = {
    "check_interval_minutes": 1,  # Fast for tests
    "continuous_monitoring_enabled": False,  # Disable by default in tests
    "min_check_interval_seconds": 5,  # Short for tests
    "max_parallel_checks": 2,  # Limited for tests
    "dns_timeout_seconds": 2,  # Fast timeout for tests
    "email_notifications_enabled": False,  # Disable for tests
}
