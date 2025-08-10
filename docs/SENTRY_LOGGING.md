# Sentry Logging Implementation

This document explains how Sentry logging has been implemented in the DNS Checker project and how to use it effectively.

## Overview

Sentry logging provides error monitoring and structured logging capabilities for the DNS Checker application. The implementation includes:

- **Error Monitoring**: Automatic capture of errors and exceptions
- **Structured Logs**: Searchable, filterable logs with custom attributes
- **Performance Monitoring**: Transaction tracking for Django views and Celery tasks
- **Integration**: Seamless integration with Django and Celery

## Configuration

### Environment Variables

Add the following environment variables to your `.env` file:

```env
# Sentry Configuration
SENTRY_DSN=https://your-sentry-dsn@sentry.io/project-id
SENTRY_ENVIRONMENT=development  # or production, staging, etc.
SENTRY_ENABLE_LOGS=True
SENTRY_LOG_LEVEL=INFO
SENTRY_EVENT_LEVEL=ERROR
```

### Sentry DSN Setup

1. Create a Sentry account at [sentry.io](https://sentry.io)
2. Create a new project for "Django"
3. Copy the DSN URL from your project settings
4. Add it to your `.env` file as `SENTRY_DSN`

## Features Implemented

### 1. Automatic Error Capture

All unhandled exceptions in Django views and Celery tasks are automatically captured and sent to Sentry.

### 2. Structured Logging (Beta)

Sentry Logs allows you to send structured, searchable logs:

```python
from sentry_sdk import logger as sentry_logger

# Structured logging with placeholders
sentry_logger.info(
    "DNS check completed for {domain_name}",
    domain_name="example.com"
)

# Logging with additional attributes
sentry_logger.error(
    "DNS resolution failed",
    attributes={
        "domain_name": "example.com",
        "domain_id": 123,
        "error_type": "NXDOMAIN",
        "retry_count": 3
    }
)
```

### 3. Traditional Python Logging Integration

All existing Python logging statements are automatically captured:

```python
import logging

logger = logging.getLogger("monitor")
logger.error("This will be sent to Sentry")  # Automatically captured
```

### 4. Performance Monitoring

- **Django Integration**: Tracks HTTP requests as transactions
- **Celery Integration**: Tracks task execution and performance
- **Database Queries**: Monitors slow database operations

## Usage Examples

### Basic Logging

```python
from sentry_sdk import logger as sentry_logger
import logging

# Traditional logging (automatically captured)
logger = logging.getLogger("monitor")
logger.info("System started successfully")
logger.error("Database connection failed")

# Sentry structured logging
sentry_logger.info("User logged in successfully")
sentry_logger.warning("Rate limit approaching")
```

### DNS Monitoring Context

```python
# When checking DNS records
sentry_logger.info(
    "Starting DNS check for {domain_name}",
    domain_name=domain.name,
    attributes={
        "domain_id": domain.id,
        "check_type": "A_records",
        "scheduled": True
    }
)

# When DNS changes are detected
sentry_logger.warning(
    "DNS change detected for {domain_name}",
    domain_name=domain.name,
    attributes={
        "domain_id": domain.id,
        "old_ips": previous_ips,
        "new_ips": current_ips,
        "change_significance": "major"
    }
)
```

### Error Handling

```python
try:
    # DNS resolution
    answers = resolver.resolve(domain.name, "A")
except dns.resolver.NXDOMAIN:
    sentry_logger.error(
        "Domain does not exist: {domain_name}",
        domain_name=domain.name,
        attributes={
            "domain_id": domain.id,
            "error_type": "NXDOMAIN",
            "resolver_config": resolver_settings
        }
    )
```

## Log Levels and Filtering

### Configuration

- `SENTRY_LOG_LEVEL`: Controls which Python logs are captured as breadcrumbs/events (default: INFO)
- `SENTRY_EVENT_LEVEL`: Controls which logs are sent as error events (default: ERROR)

### Custom Filtering

The `before_send_log` function in settings allows custom log filtering:

```python
def before_send_log(log, hint):
    # Filter out health check logs
    if "health" in log.get("body", "").lower():
        return None

    # Add team context to error logs
    if log.get("severity_text") == "error":
        log.setdefault("attributes", {})["team"] = "dns-monitoring"

    return log
```

## Testing Sentry Integration

### Demo Script

Run the included demo script to test Sentry logging:

```bash
python sentry_logging_demo.py
```

This script demonstrates:
- Traditional Python logging
- Sentry structured logging
- Contextual logging examples

### Verification Steps

1. Set up your Sentry DSN in `.env`
2. Run the demo script
3. Check your Sentry dashboard for captured logs
4. Verify different log levels are being captured correctly

## Integration Points

### Django Views

All Django views automatically have their requests tracked as transactions. Errors in views are captured with request context.

### Celery Tasks

All Celery tasks are tracked with performance monitoring. Task failures are captured with full context including task arguments.

### Database Operations

Slow database queries and connection issues are automatically monitored.

## Best Practices

### 1. Use Structured Logging

Prefer Sentry's structured logging over string formatting:

```python
# Good
sentry_logger.info(
    "User {user_id} performed action {action}",
    user_id=123,
    action="domain_check"
)

# Avoid
sentry_logger.info(f"User {user_id} performed action {action}")
```

### 2. Include Context Attributes

Add relevant attributes to help with debugging:

```python
sentry_logger.error(
    "Task failed",
    attributes={
        "task_name": "check_domain_a_records",
        "domain_id": domain_id,
        "retry_count": self.request.retries,
        "execution_time_ms": execution_time
    }
)
```

### 3. Use Appropriate Log Levels

- `trace/debug`: Development debugging
- `info`: General operational messages
- `warning`: Potential issues that don't stop operation
- `error`: Errors that need attention
- `fatal/critical`: System-breaking errors

### 4. Avoid Sensitive Information

Never log sensitive data like passwords, API keys, or personal information.

## Monitoring and Alerts

### Sentry Dashboard

- **Issues**: Track errors and exceptions
- **Performance**: Monitor transaction performance
- **Logs**: Search and filter structured logs (Beta feature)

### Alert Configuration

Set up alerts in Sentry for:
- High error rates
- New error types
- Performance degradation
- Specific log patterns

## Troubleshooting

### Common Issues

1. **Logs not appearing**: Check SENTRY_DSN configuration
2. **Too many logs**: Adjust SENTRY_LOG_LEVEL or add filtering
3. **Missing context**: Ensure attributes are being passed correctly

### Debug Mode

In development, logs also appear in the console even when Sentry is configured.

## Production Considerations

### Performance Impact

- Sentry has minimal performance impact
- Configure appropriate sampling rates
- Use log filtering to reduce noise

### Data Retention

- Configure appropriate data retention policies in Sentry
- Monitor usage to stay within plan limits

### Security

- Store SENTRY_DSN securely
- Configure appropriate PII handling
- Review captured data periodically
