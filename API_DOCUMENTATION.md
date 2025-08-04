# DNS Checker API Documentation

## Overview

The DNS Checker API provides endpoints to manage domain monitoring and retrieve DNS change data. Authentication is handled via API keys.

## Authentication

All API requests require authentication using an API key. Include the API key in the Authorization header:

```
Authorization: ApiKey your_api_key_here
```

### Managing API Keys

1. Log in to the Django admin panel: `https://your-domain/admin/`
2. Navigate to "Monitor" → "API Keys"
3. Click "Add API Key" to create a new key
4. Provide a descriptive name and select a user
5. Save the record and copy the generated API key (it will only be shown once in full)

## API Endpoints

Base URL: https://dns-checker.116.203.84.42.sslip.io

### 1. Add New Domain

**Endpoint:** `POST /api/domains/`

**Description:** Adds a new domain to the monitoring system and triggers an immediate DNS check.

**Request Body:**
```json
{
    "name": "example.com",
    "is_active": true
}
```

**Response (201 Created):**
```json
{
    "id": 1,
    "name": "example.com",
    "is_active": true,
    "last_known_ips": "",
    "last_known_ips_list": [],
    "updated_at": "2025-08-04T10:00:00Z",
    "created_at": "2025-08-04T10:00:00Z",
    "recent_logs": [],
    "total_logs": 0,
    "changes_count": 0
}
```

**Example cURL:**
```bash
curl -X POST https://your-domain/api/domains/ \
  -H "Authorization: ApiKey your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{"name": "example.com", "is_active": true}'
```

### 2. Get Domain Data

**Endpoint:** `GET /api/domains/{domain_name}/`

**Description:** Retrieves detailed information about a specific domain, including recent DNS check logs.

**Path Parameters:**
- `domain_name`: The domain name to retrieve (case-insensitive)

**Response (200 OK):**
```json
{
    "id": 1,
    "name": "example.com",
    "is_active": true,
    "last_known_ips": "93.184.216.34",
    "last_known_ips_list": ["93.184.216.34"],
    "updated_at": "2025-08-04T10:15:00Z",
    "created_at": "2025-08-04T10:00:00Z",
    "recent_logs": [
        {
            "id": 1,
            "domain_name": "example.com",
            "ips": "93.184.216.34",
            "ips_list": ["93.184.216.34"],
            "is_change": false,
            "timestamp": "2025-08-04T10:15:00Z",
            "error_message": null
        }
    ],
    "total_logs": 1,
    "changes_count": 0
}
```

**Example cURL:**
```bash
curl -X GET https://your-domain/api/domains/example.com/ \
  -H "Authorization: ApiKey your_api_key_here"
```

### 3. List All Domains (Optional)

**Endpoint:** `GET /api/domains/list/`

**Description:** Retrieves a list of all domains in the system.

**Query Parameters:**
- `is_active` (optional): Filter by active status (`true` or `false`)

**Response (200 OK):**
```json
[
    {
        "id": 1,
        "name": "example.com",
        "is_active": true,
        "last_known_ips": "93.184.216.34",
        "last_known_ips_list": ["93.184.216.34"],
        "updated_at": "2025-08-04T10:15:00Z",
        "created_at": "2025-08-04T10:00:00Z",
        "latest_check": {
            "id": 1,
            "domain_name": "example.com",
            "ips": "93.184.216.34",
            "ips_list": ["93.184.216.34"],
            "is_change": false,
            "timestamp": "2025-08-04T10:15:00Z",
            "error_message": null
        }
    }
]
```

**Example cURL:**
```bash
# Get all domains
curl -X GET https://your-domain/api/domains/list/ \
  -H "Authorization: ApiKey your_api_key_here"

# Get only active domains
curl -X GET https://your-domain/api/domains/list/?is_active=true \
  -H "Authorization: ApiKey your_api_key_here"
```

## Error Responses

### Authentication Errors

**401 Unauthorized:**
```json
{
    "detail": "Authentication credentials were not provided."
}
```

**401 Unauthorized (Invalid API Key):**
```json
{
    "detail": "Invalid API key."
}
```

### Validation Errors

**400 Bad Request:**
```json
{
    "name": ["Domain already exists."]
}
```

**400 Bad Request (Invalid domain):**
```json
{
    "name": ["Invalid domain name format."]
}
```

### Not Found Errors

**404 Not Found:**
```json
{
    "detail": "Not found."
}
```

## Response Fields

### Domain Fields

- `id`: Unique identifier for the domain
- `name`: Domain name (e.g., "example.com")
- `is_active`: Whether the domain is currently being monitored
- `last_known_ips`: Comma-separated string of last known IP addresses
- `last_known_ips_list`: Array of last known IP addresses
- `updated_at`: Timestamp of last DNS check
- `created_at`: Timestamp when domain was added
- `recent_logs`: Array of the 10 most recent DNS check logs
- `total_logs`: Total number of DNS checks performed
- `changes_count`: Number of times the IP addresses changed

### RecordLog Fields

- `id`: Unique identifier for the log entry
- `domain_name`: Name of the domain that was checked
- `ips`: Comma-separated string of IP addresses found
- `ips_list`: Array of IP addresses found
- `is_change`: Whether this check detected a change from previous IPs
- `timestamp`: When the DNS check was performed
- `error_message`: Error message if DNS lookup failed (null if successful)

## Rate Limiting

Currently, there are no rate limits implemented, but it's recommended to:
- Avoid making excessive requests
- Cache responses when appropriate
- Use the monitoring system's built-in periodic checks rather than polling frequently

## Notes

- Domain names are stored and compared in lowercase
- When adding a new domain, an immediate DNS check is triggered
- The system automatically checks all active domains every 15 minutes
- IP addresses are automatically sorted for consistent comparison
- API keys track last usage timestamp for security monitoring
