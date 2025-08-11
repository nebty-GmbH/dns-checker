# WHOIS Records Refresh Management Command

This management command (`refresh_whois_records`) allows you to update existing WHOIS records using the improved RDAP parsing functionality.

## Why This Command is Needed

Before the WHOIS parsing fix, many records had missing organization, ISP, and country information because the code only parsed traditional WHOIS responses but the `ipwhois` library was returning RDAP (Registration Data Access Protocol) responses by default.

This command allows you to refresh existing records to populate the missing data.

## Usage

### Basic Usage

```bash
# Refresh all WHOIS records (dry run first to see what would be updated)
python manage.py refresh_whois_records --dry-run

# Actually perform the refresh
python manage.py refresh_whois_records
```

### Options

- `--missing-org-only`: Only update records where organization is None/empty
- `--dry-run`: Show what would be updated without making changes
- `--batch-size N`: Number of records to process in each batch (default: 50)
- `--delay N`: Delay in seconds between WHOIS lookups to avoid rate limiting (default: 1.0)
- `--max-records N`: Maximum number of records to process (useful for testing)

### Examples

```bash
# Only refresh records with missing organization data
python manage.py refresh_whois_records --missing-org-only

# Test with a small number of records first
python manage.py refresh_whois_records --max-records 10 --dry-run

# Refresh with custom rate limiting
python manage.py refresh_whois_records --delay 2.0 --batch-size 25

# Refresh only records missing organization data (production usage)
python manage.py refresh_whois_records --missing-org-only --delay 1.5
```

## Deployment on Production

For production use, you can run this command on your Dokku deployment:

```bash
# Connect to your Dokku app
dokku run dns-checker python manage.py refresh_whois_records --missing-org-only --dry-run

# If the dry run looks good, run the actual refresh
dokku run dns-checker python manage.py refresh_whois_records --missing-org-only --delay 1.5
```

## Rate Limiting

The command includes built-in rate limiting to avoid overwhelming WHOIS servers:

- Default delay: 1.0 second between requests
- Configurable via `--delay` option
- Processes records in batches for better progress tracking

## Error Handling

The command will:
- Continue processing even if some records fail
- Report errors for individual records
- Provide a summary at the end showing success/error counts
- Skip records that already have complete data (when using standard refresh)

## Output

The command provides detailed progress information:
- Shows which records will be processed
- Displays real-time progress during execution
- Reports when organization data is updated
- Provides a final summary with counts
