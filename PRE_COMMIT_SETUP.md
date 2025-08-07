# Pre-commit Setup Guide

This project uses pre-commit hooks to ensure code quality and consistency.

## Installation

1. Install pre-commit:
```bash
pip install pre-commit
```

2. Install the git hook scripts:
```bash
pre-commit install
```

## Usage

### Automatic (Recommended)
Pre-commit will now run automatically on every commit. If any hooks fail, the commit will be aborted and you'll need to fix the issues and try again.

### Manual Execution
You can also run pre-commit manually:

```bash
# Run on all files
pre-commit run --all-files

# Run on staged files only
pre-commit run

# Run a specific hook
pre-commit run black
pre-commit run ruff
pre-commit run django-check
```

## Hooks Included

### Code Formatting & Style
- **black**: Python code formatter
- **isort**: Import sorting
- **ruff**: Fast Python linter (replaces flake8 + many plugins)
- **pyupgrade**: Upgrades syntax for newer Python versions

### Code Quality
- **flake8**: Additional Python linting
- **django-upgrade**: Django-specific upgrades

### General Checks
- **check-ast**: Validates Python syntax
- **check-yaml**: Validates YAML files
- **check-json**: Validates JSON files
- **debug-statements**: Prevents debug statements in commits
- **trailing-whitespace**: Removes trailing whitespace
- **end-of-file-fixer**: Ensures files end with newline

### Django-Specific
- **django-check**: Runs Django's system checks
- **django-check-migrations**: Ensures no missing migrations

## Configuration Notes

- Migration files are excluded from most formatting/linting hooks
- Static files and log files are excluded from whitespace checks
- Target Python version is set to 3.11 (matching your runtime.txt)
- Django target version is set to 4.2 (matching your requirements)
- Line length is set to 88 characters (Black's default)

## Troubleshooting

If pre-commit fails:
1. Check the error message
2. Fix the issues manually or let the auto-fixing tools handle them
3. Stage the changes: `git add .`
4. Commit again: `git commit -m "your message"`

To skip pre-commit hooks (not recommended):
```bash
git commit --no-verify -m "your message"
```

To update hook versions:
```bash
pre-commit autoupdate
```
