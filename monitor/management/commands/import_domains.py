import os
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from monitor.models import Domain


class Command(BaseCommand):
    """
    Django management command to import domains from a text file.
    
    Usage: python manage.py import_domains /path/to/domains.txt
    """
    
    help = 'Import domains from a text file (one domain per line)'
    
    def add_arguments(self, parser):
        parser.add_argument(
            'file_path',
            type=str,
            help='Path to the text file containing domains (one per line)'
        )
        parser.add_argument(
            '--activate',
            action='store_true',
            help='Set imported domains as active for monitoring (default: True)',
            default=True
        )
        parser.add_argument(
            '--skip-existing',
            action='store_true',
            help='Skip domains that already exist in the database',
            default=False
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be imported without actually importing',
            default=False
        )
    
    def handle(self, *args, **options):
        file_path = options['file_path']
        activate = options['activate']
        skip_existing = options['skip_existing']
        dry_run = options['dry_run']
        
        # Check if file exists
        if not os.path.exists(file_path):
            raise CommandError(f'File does not exist: {file_path}')
        
        # Read domains from file
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            raise CommandError(f'Error reading file: {str(e)}')
        
        # Process domains
        domains_to_import = []
        skipped_domains = []
        invalid_domains = []
        
        for line_num, line in enumerate(lines, 1):
            domain_name = line.strip()
            
            # Skip empty lines and comments
            if not domain_name or domain_name.startswith('#'):
                continue
            
            # Basic domain validation
            if not self.is_valid_domain(domain_name):
                invalid_domains.append((line_num, domain_name))
                continue
            
            # Check if domain already exists
            if Domain.objects.filter(name=domain_name).exists():
                if skip_existing:
                    skipped_domains.append(domain_name)
                    continue
                else:
                    # Update existing domain
                    if not dry_run:
                        Domain.objects.filter(name=domain_name).update(is_active=activate)
                    skipped_domains.append(f"{domain_name} (updated)")
                    continue
            
            domains_to_import.append(domain_name)
        
        # Report what will be done
        self.stdout.write(f"\nFile: {file_path}")
        self.stdout.write(f"Total lines processed: {len(lines)}")
        self.stdout.write(f"Valid domains to import: {len(domains_to_import)}")
        self.stdout.write(f"Existing domains: {len(skipped_domains)}")
        self.stdout.write(f"Invalid domains: {len(invalid_domains)}")
        
        if invalid_domains:
            self.stdout.write("\nInvalid domains found:")
            for line_num, domain in invalid_domains:
                self.stdout.write(f"  Line {line_num}: {domain}")
        
        if skipped_domains:
            self.stdout.write(f"\nSkipped domains ({len(skipped_domains)}):")
            for domain in skipped_domains[:10]:  # Show first 10
                self.stdout.write(f"  {domain}")
            if len(skipped_domains) > 10:
                self.stdout.write(f"  ... and {len(skipped_domains) - 10} more")
        
        if not domains_to_import:
            self.stdout.write(self.style.WARNING("\nNo new domains to import."))
            return
        
        if dry_run:
            self.stdout.write(f"\nDRY RUN - Would import {len(domains_to_import)} domains:")
            for domain in domains_to_import[:10]:  # Show first 10
                self.stdout.write(f"  {domain}")
            if len(domains_to_import) > 10:
                self.stdout.write(f"  ... and {len(domains_to_import) - 10} more")
            return
        
        # Import domains
        try:
            with transaction.atomic():
                domain_objects = [
                    Domain(name=domain_name, is_active=activate)
                    for domain_name in domains_to_import
                ]
                Domain.objects.bulk_create(domain_objects)
                
            self.stdout.write(
                self.style.SUCCESS(
                    f"\nSuccessfully imported {len(domains_to_import)} domains!"
                )
            )
            
            if activate:
                self.stdout.write("All imported domains are active for monitoring.")
            else:
                self.stdout.write("All imported domains are inactive. Use --activate to enable monitoring.")
                
        except Exception as e:
            raise CommandError(f'Error importing domains: {str(e)}')
    
    def is_valid_domain(self, domain):
        """
        Basic domain validation.
        
        Args:
            domain (str): Domain name to validate
            
        Returns:
            bool: True if domain appears valid
        """
        # Remove protocol if present
        domain = domain.replace('http://', '').replace('https://', '')
        domain = domain.replace('www.', '')
        
        # Basic checks
        if not domain:
            return False
        
        if len(domain) > 253:
            return False
        
        if domain.startswith('.') or domain.endswith('.'):
            return False
        
        if '..' in domain:
            return False
        
        # Check for at least one dot (unless it's localhost)
        if '.' not in domain and domain != 'localhost':
            return False
        
        # Check for invalid characters
        allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-')
        if not set(domain).issubset(allowed_chars):
            return False
        
        return True
