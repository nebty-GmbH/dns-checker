#!/usr/bin/env python
"""
Django management command to verify database integrity for the DNS monitoring system.
This helps debug potential issues with the admin interface.
"""

from django.core.management.base import BaseCommand
from django.db import connection
from monitor.models import Domain, RecordLog, IPWhoisInfo, RecordLogIPInfo, DomainSnapshot


class Command(BaseCommand):
    help = 'Verify database integrity and relationships for DNS monitoring'

    def add_arguments(self, parser):
        parser.add_argument(
            '--fix',
            action='store_true',
            help='Attempt to fix broken relationships',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Starting database integrity check...'))
        
        # Check basic counts
        domain_count = Domain.objects.count()
        record_log_count = RecordLog.objects.count()
        ip_whois_count = IPWhoisInfo.objects.count()
        record_log_ip_count = RecordLogIPInfo.objects.count()
        snapshot_count = DomainSnapshot.objects.count()
        
        self.stdout.write(f"\nCounts:")
        self.stdout.write(f"  Domains: {domain_count}")
        self.stdout.write(f"  Record Logs: {record_log_count}")
        self.stdout.write(f"  IP WHOIS Info: {ip_whois_count}")
        self.stdout.write(f"  Record Log IP Info: {record_log_ip_count}")
        self.stdout.write(f"  Domain Snapshots: {snapshot_count}")
        
        # Check for orphaned RecordLogIPInfo entries
        self.stdout.write(f"\nChecking for orphaned RecordLogIPInfo entries...")
        
        orphaned_ip_info = []
        broken_whois_refs = []
        broken_record_refs = []
        
        for ip_info in RecordLogIPInfo.objects.all():
            # Check if record_log exists
            try:
                if not ip_info.record_log:
                    broken_record_refs.append(ip_info.id)
                elif not ip_info.record_log.domain:
                    broken_record_refs.append(ip_info.id)
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error checking record_log for RecordLogIPInfo {ip_info.id}: {e}"))
                broken_record_refs.append(ip_info.id)
            
            # Check if ip_whois_info exists
            try:
                if not ip_info.ip_whois_info:
                    broken_whois_refs.append(ip_info.id)
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error checking ip_whois_info for RecordLogIPInfo {ip_info.id}: {e}"))
                broken_whois_refs.append(ip_info.id)
        
        if broken_record_refs:
            self.stdout.write(self.style.WARNING(f"Found {len(broken_record_refs)} RecordLogIPInfo entries with broken record_log references: {broken_record_refs}"))
        
        if broken_whois_refs:
            self.stdout.write(self.style.WARNING(f"Found {len(broken_whois_refs)} RecordLogIPInfo entries with broken ip_whois_info references: {broken_whois_refs}"))
        
        # Check for RecordLog entries that might be causing issues in admin
        self.stdout.write(f"\nChecking RecordLog entries for potential admin issues...")
        
        problematic_record_logs = []
        
        for record_log in RecordLog.objects.all()[:100]:  # Check first 100 to avoid overwhelming
            try:
                # Test the relationships that admin methods use
                domain_name = record_log.domain.name
                
                # Test ip_info_entries relation
                ip_info_count = record_log.ip_info_entries.count()
                
                # Test snapshot relation
                has_snapshot = hasattr(record_log, 'snapshot')
                if has_snapshot:
                    try:
                        snapshot = record_log.snapshot
                    except Exception:
                        pass
                
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error testing RecordLog {record_log.id}: {e}"))
                problematic_record_logs.append(record_log.id)
        
        if problematic_record_logs:
            self.stdout.write(self.style.WARNING(f"Found {len(problematic_record_logs)} problematic RecordLog entries: {problematic_record_logs}"))
        
        # Check database constraints
        self.stdout.write(f"\nChecking database constraints...")
        
        with connection.cursor() as cursor:
            # Check for foreign key constraint violations
            try:
                cursor.execute("""
                    SELECT COUNT(*) FROM monitor_recordlogipinfo rli 
                    LEFT JOIN monitor_recordlog rl ON rli.record_log_id = rl.id 
                    WHERE rl.id IS NULL
                """)
                orphaned_by_record_log = cursor.fetchone()[0]
                
                cursor.execute("""
                    SELECT COUNT(*) FROM monitor_recordlogipinfo rli 
                    LEFT JOIN monitor_ipwhoisinfo wi ON rli.ip_whois_info_id = wi.id 
                    WHERE wi.id IS NULL
                """)
                orphaned_by_whois = cursor.fetchone()[0]
                
                self.stdout.write(f"  Orphaned by record_log: {orphaned_by_record_log}")
                self.stdout.write(f"  Orphaned by ip_whois_info: {orphaned_by_whois}")
                
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error checking constraints: {e}"))
        
        # Fix issues if requested
        if options['fix']:
            self.stdout.write(f"\nAttempting to fix issues...")
            
            # Remove orphaned RecordLogIPInfo entries
            if broken_record_refs or broken_whois_refs:
                all_broken = set(broken_record_refs + broken_whois_refs)
                deleted_count = RecordLogIPInfo.objects.filter(id__in=all_broken).delete()[0]
                self.stdout.write(self.style.SUCCESS(f"Deleted {deleted_count} broken RecordLogIPInfo entries"))
        
        self.stdout.write(self.style.SUCCESS('\nDatabase integrity check completed.'))
