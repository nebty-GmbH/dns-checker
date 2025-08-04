import logging
import dns.resolver
from celery import shared_task
from django.utils import timezone
from .models import Domain, RecordLog

logger = logging.getLogger('monitor')


@shared_task(bind=True, autoretry_for=(Exception,), retry_kwargs={'max_retries': 3, 'countdown': 60})
def check_domain_a_records(self, domain_id):
    """
    Check DNS A records for a specific domain and log the results.
    
    Args:
        domain_id (int): The ID of the Domain object to check
        
    Returns:
        dict: Result dictionary with success status and details
    """
    try:
        # Import here to avoid circular imports
        from .models import MonitorSettings
        
        # Get current settings for timeout
        settings = MonitorSettings.get_settings()
        
        # Fetch the domain from database
        domain = Domain.objects.get(id=domain_id)
        logger.info(f"Checking DNS A records for domain: {domain.name}")
        
        # Configure DNS resolver with timeout from settings
        resolver = dns.resolver.Resolver()
        resolver.timeout = settings.dns_timeout_seconds
        resolver.lifetime = settings.dns_timeout_seconds * 2
        
        # Perform DNS lookup
        try:
            answers = resolver.resolve(domain.name, 'A')
            current_ips = [str(answer) for answer in answers]
            logger.info(f"Found IPs for {domain.name}: {current_ips}")
            
            # Sort IPs for consistent comparison
            current_ips_sorted = sorted(set(current_ips))
            current_ips_string = ','.join(current_ips_sorted)
            
            # Compare with last known IPs
            previous_ips_string = domain.last_known_ips or ''
            is_change = current_ips_string != previous_ips_string
            
            # Create log entry
            record_log = RecordLog.objects.create(
                domain=domain,
                ips=current_ips_string,
                is_change=is_change,
                timestamp=timezone.now()
            )
            
            # Update domain's last known IPs
            domain.last_known_ips = current_ips_string
            domain.save()
            
            if is_change:
                logger.info(f"DNS change detected for {domain.name}: {previous_ips_string} -> {current_ips_string}")
                
                # Send notification if enabled
                if settings.email_notifications_enabled and settings.notification_email:
                    send_change_notification.delay(domain.id, record_log.id)
            else:
                logger.info(f"No DNS change for {domain.name}: {current_ips_string}")
            
            return {
                'success': True,
                'domain': domain.name,
                'ips': current_ips_sorted,
                'is_change': is_change,
                'previous_ips': domain.get_last_known_ips_list() if previous_ips_string else [],
                'timestamp': record_log.timestamp.isoformat()
            }
            
        except dns.resolver.NXDOMAIN:
            error_msg = f"Domain {domain.name} does not exist (NXDOMAIN)"
            logger.error(error_msg)
            
            # Log the error
            RecordLog.objects.create(
                domain=domain,
                ips='',
                is_change=False,
                error_message=error_msg,
                timestamp=timezone.now()
            )
            
            return {
                'success': False,
                'domain': domain.name,
                'error': error_msg
            }
            
        except dns.resolver.Timeout:
            error_msg = f"DNS lookup timeout for domain {domain.name}"
            logger.error(error_msg)
            
            # Log the error
            RecordLog.objects.create(
                domain=domain,
                ips='',
                is_change=False,
                error_message=error_msg,
                timestamp=timezone.now()
            )
            
            return {
                'success': False,
                'domain': domain.name,
                'error': error_msg
            }
            
        except dns.resolver.NoAnswer:
            error_msg = f"No A records found for domain {domain.name}"
            logger.error(error_msg)
            
            # Log the error
            RecordLog.objects.create(
                domain=domain,
                ips='',
                is_change=False,
                error_message=error_msg,
                timestamp=timezone.now()
            )
            
            return {
                'success': False,
                'domain': domain.name,
                'error': error_msg
            }
            
    except Domain.DoesNotExist:
        error_msg = f"Domain with ID {domain_id} does not exist"
        logger.error(error_msg)
        return {
            'success': False,
            'error': error_msg
        }
        
    except Exception as e:
        error_msg = f"Unexpected error checking domain ID {domain_id}: {str(e)}"
        logger.error(error_msg)
        
        # If we have the domain object, log the error
        try:
            domain = Domain.objects.get(id=domain_id)
            RecordLog.objects.create(
                domain=domain,
                ips='',
                is_change=False,
                error_message=error_msg,
                timestamp=timezone.now()
            )
        except:
            pass
        
        # Re-raise for Celery retry mechanism
        raise


@shared_task
def schedule_domain_checks():
    """
    Scheduler task that dispatches individual domain check tasks for all active domains.
    This task uses the configurable interval from MonitorSettings.
    
    Returns:
        dict: Summary of scheduled tasks
    """
    from .models import MonitorSettings
    
    active_domains = Domain.objects.filter(is_active=True)
    settings = MonitorSettings.get_settings()
    scheduled_count = 0
    
    logger.info(f"Scheduling DNS checks for {active_domains.count()} active domains (interval: {settings.check_interval_minutes} minutes)")
    
    # Limit parallel checks based on settings
    domains_to_check = active_domains[:settings.max_parallel_checks]
    
    for domain in domains_to_check:
        try:
            # Dispatch individual check task
            check_domain_a_records.delay(domain.id)
            scheduled_count += 1
            logger.debug(f"Scheduled check for domain: {domain.name}")
        except Exception as e:
            logger.error(f"Failed to schedule check for domain {domain.name}: {str(e)}")
    
    if active_domains.count() > settings.max_parallel_checks:
        logger.warning(f"Limited to {settings.max_parallel_checks} parallel checks. {active_domains.count() - settings.max_parallel_checks} domains will be checked in the next cycle.")
    
    logger.info(f"Successfully scheduled {scheduled_count} domain checks")
    
    return {
        'success': True,
        'total_active_domains': active_domains.count(),
        'scheduled_tasks': scheduled_count,
        'max_parallel_checks': settings.max_parallel_checks,
        'check_interval_minutes': settings.check_interval_minutes,
        'timestamp': timezone.now().isoformat()
    }


@shared_task
def send_change_notification(domain_id, record_log_id):
    """
    Send email notification when DNS change is detected.
    
    Args:
        domain_id (int): The ID of the Domain that changed
        record_log_id (int): The ID of the RecordLog entry
    """
    try:
        from django.core.mail import send_mail
        from django.conf import settings as django_settings
        from .models import MonitorSettings
        
        domain = Domain.objects.get(id=domain_id)
        record_log = RecordLog.objects.get(id=record_log_id)
        monitor_settings = MonitorSettings.get_settings()
        
        if not monitor_settings.email_notifications_enabled or not monitor_settings.notification_email:
            logger.info(f"Email notifications disabled, skipping notification for {domain.name}")
            return
        
        subject = f"DNS Change Alert: {domain.name}"
        
        previous_ips = domain.get_last_known_ips_list()
        current_ips = record_log.get_ips_list()
        
        message = f"""
DNS A-record change detected for domain: {domain.name}

Previous IPs: {', '.join(previous_ips) if previous_ips else 'None'}
Current IPs:  {', '.join(current_ips)}

Change detected at: {record_log.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

This is an automated notification from your DNS monitoring system.
"""
        
        send_mail(
            subject=subject,
            message=message,
            from_email=getattr(django_settings, 'DEFAULT_FROM_EMAIL', 'noreply@example.com'),
            recipient_list=[monitor_settings.notification_email],
            fail_silently=False,
        )
        
        logger.info(f"Email notification sent for DNS change in {domain.name}")
        
    except Exception as e:
        logger.error(f"Failed to send email notification for domain {domain_id}: {str(e)}")
        raise


@shared_task
def check_all_domains_now():
    """
    Manual task to check all active domains immediately.
    Useful for testing or manual triggering.
    
    Returns:
        dict: Summary of results
    """
    active_domains = Domain.objects.filter(is_active=True)
    results = []
    
    logger.info(f"Manually checking all {active_domains.count()} active domains")
    
    for domain in active_domains:
        try:
            result = check_domain_a_records(domain.id)
            results.append(result)
        except Exception as e:
            error_result = {
                'success': False,
                'domain': domain.name,
                'error': str(e)
            }
            results.append(error_result)
            logger.error(f"Failed to check domain {domain.name}: {str(e)}")
    
    successful_checks = sum(1 for r in results if r.get('success', False))
    failed_checks = len(results) - successful_checks
    changes_detected = sum(1 for r in results if r.get('is_change', False))
    
    logger.info(f"Manual check complete: {successful_checks} successful, {failed_checks} failed, {changes_detected} changes detected")
    
    return {
        'total_domains': len(results),
        'successful_checks': successful_checks,
        'failed_checks': failed_checks,
        'changes_detected': changes_detected,
        'results': results,
        'timestamp': timezone.now().isoformat()
    }


@shared_task(bind=True)
def start_continuous_monitoring(self):
    """
    Start continuous monitoring loop.
    This task continuously checks domains with rate limiting.
    """
    try:
        from .models import MonitorSettings
        
        settings = MonitorSettings.get_settings()
        
        # Check if continuous monitoring is still enabled
        if not settings.continuous_monitoring_enabled:
            logger.info("Continuous monitoring is disabled, stopping task")
            return {'message': 'Continuous monitoring disabled'}
        
        logger.info("Starting continuous monitoring cycle")
        
        # Get domains that can be checked now (respecting rate limits)
        domains_to_check = Domain.objects.filter(is_active=True).all()
        
        checkable_domains = [
            domain for domain in domains_to_check 
            if domain.can_be_checked_now()
        ]
        
        logger.info(f"Found {len(checkable_domains)} domains ready for checking out of {len(domains_to_check)} total active domains")
        
        if checkable_domains:
            # Check domains in parallel respecting max_parallel_checks
            batch_size = min(settings.max_parallel_checks, len(checkable_domains))
            batches = [checkable_domains[i:i + batch_size] for i in range(0, len(checkable_domains), batch_size)]
            
            for batch in batches:
                # Process each domain in the batch
                for domain in batch:
                    check_domain_a_records.delay(domain.id)
                logger.info(f"Queued batch of {len(batch)} domains")
        
        # Check if continuous monitoring is still enabled before scheduling next cycle
        settings.refresh_from_db()
        if settings.continuous_monitoring_enabled:
            # Schedule the next cycle immediately
            logger.info("Scheduling next continuous monitoring cycle")
            start_continuous_monitoring.apply_async(countdown=5)  # Small delay to avoid overwhelming
        else:
            logger.info("Continuous monitoring disabled, not scheduling next cycle")
        
        return {
            'message': 'Continuous monitoring cycle completed',
            'domains_checked': len(checkable_domains),
            'total_active_domains': len(domains_to_check),
            'timestamp': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in continuous monitoring: {str(e)}")
        # Re-raise to trigger Celery retry if needed
        raise


@shared_task(bind=True)
def check_domains_with_rate_limiting(self):
    """
    Check all domains that are ready to be checked based on rate limiting.
    This is similar to continuous monitoring but designed for one-off execution.
    """
    try:
        from .models import MonitorSettings
        
        settings = MonitorSettings.get_settings()
        
        # Get domains that can be checked now (respecting rate limits)
        domains_to_check = Domain.objects.filter(is_active=True).all()
        
        checkable_domains = [
            domain for domain in domains_to_check 
            if domain.can_be_checked_now()
        ]
        
        logger.info(f"Rate-limited check: {len(checkable_domains)} domains ready for checking out of {len(domains_to_check)} total active domains")
        
        if not checkable_domains:
            return {
                'message': 'No domains ready for checking due to rate limiting',
                'total_active_domains': len(domains_to_check),
                'timestamp': timezone.now().isoformat()
            }
        
        # Check domains in parallel respecting max_parallel_checks
        batch_size = min(settings.max_parallel_checks, len(checkable_domains))
        batches = [checkable_domains[i:i + batch_size] for i in range(0, len(checkable_domains), batch_size)]
        
        checked_count = 0
        for batch in batches:
            # Process each domain in the batch
            for domain in batch:
                check_domain_a_records.delay(domain.id)
                checked_count += 1
            logger.info(f"Queued batch of {len(batch)} domains")
        
        logger.info(f"Rate-limited check complete: queued {checked_count} domain checks")
        
        return {
            'total_domains_checked': checked_count,
            'total_active_domains': len(domains_to_check),
            'message': f'Queued {checked_count} domain checks',
            'timestamp': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in rate-limited domain check: {str(e)}")
        raise
