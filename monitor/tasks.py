import logging
import dns.resolver
import requests
import time
from ipwhois import IPWhois
from celery import shared_task
from django.utils import timezone
from .models import Domain, RecordLog, DomainSnapshot, IPWhoisInfo, RecordLogIPInfo

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
            
            # Trigger snapshot capture for IP changes or initial domain check
            is_initial_check = not previous_ips_string  # First time we're checking this domain
            
            if is_initial_check:
                logger.info(f"Initial DNS check for {domain.name}: {current_ips_string}")
                
                # Capture initial snapshot for new domain
                capture_domain_snapshot.delay(domain.id, record_log.id, is_initial=True)
                
                # Fetch WHOIS info for initial IPs
                fetch_record_log_ip_info.delay(record_log.id)
            elif is_change:
                logger.info(f"DNS change detected for {domain.name}: {previous_ips_string} -> {current_ips_string}")
                
                # Capture snapshot due to IP change
                capture_domain_snapshot.delay(domain.id, record_log.id, is_initial=False)
                
                # Fetch WHOIS info for changed IPs
                fetch_record_log_ip_info.delay(record_log.id)
                
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


@shared_task(bind=True, autoretry_for=(Exception,), retry_kwargs={'max_retries': 3, 'countdown': 120})
def capture_domain_snapshot(self, domain_id, record_log_id=None, is_initial=False):
    """
    Capture an HTML snapshot of a domain's homepage.
    
    Args:
        domain_id (int): The ID of the Domain object
        record_log_id (int, optional): The ID of the RecordLog entry this snapshot is associated with
        is_initial (bool): Whether this is the initial snapshot when domain was first added
        
    Returns:
        dict: Result dictionary with success status and details
    """
    try:
        # Get the domain from database
        domain = Domain.objects.get(id=domain_id)
        logger.info(f"Capturing snapshot for domain: {domain.name}")
        
        # Get record log if provided
        record_log = None
        if record_log_id:
            try:
                record_log = RecordLog.objects.get(id=record_log_id)
            except RecordLog.DoesNotExist:
                logger.warning(f"RecordLog with ID {record_log_id} not found")
        
        # Prepare the URL - try both HTTP and HTTPS
        urls_to_try = [
            f"https://{domain.name}",
            f"http://{domain.name}"
        ]
        
        snapshot_data = None
        
        for url in urls_to_try:
            try:
                logger.info(f"Attempting to fetch {url}")
                start_time = time.time()
                
                # Configure request with reasonable timeout and headers
                headers = {
                    'User-Agent': 'DNS-Checker-Bot/1.0 (Site Monitor)',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                }
                
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=30,
                    allow_redirects=True,
                    verify=True  # Verify SSL certificates
                )
                
                end_time = time.time()
                response_time_ms = int((end_time - start_time) * 1000)
                
                # Check if we got a reasonable response
                if response.status_code < 400:
                    logger.info(f"Successfully fetched {url} - Status: {response.status_code}, Size: {len(response.text)} bytes")
                    
                    snapshot_data = {
                        'html_content': response.text,
                        'status_code': response.status_code,
                        'response_time_ms': response_time_ms,
                        'url_used': url
                    }
                    break
                else:
                    logger.warning(f"HTTP error for {url}: {response.status_code}")
                    
            except requests.exceptions.SSLError as e:
                logger.warning(f"SSL error for {url}: {str(e)}")
                continue
            except requests.exceptions.Timeout as e:
                logger.warning(f"Timeout for {url}: {str(e)}")
                continue
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"Connection error for {url}: {str(e)}")
                continue
            except Exception as e:
                logger.warning(f"Unexpected error for {url}: {str(e)}")
                continue
        
        # Create snapshot record
        if snapshot_data:
            # Success - save the snapshot
            snapshot = DomainSnapshot.objects.create(
                domain=domain,
                record_log=record_log,
                html_content=snapshot_data['html_content'],
                status_code=snapshot_data['status_code'],
                response_time_ms=snapshot_data['response_time_ms'],
                is_initial_snapshot=is_initial
            )
            
            logger.info(f"Snapshot captured successfully for {domain.name} - ID: {snapshot.id}, Size: {snapshot.content_length} bytes")
            
            return {
                'success': True,
                'domain': domain.name,
                'snapshot_id': snapshot.id,
                'content_length': snapshot.content_length,
                'status_code': snapshot_data['status_code'],
                'response_time_ms': snapshot_data['response_time_ms'],
                'url_used': snapshot_data['url_used'],
                'is_initial': is_initial
            }
        else:
            # Failed to fetch from any URL
            error_msg = f"Failed to fetch homepage for {domain.name} from any URL"
            logger.error(error_msg)
            
            # Save failed snapshot record
            snapshot = DomainSnapshot.objects.create(
                domain=domain,
                record_log=record_log,
                html_content='',
                status_code=0,
                error_message=error_msg,
                is_initial_snapshot=is_initial
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
        error_msg = f"Unexpected error capturing snapshot for domain ID {domain_id}: {str(e)}"
        logger.error(error_msg)
        
        # Re-raise for Celery retry mechanism
        raise


@shared_task(bind=True, autoretry_for=(Exception,), retry_kwargs={'max_retries': 3, 'countdown': 180})
def fetch_ip_whois_info(self, ip_address):
    """
    Fetch WHOIS/ASN information for an IP address.
    
    Args:
        ip_address (str): The IP address to look up
        
    Returns:
        dict: Result dictionary with WHOIS information or error
    """
    try:
        logger.info(f"Fetching WHOIS information for IP: {ip_address}")
        
        # Check if we already have recent information for this IP
        try:
            existing_info = IPWhoisInfo.objects.get(ip_address=ip_address)
            
            # Check if the information is recent (less than 24 hours old)
            from django.utils import timezone
            if timezone.now() - existing_info.updated_at < timezone.timedelta(hours=24):
                logger.info(f"Using cached WHOIS info for {ip_address}")
                return {
                    'success': True,
                    'ip_address': ip_address,
                    'cached': True,
                    'whois_info': {
                        'asn': existing_info.asn,
                        'asn_description': existing_info.asn_description,
                        'organization': existing_info.organization,
                        'isp': existing_info.isp,
                        'country': existing_info.country,
                        'country_code': existing_info.country_code,
                        'registry': existing_info.registry,
                        'network_cidr': existing_info.network_cidr,
                    }
                }
        except IPWhoisInfo.DoesNotExist:
            pass
        
        # Perform WHOIS lookup
        start_time = time.time()
        obj = IPWhois(ip_address)
        
        try:
            # Try RDAP first (more modern)
            result = obj.lookup_rdap(depth=1)
        except Exception as rdap_error:
            logger.warning(f"RDAP lookup failed for {ip_address}: {str(rdap_error)}, trying WHOIS")
            try:
                # Fallback to traditional WHOIS
                result = obj.lookup_whois()
            except Exception as whois_error:
                logger.error(f"Both RDAP and WHOIS lookups failed for {ip_address}: RDAP={str(rdap_error)}, WHOIS={str(whois_error)}")
                raise whois_error
        
        end_time = time.time()
        lookup_time = int((end_time - start_time) * 1000)
        
        logger.info(f"WHOIS lookup completed for {ip_address} in {lookup_time}ms")
        
        # Extract relevant information
        whois_data = {
            'asn': None,
            'asn_description': None,
            'organization': None,
            'isp': None,
            'country': None,
            'country_code': None,
            'registry': None,
            'network_cidr': None,
        }
        
        # Extract ASN information
        if 'asn' in result and result['asn']:
            whois_data['asn'] = str(result['asn'])
        
        if 'asn_description' in result and result['asn_description']:
            whois_data['asn_description'] = result['asn_description']
        
        # Extract network information
        if 'nets' in result and result['nets']:
            net = result['nets'][0]  # Use the first network entry
            
            if 'name' in net and net['name']:
                whois_data['organization'] = net['name']
            
            if 'description' in net and net['description']:
                # Sometimes description contains ISP info
                if not whois_data['organization'] and net['description']:
                    whois_data['organization'] = net['description']
                whois_data['isp'] = net['description']
            
            if 'country' in net and net['country']:
                whois_data['country'] = net['country']
            
            if 'cidr' in net and net['cidr']:
                whois_data['network_cidr'] = net['cidr']
        
        # Extract registry information
        if 'asn_registry' in result and result['asn_registry']:
            whois_data['registry'] = result['asn_registry']
        
        # Extract country code from query if not found in nets
        if 'asn_country_code' in result and result['asn_country_code']:
            if not whois_data['country_code']:
                whois_data['country_code'] = result['asn_country_code']
        
        # Clean up the data
        for key, value in whois_data.items():
            if isinstance(value, str):
                whois_data[key] = value.strip()[:255] if value.strip() else None
        
        # Create or update the database record
        ip_whois_info, created = IPWhoisInfo.objects.update_or_create(
            ip_address=ip_address,
            defaults=whois_data
        )
        
        action = "Created" if created else "Updated"
        logger.info(f"{action} WHOIS info for {ip_address} - ASN: {whois_data['asn']}, Org: {whois_data['organization']}")
        
        return {
            'success': True,
            'ip_address': ip_address,
            'cached': False,
            'created': created,
            'lookup_time_ms': lookup_time,
            'whois_info': whois_data
        }
        
    except Exception as e:
        error_msg = f"Failed to fetch WHOIS info for {ip_address}: {str(e)}"
        logger.error(error_msg)
        
        # Save error information
        IPWhoisInfo.objects.update_or_create(
            ip_address=ip_address,
            defaults={
                'error_message': error_msg,
                'asn': None,
                'asn_description': None,
                'organization': None,
                'isp': None,
                'country': None,
                'country_code': None,
                'registry': None,
                'network_cidr': None,
            }
        )
        
        return {
            'success': False,
            'ip_address': ip_address,
            'error': error_msg
        }


@shared_task(bind=True, autoretry_for=(Exception,), retry_kwargs={'max_retries': 2, 'countdown': 60})
def fetch_record_log_ip_info(self, record_log_id):
    """
    Fetch WHOIS information for all IPs in a RecordLog entry.
    
    Args:
        record_log_id (int): The ID of the RecordLog entry
        
    Returns:
        dict: Result dictionary with summary of WHOIS lookups
    """
    try:
        record_log = RecordLog.objects.get(id=record_log_id)
        logger.info(f"Fetching IP info for record log {record_log_id} - Domain: {record_log.domain.name}")
        
        ips = record_log.get_ips_list()
        if not ips:
            logger.warning(f"No IPs found in record log {record_log_id}")
            return {
                'success': True,
                'record_log_id': record_log_id,
                'domain': record_log.domain.name,
                'ips_processed': 0,
                'message': 'No IPs to process'
            }
        
        results = []
        
        for ip in ips:
            # Fetch WHOIS info for this IP
            whois_result = fetch_ip_whois_info(ip)
            results.append(whois_result)
            
            if whois_result['success']:
                # Get the IPWhoisInfo object
                ip_whois_info = IPWhoisInfo.objects.get(ip_address=ip)
                
                # Create association between RecordLog and IPWhoisInfo
                record_log_ip_info, created = RecordLogIPInfo.objects.get_or_create(
                    record_log=record_log,
                    ip_address=ip,
                    defaults={'ip_whois_info': ip_whois_info}
                )
                
                if not created:
                    # Update with latest WHOIS info
                    record_log_ip_info.ip_whois_info = ip_whois_info
                    record_log_ip_info.save()
        
        successful_lookups = sum(1 for r in results if r['success'])
        failed_lookups = len(results) - successful_lookups
        
        logger.info(f"IP info collection complete for record log {record_log_id}: {successful_lookups} successful, {failed_lookups} failed")
        
        return {
            'success': True,
            'record_log_id': record_log_id,
            'domain': record_log.domain.name,
            'ips_processed': len(ips),
            'successful_lookups': successful_lookups,
            'failed_lookups': failed_lookups,
            'results': results
        }
        
    except RecordLog.DoesNotExist:
        error_msg = f"RecordLog with ID {record_log_id} does not exist"
        logger.error(error_msg)
        return {
            'success': False,
            'error': error_msg
        }
        
    except Exception as e:
        error_msg = f"Unexpected error fetching IP info for record log {record_log_id}: {str(e)}"
        logger.error(error_msg)
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
