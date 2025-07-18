from celery import shared_task
from django.utils import timezone
from datetime import timedelta

from .models import SuspiciousIP, RequestLog

SENSITIVE_PATHS = ['/admin', '/login']

@shared_task
def flag_suspicious_ips():
    # Get all request from the last hour
    one_hour_ago = timezone.now() - timedelta(hours=1)
    recent_logs = RequestLog.objects.filter(timestamp__gte=one_hour_ago)

    # Count requests per IP
    ip_counts = {}
    suspicious = {}

    for log in recent_logs:
        ip = log.ip_address
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

        if any(log.path.startswith(path) for path in SENSITIVE_PATHS):
            suspicious[ip] = 'Accessed sensitive path'

    # Flag high request volume
    for ip, count in ip_counts.items():
        if count > 100:
            suspicious[ip] = 'Exceeded 100 requests/hour'

    # Store suspicious IPs
    for ip, reason in suspicious.items():
        SuspiciousIP.objects.get_or_create(ip_address=ip, defaults={'reason':reason})