from django.http import HttpResponseForbidden
from django.utils.timezone import now
from .models import RequestLog, BlockedIP

class LogIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request, *args, **kwds):
        ip = self.get_client_ip(request)
        path = request.path

        # Block blacklisted IPs
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Access denied: Your IP is blocked.")
        
        # Log to database
        RequestLog.objects.create(
            ip_address = ip,
            timestamp = now(),
            path = path
        )

        return self.get_response(request)

    def get_client_ip(self, request):
        # Handles X-Forwarded-For if behind a proxy
        x_forwarded_for = request.META.get('HTTP_X_FOWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip