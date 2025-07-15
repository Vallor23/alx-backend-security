from django.utils.timezone import now
from .models import RequestLog

class LogIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request, *args, **kwds):
        ip_address = self.get_client_ip(request)
        path = request.path

        # Log to database
        RequestLog.objects.create(
            ip_address = ip_address,
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