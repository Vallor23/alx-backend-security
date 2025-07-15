from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponseForbidden
from django.utils.timezone import now
from .models import RequestLog, BlockedIP
from django_ip_geolocation.backends import IPGeolocationAPI

API_KEY = settings.IP_GEOLOCATION_KEY
geo = IPGeolocationAPI(API_KEY)

class LogIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request, *args, **kwds):
        ip = self.get_client_ip(request)
        path = request.path

        # Block blacklisted IPs
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Access denied: Your IP is blocked.")
        
        # Get location from cache or API
        geo_data = cache.get(ip)
        if not geo_data:
            try:
                response = geo.get_geolocation_data(ip)
                geo_data = {
                    "country": response.get("country_name"),
                    "city": response.get("city")
                }
                cache.set(ip, geo_data, timeout=60 * 60 * 24)
            except Exception:
                geo_data = {"country": None, "city": None}


        # Log to database
        RequestLog.objects.create(
            ip_address = ip,
            timestamp = now(),
            path = path,
            country = geo_data.get("country"),
            city = geo_data.get("city")
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