from django.db import models

# Create your models here.
class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=255)
    country = models.CharField(max_length=100, null=True, blank=True)
    city= models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return f"{self.ip_address} accessed {self.path} at {self.timestamp}"
    
class BlockedIP(models.Model): 
    ip_address = models.GenericIPAddressField()

    def __str__(self):
        return self.ip_address