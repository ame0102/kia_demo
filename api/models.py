from django.db import models
from django.contrib.auth.models import User

class Vehicle(models.Model):
    vin = models.CharField(max_length=17, primary_key=True)
    owner_email = models.EmailField()
    phone = models.CharField(max_length=15, blank=True, null=True)
    owner_role = models.CharField(max_length=20, default='PRIMARY')
    dealer_code = models.CharField(max_length=20, default='eDelivery')
    
    def __str__(self):
        return self.vin

class FirmwareVersion(models.Model):
    version = models.CharField(max_length=50)
    file_path = models.CharField(max_length=255)
    hash = models.CharField(max_length=64)
    signature = models.TextField(blank=True, null=True)
    is_signed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Firmware v{self.version}"

class SecurityLog(models.Model):
    EVENT_TYPES = [
        ('AUTH', 'Authentication'),
        ('API', 'API Access'),
        ('OTA', 'Firmware Update'),
        ('CAN', 'CAN Bus Activity'),
        ('ATTACK', 'Attack Attempt'),
    ]
    
    timestamp = models.DateTimeField(auto_now_add=True)
    event_type = models.CharField(max_length=10, choices=EVENT_TYPES)
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    description = models.TextField()
    success = models.BooleanField(default=True)
    
    def __str__(self):
        return f"{self.timestamp} - {self.event_type} - {'Success' if self.success else 'Failed'}"