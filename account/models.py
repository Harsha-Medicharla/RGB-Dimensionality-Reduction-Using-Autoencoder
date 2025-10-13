from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import timedelta
import random

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    bio = models.TextField(max_length=500, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    email_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.username

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'


class OTP(models.Model):
    OTP_TYPE_CHOICES = [
        ('registration', 'Registration'),
        ('password_reset', 'Password Reset'),
    ]
    
    email = models.EmailField()
    otp_code = models.CharField(max_length=6)
    otp_type = models.CharField(max_length=20, choices=OTP_TYPE_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.email} - {self.otp_type} - {self.otp_code}"
    
    def is_valid(self):
        return not self.is_used and timezone.now() < self.expires_at
    
    @staticmethod
    def generate_otp():
        return str(random.randint(100000, 999999))
    
    @classmethod
    def create_otp(cls, email, otp_type):
        # Invalidate old OTPs
        cls.objects.filter(email=email, otp_type=otp_type, is_used=False).update(is_used=True)
        
        # Create new OTP
        otp_code = cls.generate_otp()
        expires_at = timezone.now() + timedelta(minutes=5)
        
        return cls.objects.create(
            email=email,
            otp_code=otp_code,
            otp_type=otp_type,
            expires_at=expires_at
        )
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'OTP'
        verbose_name_plural = 'OTPs'