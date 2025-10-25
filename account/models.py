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
        # Returns username as string representation
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
    
    def time_remaining(self):
        """Returns seconds remaining until expiration"""
        if self.is_used:
            return 0
        remaining = (self.expires_at - timezone.now()).total_seconds()
        return max(0, int(remaining))
    
    @staticmethod
    def generate_otp():
        return str(random.randint(100000, 999999))
    
    @classmethod
    def can_resend(cls, email, otp_type):
        """Check if user can resend OTP (max 5 in 10 minutes)"""
        ten_minutes_ago = timezone.now() - timedelta(minutes=10)
        recent_otps = cls.objects.filter(
            email=email,
            otp_type=otp_type,
            created_at__gte=ten_minutes_ago
        ).count()
        return recent_otps < 5
    
    @classmethod
    def get_resend_cooldown(cls, email, otp_type):
        """Get seconds until user can resend again"""
        ten_minutes_ago = timezone.now() - timedelta(minutes=10)
        recent_otps = cls.objects.filter(
            email=email,
            otp_type=otp_type,
            created_at__gte=ten_minutes_ago
        ).order_by('created_at')
        
        if recent_otps.count() < 5:
            return 0
        
        # Get the oldest OTP in the window
        oldest_otp = recent_otps.first()
        cooldown_end = oldest_otp.created_at + timedelta(minutes=10)
        remaining = (cooldown_end - timezone.now()).total_seconds()
        return max(0, int(remaining))
    
    @classmethod
    def create_otp(cls, email, otp_type):
        """Creates and returns a new OTP after invalidating old ones"""
        cls.objects.filter(email=email, otp_type=otp_type, is_used=False).update(is_used=True)
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


class ImageUpload(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='images')
    input_image = models.ImageField(upload_to='uploads/input/')
    output_image = models.ImageField(upload_to='uploads/output/', null=True, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    processed = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.user.username} - {self.uploaded_at.strftime('%Y-%m-%d %H:%M')}"
    
    class Meta:
        ordering = ['-uploaded_at']
        verbose_name = 'Image Upload'
        verbose_name_plural = 'Image Uploads'