import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
import hashlib


class UserManager(BaseUserManager):
    """Custom user manager for phone number authentication"""
    
    def create_user(self, phone_number, **extra_fields):
        if not phone_number:
            raise ValueError('Phone number is required')
        
        # Hash phone number for privacy
        phone_hash = hashlib.sha256(phone_number.encode()).hexdigest()
        
        user = self.model(
            phone_number=phone_number,
            phone_number_hash=phone_hash,
            **extra_fields
        )
        user.save(using=self._db)
        return user
    
    def create_superuser(self, phone_number, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('phone_verified', True)
        
        return self.create_user(phone_number, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """Custom user model using phone number for authentication"""
    
    USER_TYPE_CHOICES = [
        ('anonymous', 'Anonymous'),
        ('verified', 'Verified'),
        ('premium', 'Premium'),
    ]
    
    # Primary identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_type = models.CharField(max_length=20, choices=USER_TYPE_CHOICES, default='verified')
    
    # Authentication
    phone_number = models.CharField(max_length=20, unique=True)
    phone_number_hash = models.CharField(max_length=64, unique=True)
    phone_verified = models.BooleanField(default=False)
    
    # Profile
    display_name = models.CharField(max_length=100, default='User')
    language_preference = models.CharField(max_length=10, default='en')
    
    # Device info
    device_id = models.CharField(max_length=255, blank=True, null=True)
    device_model = models.CharField(max_length=100, blank=True, null=True)
    os_version = models.CharField(max_length=50, blank=True, null=True)
    app_version = models.CharField(max_length=20, blank=True, null=True)
    
    # Privacy settings (JSON field)
    privacy_settings = models.JSONField(default=dict, blank=True)
    
    # Activity tracking
    created_at = models.DateTimeField(auto_now_add=True)
    last_login_at = models.DateTimeField(null=True, blank=True)
    last_active_at = models.DateTimeField(null=True, blank=True)
    login_count = models.IntegerField(default=0)
    
    # Account status
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    
    # Metadata
    total_calls_protected = models.IntegerField(default=0)
    total_scams_blocked = models.IntegerField(default=0)
    total_reports_submitted = models.IntegerField(default=0)
    total_training_contributions = models.IntegerField(default=0)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = []
    
    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.display_name} ({self.phone_number})"
    
    def update_last_login(self):
        """Update login tracking"""
        self.last_login_at = timezone.now()
        self.login_count += 1
        self.save(update_fields=['last_login_at', 'login_count'])


class AuthAttempt(models.Model):
    """Track OTP attempts for security"""
    
    phone_number = models.CharField(max_length=20)
    otp_code = models.CharField(max_length=6)
    otp_sent_at = models.DateTimeField(auto_now_add=True)
    otp_expires_at = models.DateTimeField()
    attempts = models.IntegerField(default=0)
    verified = models.BooleanField(default=False)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, null=True)
    
    class Meta:
        db_table = 'auth_attempts'
        ordering = ['-otp_sent_at']
        indexes = [
            models.Index(fields=['phone_number', 'verified']),
        ]
    
    def __str__(self):
        return f"OTP for {self.phone_number} - {'Verified' if self.verified else 'Pending'}"
    
    def is_expired(self):
        """Check if OTP is expired"""
        return timezone.now() > self.otp_expires_at