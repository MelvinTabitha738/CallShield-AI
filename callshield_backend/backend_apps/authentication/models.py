# backend_apps/authentication/models.py

import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from django.core.exceptions import ValidationError
import hashlib


class UserManager(BaseUserManager):
    """Custom user manager for phone number authentication"""
    
    def create_user(self, phone_number, **extra_fields):
        if not phone_number:
            raise ValueError('Phone number is required')
        
        # Validate phone number format
        if not phone_number.startswith('+'):
            raise ValueError('Phone number must start with + (international format)')
        
        # Hash phone number for privacy
        phone_hash = hashlib.sha256(phone_number.encode()).hexdigest()
        
        # Ensure hash is not empty
        if not phone_hash:
            raise ValueError('Failed to generate phone number hash')
        
        user = self.model(
            phone_number=phone_number,
            phone_number_hash=phone_hash,
            **extra_fields
        )
        user.save(using=self._db)
        return user
    
    def create_superuser(self, phone_number, **extra_fields):
        """
        Create superuser with phone number.
        Usage: python manage.py createsuperuser
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('phone_verified', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        
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
    phone_number = models.CharField(
        max_length=20,
        unique=True,
        help_text='Phone number in international format (+254...)'
    )
    phone_number_hash = models.CharField(
        max_length=64,
        unique=True,
        blank=False,  # Prevent empty in forms
        help_text='SHA-256 hash of phone number for privacy'
    )
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
    
    def clean(self):
        """Validate model data before saving"""
        super().clean()
        
        # Validate phone number
        if not self.phone_number:
            raise ValidationError({'phone_number': 'Phone number is required'})
        
        if not self.phone_number.startswith('+'):
            raise ValidationError({
                'phone_number': 'Phone number must be in international format (+254...)'
            })
        
        # Validate phone_number_hash
        if not self.phone_number_hash or self.phone_number_hash == '':
            raise ValidationError({
                'phone_number_hash': 'Phone number hash cannot be empty'
            })
    
    def save(self, *args, **kwargs):
        """Override save to ensure hash is always generated"""
        
        # Auto-generate hash if phone_number exists but hash doesn't
        if self.phone_number and not self.phone_number_hash:
            self.phone_number_hash = hashlib.sha256(
                self.phone_number.encode()
            ).hexdigest()
        
        # Final validation: Prevent saving empty hash
        if not self.phone_number_hash or self.phone_number_hash.strip() == '':
            raise ValueError(
                'Cannot save user without phone_number_hash. '
                'Phone number is required for hash generation.'
            )
        
        # Ensure phone number is in correct format
        if not self.phone_number.startswith('+'):
            raise ValueError(
                'Phone number must be in international format starting with +'
            )
        
        super().save(*args, **kwargs)
    
    def update_last_login(self):
        """Update login tracking"""
        self.last_login_at = timezone.now()
        self.login_count += 1
        self.save(update_fields=['last_login_at', 'login_count'])


class OTPVerification(models.Model):
    """OTP verification for phone number authentication"""
    
    phone_number = models.CharField(max_length=20)
    otp_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_verified = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)
    
    # Security tracking
    attempts = models.IntegerField(default=0)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, null=True)
    
    class Meta:
        db_table = 'otp_verifications'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['phone_number', 'is_verified']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        status = 'Verified' if self.is_verified else 'Pending'
        return f"OTP for {self.phone_number} - {status}"
    
    def is_expired(self):
        """Check if OTP is expired"""
        return timezone.now() > self.expires_at
    
    def increment_attempts(self):
        """Increment failed verification attempts"""
        self.attempts += 1
        self.save(update_fields=['attempts'])
    
    def mark_verified(self):
        """Mark OTP as verified"""
        self.is_verified = True
        self.verified_at = timezone.now()
        self.save(update_fields=['is_verified', 'verified_at'])


class AuthAttempt(models.Model):
    """Track authentication attempts for security monitoring"""
    
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