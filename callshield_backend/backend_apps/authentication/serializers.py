# backend_apps/authentication/serializers.py

from rest_framework import serializers
from .models import User, AuthAttempt
import phonenumbers
from phonenumbers import NumberParseException


class PhoneNumberField(serializers.CharField):
    """Custom field for validating Kenyan phone numbers"""
    
    def to_internal_value(self, data):
        # Allow blank/unknown for anonymous callers
        if not data or str(data).strip() in ('', 'Unknown', 'unknown'):
            return ''
        try:
            # Parse phone number
            parsed = phonenumbers.parse(data, 'KE')

            # Validate
            if not phonenumbers.is_valid_number(parsed):
                raise serializers.ValidationError('Invalid phone number')

            # Return in international format
            return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)

        except NumberParseException:
            raise serializers.ValidationError('Invalid phone number format. Use +254XXXXXXXXX or 07XXXXXXXX')


class RequestOTPSerializer(serializers.Serializer):
    """Serializer for requesting OTP"""
    
    phone_number = PhoneNumberField(
        required=True,
        help_text="Phone number in format +254XXXXXXXXX or 07XXXXXXXX"
    )
    
    def validate_phone_number(self, value):
        """Additional validation for phone number"""
        # Ensure it starts with +254 (Kenya)
        if not value.startswith('+254'):
            raise serializers.ValidationError('Only Kenyan phone numbers are supported')
        
        return value


class VerifyOTPSerializer(serializers.Serializer):
    """Serializer for verifying OTP"""
    
    phone_number = PhoneNumberField(required=True)
    otp = serializers.CharField(
        required=True,
        min_length=6,
        max_length=6,
        help_text="6-digit OTP code"
    )
    device_id = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Device identifier (optional)"
    )
    device_model = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Device model (optional)"
    )
    os_version = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="OS version (optional)"
    )
    app_version = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="App version (optional)"
    )
    
    def validate_otp(self, value):
        """Validate OTP format"""
        if not value.isdigit():
            raise serializers.ValidationError('OTP must contain only digits')
        return value


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model"""
    
    class Meta:
        model = User
        fields = [
            'id',
            'phone_number',
            'display_name',
            'user_type',
            'phone_verified',
            'language_preference',
            'created_at',
            'last_login_at',
            'total_calls_protected',
            'total_scams_blocked',
            'total_reports_submitted',
            'total_training_contributions',
        ]
        read_only_fields = [
            'id',
            'phone_number',
            'phone_verified',
            'created_at',
            'last_login_at',
            'total_calls_protected',
            'total_scams_blocked',
            'total_reports_submitted',
            'total_training_contributions',
        ]


class TokenResponseSerializer(serializers.Serializer):
    """Serializer for token response"""
    
    access_token = serializers.CharField()
    refresh_token = serializers.CharField()
    user = UserSerializer()
    message = serializers.CharField(default="Login successful")


class RefreshTokenSerializer(serializers.Serializer):
    """Serializer for token refresh"""
    
    refresh_token = serializers.CharField(required=True)