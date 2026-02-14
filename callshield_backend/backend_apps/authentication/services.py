# backend_apps/authentication/services.py

import random
import hashlib
from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, AuthAttempt


class OTPService:
    """Service for handling OTP generation and verification"""
    
    OTP_EXPIRY_MINUTES = 10
    MAX_OTP_ATTEMPTS = 5
    
    @staticmethod
    def generate_otp():
        """Generate a 6-digit OTP"""
        return str(random.randint(100000, 999999))
    
    @staticmethod
    def send_otp(phone_number, request=None):
        """
        Generate and send OTP to phone number
        
        Args:
            phone_number (str): Phone number to send OTP to
            request: HTTP request object (for IP, user agent)
        
        Returns:
            dict: Result of OTP generation
        """
        # Generate OTP
        otp_code = OTPService.generate_otp()
        
        # Calculate expiry
        expires_at = timezone.now() + timedelta(minutes=OTPService.OTP_EXPIRY_MINUTES)
        
        # Get client info
        ip_address = None
        user_agent = None
        if request:
            ip_address = OTPService._get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]
        
        # Save OTP attempt
        auth_attempt = AuthAttempt.objects.create(
            phone_number=phone_number,
            otp_code=otp_code,
            otp_expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Send OTP via SMS (or console in development)
        sms_sent = OTPService._send_sms(phone_number, otp_code)
        
        if sms_sent:
            return {
                'success': True,
                'message': f'OTP sent to {phone_number}',
                'expires_in_minutes': OTPService.OTP_EXPIRY_MINUTES
            }
        else:
            return {
                'success': False,
                'message': 'Failed to send OTP. Please try again.'
            }
    
    @staticmethod
    def verify_otp(phone_number, otp_code):
        """
        Verify OTP code
        
        Args:
            phone_number (str): Phone number
            otp_code (str): OTP code to verify
        
        Returns:
            tuple: (success: bool, message: str)
        """
        # Mock OTP check (development only)
        if settings.MOCK_OTP_ENABLED and otp_code == "123456":
            return True, "OTP verified (mock mode)"
        
        # Find recent OTP attempt
        auth_attempt = AuthAttempt.objects.filter(
            phone_number=phone_number,
            verified=False,
            otp_expires_at__gt=timezone.now()
        ).order_by('-otp_sent_at').first()
        
        if not auth_attempt:
            return False, "No valid OTP found. Please request a new one."
        
        # Check attempts
        if auth_attempt.attempts >= OTPService.MAX_OTP_ATTEMPTS:
            return False, "Too many failed attempts. Please request a new OTP."
        
        # Verify OTP
        if auth_attempt.otp_code == otp_code:
            # Mark as verified
            auth_attempt.verified = True
            auth_attempt.save()
            return True, "OTP verified successfully"
        else:
            # Increment attempts
            auth_attempt.attempts += 1
            auth_attempt.save()
            
            remaining = OTPService.MAX_OTP_ATTEMPTS - auth_attempt.attempts
            return False, f"Invalid OTP. {remaining} attempts remaining."
    
    @staticmethod
    def _send_sms(phone_number, otp_code):
        """
        Send SMS based on configured backend
        
        Args:
            phone_number (str): Recipient phone number
            otp_code (str): OTP code to send
        
        Returns:
            bool: True if sent successfully
        """
        sms_backend = getattr(settings, 'SMS_BACKEND', 'console')
        
        if sms_backend == 'console':
            # Print to console (development)
            print("\n" + "="*60)
            print(f"📱 SMS TO: {phone_number}")
            print(f"📨 OTP CODE: {otp_code}")
            print(f"⏰ Valid for {OTPService.OTP_EXPIRY_MINUTES} minutes")
            print("="*60 + "\n")
            return True
        
        elif sms_backend == 'africastalking':
            # Africa's Talking integration (production)
            try:
                import africastalking
                
                # Initialize
                username = settings.AFRICASTALKING_USERNAME
                api_key = settings.AFRICASTALKING_API_KEY
                africastalking.initialize(username, api_key)
                
                # Get SMS service
                sms = africastalking.SMS
                
                # Send SMS
                message = f"Your CallShield verification code is: {otp_code}\n\nValid for {OTPService.OTP_EXPIRY_MINUTES} minutes."
                response = sms.send(message, [phone_number])
                
                return True
            except Exception as e:
                print(f"❌ SMS Error: {e}")
                return False
        
        else:
            # Unknown backend
            print(f"⚠️  Unknown SMS backend: {sms_backend}")
            return False
    
    @staticmethod
    def _get_client_ip(request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class AuthService:
    """Service for handling authentication"""
    
    @staticmethod
    def get_or_create_user(phone_number, **extra_data):
        """
        Get existing user or create new one
        
        Args:
            phone_number (str): Phone number
            **extra_data: Additional user data (device_id, etc.)
        
        Returns:
            tuple: (user, created)
        """
        # Get or create user
        user, created = User.objects.get_or_create(
            phone_number=phone_number,
            defaults={
                'display_name': f'User_{random.randint(1000, 9999)}',
                'phone_verified': True,
                **extra_data
            }
        )
        
        # Update device info if provided
        if not created and extra_data:
            for key, value in extra_data.items():
                if value:  # Only update if value provided
                    setattr(user, key, value)
            user.save()
        
        return user, created
    
    @staticmethod
    def generate_tokens(user):
        """
        Generate JWT tokens for user
        
        Args:
            user: User instance
        
        Returns:
            dict: Access and refresh tokens
        """
        refresh = RefreshToken.for_user(user)
        
        return {
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
        }
    
    @staticmethod
    def update_login_info(user):
        """Update user's last login information"""
        user.update_last_login()