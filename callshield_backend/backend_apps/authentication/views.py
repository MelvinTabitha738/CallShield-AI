# backend_apps/authentication/views.py

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.utils import timezone

from .models import User
from .serializers import (
    RequestOTPSerializer,
    VerifyOTPSerializer,
    UserSerializer,
    TokenResponseSerializer,
    RefreshTokenSerializer
)
from .services import OTPService, AuthService


@api_view(['POST'])
@permission_classes([AllowAny])
def request_otp(request):
    """
    Request OTP for phone number
    
    POST /api/auth/request-otp/
    Body: {
        "phone_number": "+254712555123"
    }
    """
    serializer = RequestOTPSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response(
            {
                'success': False,
                'errors': serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )
    
    phone_number = serializer.validated_data['phone_number']
    
    # Send OTP
    result = OTPService.send_otp(phone_number, request=request)
    
    if result['success']:
        return Response(
            {
                'success': True,
                'message': result['message'],
                'phone_number': phone_number,
                'expires_in_minutes': result['expires_in_minutes']
            },
            status=status.HTTP_200_OK
        )
    else:
        return Response(
            {
                'success': False,
                'message': result['message']
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_otp(request):
    """
    Verify OTP and login/register user
    
    POST /api/auth/verify-otp/
    Body: {
        "phone_number": "+254712555123",
        "otp": "123456",
        "device_id": "android-abc123",  // optional
        "device_model": "Samsung Galaxy A14",  // optional
        "os_version": "Android 13",  // optional
        "app_version": "1.0.0"  // optional
    }
    """
    serializer = VerifyOTPSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response(
            {
                'success': False,
                'errors': serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )
    
    phone_number = serializer.validated_data['phone_number']
    otp_code = serializer.validated_data['otp']
    
    # Verify OTP
    success, message = OTPService.verify_otp(phone_number, otp_code)
    
    if not success:
        return Response(
            {
                'success': False,
                'message': message
            },
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # OTP verified - get or create user
    device_data = {
        'device_id': serializer.validated_data.get('device_id'),
        'device_model': serializer.validated_data.get('device_model'),
        'os_version': serializer.validated_data.get('os_version'),
        'app_version': serializer.validated_data.get('app_version'),
    }
    
    # Remove None values
    device_data = {k: v for k, v in device_data.items() if v}
    
    user, created = AuthService.get_or_create_user(phone_number, **device_data)
    
    # Update login info
    AuthService.update_login_info(user)
    
    # Generate tokens
    tokens = AuthService.generate_tokens(user)
    
    # Prepare response
    response_data = {
        'success': True,
        'message': 'Login successful' if not created else 'Account created successfully',
        'is_new_user': created,
        'access_token': tokens['access_token'],
        'refresh_token': tokens['refresh_token'],
        'user': UserSerializer(user).data
    }
    
    return Response(response_data, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
def refresh_token(request):
    """
    Refresh access token using refresh token
    
    POST /api/auth/refresh-token/
    Body: {
        "refresh_token": "your-refresh-token-here"
    }
    """
    serializer = RefreshTokenSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response(
            {
                'success': False,
                'errors': serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )
    
    refresh_token_str = serializer.validated_data['refresh_token']
    
    try:
        # Create RefreshToken instance
        refresh = RefreshToken(refresh_token_str)
        
        # Generate new access token
        new_access_token = str(refresh.access_token)
        
        return Response(
            {
                'success': True,
                'access_token': new_access_token,
                'message': 'Token refreshed successfully'
            },
            status=status.HTTP_200_OK
        )
        
    except TokenError as e:
        return Response(
            {
                'success': False,
                'message': 'Invalid or expired refresh token',
                'error': str(e)
            },
            status=status.HTTP_401_UNAUTHORIZED
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    """
    Logout user (blacklist refresh token)
    
    POST /api/auth/logout/
    Headers: Authorization: Bearer <access-token>
    Body: {
        "refresh_token": "your-refresh-token-here"
    }
    """
    try:
        refresh_token = request.data.get('refresh_token')
        
        if not refresh_token:
            return Response(
                {
                    'success': False,
                    'message': 'Refresh token is required'
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Blacklist the refresh token
        token = RefreshToken(refresh_token)
        token.blacklist()
        
        return Response(
            {
                'success': True,
                'message': 'Logout successful'
            },
            status=status.HTTP_200_OK
        )
        
    except TokenError:
        return Response(
            {
                'success': False,
                'message': 'Invalid token'
            },
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {
                'success': False,
                'message': 'Logout failed',
                'error': str(e)
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_current_user(request):
    """
    Get current authenticated user info
    
    GET /api/auth/me/
    Headers: Authorization: Bearer <access-token>
    """
    user = request.user
    
    return Response(
        {
            'success': True,
            'user': UserSerializer(user).data
        },
        status=status.HTTP_200_OK
    )


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def update_profile(request):
    """
    Update user profile
    
    PATCH /api/auth/profile/
    Headers: Authorization: Bearer <access-token>
    Body: {
        "display_name": "Melvin Tabitha",  // optional
        "language_preference": "sw"  // optional (en, sw)
    }
    """
    user = request.user
    serializer = UserSerializer(user, data=request.data, partial=True)
    
    if not serializer.is_valid():
        return Response(
            {
                'success': False,
                'errors': serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )
    
    serializer.save()
    
    return Response(
        {
            'success': True,
            'message': 'Profile updated successfully',
            'user': serializer.data
        },
        status=status.HTTP_200_OK
    )


@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """
    Health check endpoint (for monitoring)
    
    GET /api/auth/health/
    """
    return Response(
        {
            'status': 'healthy',
            'service': 'CallShield Authentication API',
            'timestamp': timezone.now().isoformat()
        },
        status=status.HTTP_200_OK
    )