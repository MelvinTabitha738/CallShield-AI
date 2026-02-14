from .base import *

DEBUG = True

ALLOWED_HOSTS = ['localhost', '127.0.0.1', '10.0.2.2']

# Development-specific settings
SMS_BACKEND = 'console'
MOCK_OTP_ENABLED = True

# Email backend for development (prints to console)
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'