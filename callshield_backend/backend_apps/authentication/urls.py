# backend_apps/authentication/urls.py

from django.urls import path
from . import views

app_name = 'authentication'

urlpatterns = [
    # Authentication endpoints
    path('request-otp/', views.request_otp, name='request-otp'),
    path('verify-otp/', views.verify_otp, name='verify-otp'),
    path('refresh-token/', views.refresh_token, name='refresh-token'),
    path('logout/', views.logout, name='logout'),
    
    # User endpoints
    path('me/', views.get_current_user, name='current-user'),
    path('profile/', views.update_profile, name='update-profile'),
    
    # Health check
    path('health/', views.health_check, name='health-check'),
]