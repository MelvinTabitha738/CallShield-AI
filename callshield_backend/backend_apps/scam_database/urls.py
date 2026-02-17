# backend_apps/scam_database/urls.py

from django.urls import path
from . import views

app_name = 'scam_database'

urlpatterns = [
    # Public endpoints
    path('check-number/', views.check_number, name='check-number'),
    path('number-details/<str:phone_number>/', views.number_details, name='number-details'),
    path('health/', views.health_check, name='health-check'),
    
    # Authenticated endpoints
    path('report-scam/', views.report_scam, name='report-scam'),
    path('my-reports/', views.my_reports, name='my-reports'),
    
    # Admin endpoints
    path('admin/stats/', views.admin_stats, name='admin-stats'),
]