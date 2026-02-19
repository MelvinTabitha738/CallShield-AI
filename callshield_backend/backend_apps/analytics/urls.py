from django.urls import path
from . import views

app_name = 'analytics'

urlpatterns = [
    #User Analytics 
    path(
        'user/stats/',
        views.user_stats,
        name='user-stats'
    ),
    
    #Admin Analytics
    path(
        'admin/overview/',
        views.system_overview,
        name='admin-overview'
    ),
    path(
        'admin/activity/',
        views.time_based_activity,
        name='admin-activity'
    ),
    path(
        'admin/trends/',
        views.scam_trends,
        name='admin-trends'
    ),
    path(
        'admin/engagement/',
        views.user_engagement,
        name='admin-engagement'
    ),
    
    #Public Analytics
    path(
        'public/impact/',
        views.community_impact,
        name='public-impact'
    ),
    path(
        'public/scam-intelligence/',
        views.scam_intelligence,
        name='public-scam-intelligence'
    ),
]