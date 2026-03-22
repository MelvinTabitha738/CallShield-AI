from django.urls import path
from . import views

app_name = 'real_time_detection'

urlpatterns = [
    # ── Public
    path('health/',         views.health_check,  name='health-check'),

    #  Authenticated
    path('start-session/',   views.start_session,   name='start-session'),
    path('process-chunk/',   views.process_chunk,   name='process-chunk'),
    path('end-session/',     views.end_session,     name='end-session'),
    path('my-sessions/',     views.my_sessions,     name='my-sessions'),
    path('active-session/',  views.active_session,  name='active-session'),

    # Session detail
    path('session/<uuid:session_id>/', views.get_session, name='get-session'),
]
