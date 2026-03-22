# backend_apps/real_time_detection/views.py

from django.core.cache import cache
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import CallSession
from .serializers import (
    CallSessionSerializer,
    EndSessionSerializer,
    ProcessChunkSerializer,
    StartSessionSerializer,
)
from .services import CallSessionService, AudioProcessingService
from .ml_integration import MLModelInterface


# ─────────────────────────────────────────────────────────────────────
# Public
# ─────────────────────────────────────────────────────────────────────

def health_check(request):
    """
    Simple health-check for the detection service.
    GET /api/detection/health/
    No authentication required.
    """
    model_info = MLModelInterface.get_model_info()
    return JsonResponse({
        'status':         'healthy',
        'service':        'CallShield Real-Time Detection API',
        'ml_model_ready': model_info.get('ready', True),
        'model_info':     model_info,
        'timestamp':      timezone.now().isoformat(),
    })


# ─────────────────────────────────────────────────────────────────────
# Authenticated
# ─────────────────────────────────────────────────────────────────────

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def start_session(request):
    """
    Start a new call protection session.

    POST /api/detection/start-session/
    Authorization: Bearer <token>

    Body:
    {
        "phone_number": "+254700888999",
        "device_id":    "android-abc123",   (optional)
        "app_version":  "1.0.0",            (optional)
        "user_consented": true              (optional, default true)
    }

    Response:
    {
        "success":           true,
        "session_id":        "<uuid>",
        "initial_risk_score": 0,
        "caller_risk":       0,
        "is_known_scammer":  false,
        "alert_threshold":   70,
        "status":            "active",
        "ml_model_ready":    true,
        "message":           "Session started - protection active"
    }
    """
    serializer = StartSessionSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(
            {'success': False, 'errors': serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )

    session = CallSessionService.start_session(
        user=request.user,
        phone_number=serializer.validated_data['phone_number'],
        device_id=serializer.validated_data.get('device_id', ''),
        app_version=serializer.validated_data.get('app_version', ''),
        user_consented=serializer.validated_data.get('user_consented', True),
    )

    # Cache raw caller number so the browser companion can auto-fill it (10-min TTL)
    raw_number = serializer.validated_data.get('phone_number', '')
    if raw_number:
        cache.set(f'caller_number_{session.id}', raw_number, timeout=600)

    return Response(
        {
            'success':            True,
            'message':            'Session started - protection active',
            'session_id':         str(session.id),
            'initial_risk_score': session.initial_risk_score,
            'caller_risk':        session.initial_risk_score,
            'is_known_scammer':   session.initial_risk_score >= 70,
            'alert_threshold':    session.alert_threshold,
            'status':             session.status,
            'ml_model_ready':     True,
        },
        status=status.HTTP_201_CREATED,
    )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def process_chunk(request):
    """
    Submit an audio chunk for real-time ML analysis.

    POST /api/detection/process-chunk/
    Authorization: Bearer <token>
    Content-Type: multipart/form-data

    Body:
    {
        "session_id":   "<uuid>",
        "audio_chunk":  <binary audio file>,
        "chunk_number": 1,
        "timestamp":    "2024-02-15T12:30:05Z"
    }

    Response:
    {
        "success":           true,
        "session_id":        "<uuid>",
        "chunk_number":      1,
        "analyzed":          true,
        "current_risk":      45,
        "peak_risk":         45,
        "risk_level":        "MODERATE",
        "should_alert":      false,
        "alert_message":     null,
        "patterns_detected": ["mentions_authority"],
        "scam_type":         null,
        "transcript_chunk":  "Hello, this is KRA calling about...",
        "ml_confidence":     0.78,
        "ml_model_used":     true
    }
    """
    serializer = ProcessChunkSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(
            {'success': False, 'errors': serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Retrieve caller number from request (sent by Android alongside audio)
    caller_number = request.data.get('caller_number', '')

    # Process audio chunk
    result = AudioProcessingService.process_audio_chunk(
        session_id=serializer.validated_data['session_id'],
        user=request.user,
        audio_file=serializer.validated_data['audio_chunk'],
        chunk_number=serializer.validated_data['chunk_number'],
        timestamp=serializer.validated_data['timestamp'],
        caller_number=caller_number,
    )

    http_status = (
        status.HTTP_200_OK
        if result.get('success')
        else status.HTTP_400_BAD_REQUEST
    )
    return Response(result, status=http_status)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def end_session(request):
    """
    End a call session. Privacy policy is enforced automatically.

    POST /api/detection/end-session/
    Authorization: Bearer <token>

    Body:
    {
        "session_id":              "<uuid>",
        "call_duration":           180,          (optional, seconds)
        "user_consented_storage":  false,        (required: true/false)
        "user_consented_training": false,        (optional, default false)
        "user_feedback_notes":     "Aggressive caller"  (optional)
    }

    Response:
    {
        "success":             true,
        "session_id":          "<uuid>",
        "scam_detected":       true,
        "final_risk_score":    85,
        "peak_risk_score":     90,
        "scam_type":           "kra_impersonation",
        "call_duration":       180,
        "alert_triggered":     true,
        "patterns_detected":   ["urgency", "authority_impersonation"],
        "storage_action":      "deleted_no_consent",
        "scam_db_updated":     true,
        "recommendation":      "Number reported to scam database",
        "privacy_notice":      "✅ Conversation deleted - only scam report kept"
    }
    """
    serializer = EndSessionSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(
            {'success': False, 'errors': serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )

    result = CallSessionService.end_session(
        session_id=serializer.validated_data['session_id'],
        user=request.user,
        call_duration=serializer.validated_data.get('call_duration'),
        user_consented_storage=serializer.validated_data['user_consented_storage'],
        user_consented_training=serializer.validated_data.get('user_consented_training', False),
        user_feedback_notes=serializer.validated_data.get('user_feedback_notes', ''),
    )

    http_status = (
        status.HTTP_200_OK
        if result.get('success')
        else status.HTTP_400_BAD_REQUEST
    )
    return Response(result, status=http_status)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_session(request, session_id):
    """
    Get current metadata for a specific session.

    GET /api/detection/session/<session_id>/
    Authorization: Bearer <token>
    """
    try:
        session = CallSession.objects.get(id=session_id, user=request.user)
    except CallSession.DoesNotExist:
        return Response(
            {'success': False, 'message': 'Session not found.'},
            status=status.HTTP_404_NOT_FOUND,
        )

    return Response(
        {'success': True, 'session': CallSessionSerializer(session).data},
        status=status.HTTP_200_OK,
    )


def monitor_view(request):
    """
    Serve the browser companion page inline — no template file needed.
    GET /monitor/
    """
    import os
    template_path = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'templates', 'companion.html')
    template_path = os.path.normpath(template_path)
    with open(template_path, 'r', encoding='utf-8') as f:
        html = f.read()
    return HttpResponse(html, content_type='text/html')


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def active_session(request):
    """
    Return the current active call session for the authenticated user.
    The browser companion polls this every 2 seconds.

    GET /api/detection/active-session/
    Authorization: Bearer <token>

    Response (active):
    {
        "active": true,
        "session_id": "<uuid>",
        "current_risk_score": 45,
        "peak_risk_score": 60,
        "alert_triggered": false,
        "chunks_processed": 3
    }

    Response (idle):
    { "active": false }
    """
    session = (
        CallSession.objects
        .filter(user=request.user, status='active')
        .order_by('-started_at')
        .first()
    )

    if session:
        caller_number = cache.get(f'caller_number_{session.id}', '')
        return Response({
            'active':              True,
            'session_id':          str(session.id),
            'current_risk_score':  session.current_risk_score,
            'peak_risk_score':     session.peak_risk_score,
            'alert_triggered':     session.alert_triggered,
            'chunks_processed':    session.chunks_processed,
            'caller_number':       caller_number,
        })

    return Response({'active': False})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def my_sessions(request):
    """
    Get the current user's call session history (most recent 20).

    GET /api/detection/my-sessions/
    Authorization: Bearer <token>
    """
    sessions = (
        CallSession.objects
        .filter(user=request.user)
        .order_by('-started_at')[:20]
    )

    return Response(
        {
            'success':  True,
            'sessions': CallSessionSerializer(sessions, many=True).data,
            'total':    sessions.count(),
        },
        status=status.HTTP_200_OK,
    )