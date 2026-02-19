# backend_apps/real_time_detection/views.py

from django.http import JsonResponse
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .ml_integration import MLModelInterface
from .models import CallSession
from .serializers import (
    CallSessionSerializer,
    EndSessionSerializer,
    ProcessChunkSerializer,
    StartSessionSerializer,
)
from .services import CallSessionService, TranscriptProcessingService


# ─────────────────────────────────────────────────────────────────────
# Public
# ─────────────────────────────────────────────────────────────────────

def health_check(request):
    """
    Simple health-check for the detection service.
    GET /api/detection/health/
    No authentication required.
    """
    return JsonResponse({
        'status':          'healthy',
        'service':         'CallShield Real-Time Detection API',
        'ml_model_ready':  MLModelInterface.is_ready(),
        'model_info':      MLModelInterface.get_model_info(),
        'timestamp':       timezone.now().isoformat(),
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
        "app_version":  "1.0.0"             (optional)
    }

    Response:
    {
        "success":           true,
        "session_id":        "<uuid>",
        "initial_risk_score": 0,
        "alert_threshold":   70,
        "status":            "active",
        "ml_model_ready":    false
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
    )

    return Response(
        {
            'success':            True,
            'message':            'CallShield session started.',
            'session_id':         str(session.id),
            'initial_risk_score': session.initial_risk_score,
            'alert_threshold':    session.alert_threshold,
            'status':             session.status,
            'ml_model_ready':     MLModelInterface.is_ready(),
        },
        status=status.HTTP_201_CREATED,
    )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def process_chunk(request):
    """
    Submit a transcript chunk for real-time ML analysis.

    POST /api/detection/process-chunk/
    Authorization: Bearer <token>

    Body:
    {
        "session_id":      "<uuid>",
        "transcript_text": "Hello I am calling from KRA…",
        "chunk_number":    1,
        "timestamp":       "2024-02-15T12:30:05Z",
        "speaker":         "caller"    (optional: user / caller / unknown)
    }

    Response:
    {
        "success":           true,
        "session_id":        "<uuid>",
        "chunk_number":      1,
        "current_risk":      0,
        "risk_level":        "SAFE",
        "should_alert":      false,
        "alert_message":     null,
        "patterns_detected": [],
        "scam_type":         null,
        "ml_confidence":     0.0,
        "ml_model_used":     false,
        "analyzed":          false,
        "error":             "ML model not loaded.",
        "privacy_notice":    "⚠️ Transcript is temporary …"
    }
    """
    serializer = ProcessChunkSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(
            {'success': False, 'errors': serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )

    result = TranscriptProcessingService.process_chunk(
        session_id=serializer.validated_data['session_id'],
        user=request.user,
        transcript_text=serializer.validated_data['transcript_text'],
        chunk_number=serializer.validated_data['chunk_number'],
        timestamp=serializer.validated_data['timestamp'],
        speaker=serializer.validated_data.get('speaker', 'unknown'),
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
        "user_confirmed_scam":     true,         (true / false / null)
        "user_feedback_notes":     "Very aggressive caller",  (optional)
        "user_consented_storage":  true,         (default false)
        "user_consented_training": true          (default false)
    }

    Response:
    {
        "success":             true,
        "session_id":          "<uuid>",
        "final_risk_score":    85,
        "peak_risk_score":     90,
        "call_duration":       180,
        "alert_triggered":     true,
        "patterns_detected":   ["urgency", "impersonation"],
        "detected_scam_type":  "kra_impersonation",
        "storage_action":      "stored_for_training",
        "recommendation":      "Thank you for reporting!",
        "privacy_notice":      "✅ Transcript stored for 90 days …"
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
        user_confirmed_scam=serializer.validated_data.get('user_confirmed_scam'),
        user_feedback_notes=serializer.validated_data.get('user_feedback_notes', ''),
        user_consented_storage=serializer.validated_data.get('user_consented_storage', False),
        user_consented_training=serializer.validated_data.get('user_consented_training', False),
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