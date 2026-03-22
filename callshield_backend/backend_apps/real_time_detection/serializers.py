# backend_apps/real_time_detection/serializers.py

from rest_framework import serializers
from backend_apps.authentication.serializers import PhoneNumberField
from .models import CallSession


class StartSessionSerializer(serializers.Serializer):
    """Validate a start-session request."""

    phone_number = PhoneNumberField(
        required=False,
        allow_blank=True,
        default='',
        help_text="Caller's phone number (+254XXXXXXXXX or 07XXXXXXXX). Optional — omit for private/unknown callers.",
    )
    device_id   = serializers.CharField(required=False, allow_blank=True, default='')
    app_version = serializers.CharField(required=False, allow_blank=True, default='')
    user_consented = serializers.BooleanField(
        required=False,
        default=True,
        help_text='User consent to record and analyze the call.',
    )


class ProcessChunkSerializer(serializers.Serializer):
    """
    Validate an audio chunk submitted for real-time analysis.
    
    Audio is sent as a file upload, analyzed immediately, then discarded.
    Only the transcript is temporarily stored in the session.
    """

    session_id = serializers.UUIDField(
        required=True,
        help_text='Session UUID returned by /start-session/.',
    )
    
    # Audio file (multipart upload)
    audio_chunk = serializers.FileField(
        required=True,
        help_text='2-second audio chunk (WAV, MP3, or raw PCM).',
    )
    
    chunk_number = serializers.IntegerField(
        required=True,
        min_value=1,
        help_text='Sequential position of this chunk (starts at 1).',
    )
    
    timestamp = serializers.DateTimeField(
        required=True,
        help_text='ISO-8601 datetime when this chunk was captured on the device.',
    )


class EndSessionSerializer(serializers.Serializer):
    """Validate an end-session request."""

    session_id = serializers.UUIDField(required=True)

    call_duration = serializers.IntegerField(
        required=False,
        allow_null=True,
        min_value=0,
        help_text='Total call duration in seconds.',
    )

    # User consent for storage (REQUIRED for post-call decision)
    user_consented_storage = serializers.BooleanField(
        required=True,
        help_text='Did user consent to store conversation for training?',
    )
    
    user_consented_training = serializers.BooleanField(
        required=False,
        default=False,
        help_text='User consents to using transcript for ML model training.',
    )
    
    # Optional feedback
    user_feedback_notes = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=1000,
        default='',
        help_text='Optional free-text notes about the call.',
    )

    def validate(self, data):
        """Training consent requires storage consent."""
        if data.get('user_consented_training') and not data.get('user_consented_storage'):
            raise serializers.ValidationError({
                'user_consented_training':
                    'Cannot consent to training without first consenting to storage.',
            })
        return data


class CallSessionSerializer(serializers.ModelSerializer):
    """Read-only serializer for CallSession data returned to the app."""

    duration_display = serializers.SerializerMethodField()

    class Meta:
        model  = CallSession
        fields = [
            'id',
            'status',
            'initial_risk_score',
            'current_risk_score',
            'peak_risk_score',
            'final_risk_score',
            'ml_confidence',
            'alert_triggered',
            'alert_count',
            'call_duration_seconds',
            'duration_display',
            'chunks_processed',
            'scam_detected_by_ai',  # ← ADDED
            'user_consented_storage',  # ← ADDED
            'detected_patterns',
            'detected_scam_type',
            'auto_report_recommended',
            'content_deleted',
            'deletion_reason',
            'started_at',
            'ended_at',
        ]
        read_only_fields = fields

    def get_duration_display(self, obj):
        return obj.get_duration_display()