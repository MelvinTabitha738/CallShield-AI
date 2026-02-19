# backend_apps/real_time_detection/serializers.py

from rest_framework import serializers
from backend_apps.authentication.serializers import PhoneNumberField
from .models import CallSession


class StartSessionSerializer(serializers.Serializer):
    """Validate a start-session request."""

    phone_number = PhoneNumberField(
        required=True,
        help_text="Caller's phone number (+254XXXXXXXXX or 07XXXXXXXX).",
    )
    device_id   = serializers.CharField(required=False, allow_blank=True, default='')
    app_version = serializers.CharField(required=False, allow_blank=True, default='')


class ProcessChunkSerializer(serializers.Serializer):
    """Validate a transcript chunk submitted for real-time analysis."""

    session_id = serializers.UUIDField(
        required=True,
        help_text='Session UUID returned by /start-session/.',
    )
    transcript_text = serializers.CharField(
        required=True,
        min_length=1,
        help_text='Transcribed text of the most recent audio chunk.',
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
    speaker = serializers.ChoiceField(
        choices=['user', 'caller', 'unknown'],
        default='unknown',
        help_text='Who was speaking in this chunk.',
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

    # ← FIXED: BooleanField with allow_null instead of NullBooleanField
    user_confirmed_scam = serializers.BooleanField(
        required=False,
        allow_null=True,
        default=None,
        help_text='True = scam, False = not a scam, null = user unsure.',
    )

    user_feedback_notes = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=1000,
        default='',
        help_text='Optional free-text notes about the call.',
    )
    user_consented_storage = serializers.BooleanField(
        required=False,
        default=False,
        help_text='User consents to storing PII-redacted transcript for 90 days.',
    )
    user_consented_training = serializers.BooleanField(
        required=False,
        default=False,
        help_text='User consents to using transcript for ML model training.',
    )

    def validate(self, data):
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
            'user_confirmed_scam',
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