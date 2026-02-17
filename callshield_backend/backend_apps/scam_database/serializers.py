# backend_apps/scam_database/serializers.py

from rest_framework import serializers
from .models import (
    PhoneNumberActive,
    PhoneNumberArchived,
    ScamIncident,
    ScamEvidence,
    ReporterCredibility,
    ScamType
)
from backend_apps.authentication.serializers import PhoneNumberField


class ScamTypeField(serializers.ChoiceField):
    """Custom field for scam type validation"""
    
    def __init__(self, **kwargs):
        kwargs['choices'] = ScamType.choices
        super().__init__(**kwargs)


class CheckNumberSerializer(serializers.Serializer):
    """Serializer for checking if number is in scam database"""
    
    phone_number = PhoneNumberField(
        required=True,
        help_text="Phone number to check"
    )


class CheckNumberResponseSerializer(serializers.Serializer):
    """Response for number check"""
    
    status = serializers.ChoiceField(
        choices=['active', 'archived', 'clean']
    )
    risk_score = serializers.IntegerField()
    risk_level = serializers.CharField()
    scam_type = serializers.CharField(allow_null=True)
    report_count = serializers.IntegerField()
    verified_reports = serializers.IntegerField()
    last_reported = serializers.DateTimeField(allow_null=True)
    should_warn = serializers.BooleanField()


class ReportScamSerializer(serializers.Serializer):
    """Serializer for submitting scam reports"""
    
    phone_number = PhoneNumberField(
        required=True,
        help_text="Scammer's phone number"
    )
    scam_type = ScamTypeField(
        required=True,
        help_text="Type of scam"
    )
    severity = serializers.IntegerField(
        required=True,
        min_value=0,
        max_value=100,
        help_text="Severity score (0-100)"
    )
    
    # Evidence fields (AT LEAST ONE REQUIRED - validated in view)
    narrative = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=5000,
        help_text="Detailed description (min 50 chars recommended)"
    )
    audio_file = serializers.FileField(
        required=False,
        allow_null=True,
        help_text="Call recording"
    )
    transcript = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=10000,
        help_text="Conversation transcript"
    )
    screenshot_1 = serializers.ImageField(
        required=False,
        allow_null=True,
        help_text="Screenshot 1"
    )
    screenshot_2 = serializers.ImageField(
        required=False,
        allow_null=True,
        help_text="Screenshot 2"
    )
    screenshot_3 = serializers.ImageField(
        required=False,
        allow_null=True,
        help_text="Screenshot 3"
    )
    
    # Metadata
    call_duration = serializers.IntegerField(
        required=False,
        allow_null=True,
        min_value=0,
        help_text="Call duration in seconds"
    )
    user_confidence = serializers.IntegerField(
        required=False,
        min_value=1,
        max_value=10,
        default=5,
        help_text="User confidence (1-10)"
    )
    tags = serializers.ListField(
        child=serializers.CharField(max_length=50),
        required=False,
        allow_empty=True,
        help_text="Keywords/tags"
    )
    amount_lost = serializers.DecimalField(
        required=False,
        allow_null=True,
        max_digits=10,
        decimal_places=2,
        help_text="Amount lost in KES"
    )
    region = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=100,
        help_text="County/region"
    )
    
    # Consent
    user_consented_storage = serializers.BooleanField(
        required=False,
        default=False,
        help_text="Consent to store evidence"
    )
    user_consented_training = serializers.BooleanField(
        required=False,
        default=False,
        help_text="Consent to use for ML training"
    )
    
    def validate(self, data):
        """Validate that at least ONE piece of evidence is provided"""
        
        has_narrative = data.get('narrative', '').strip() and len(data.get('narrative', '').strip()) >= 50
        has_audio = data.get('audio_file') is not None
        has_transcript = data.get('transcript', '').strip() and len(data.get('transcript', '').strip()) >= 100
        has_screenshot = any([
            data.get('screenshot_1'),
            data.get('screenshot_2'),
            data.get('screenshot_3')
        ])
        
        if not any([has_narrative, has_audio, has_transcript, has_screenshot]):
            raise serializers.ValidationError({
                'evidence': 'You must provide at least ONE of: Detailed narrative (50+ chars), audio recording, transcript (100+ chars), or screenshot'
            })
        
        # Validate narrative length if provided
        if data.get('narrative') and len(data.get('narrative', '').strip()) < 50:
            raise serializers.ValidationError({
                'narrative': 'Narrative must be at least 50 characters if provided'
            })
        
        # Audio requires storage consent
        if data.get('audio_file') and not data.get('user_consented_storage'):
            raise serializers.ValidationError({
                'user_consented_storage': 'You must consent to storage when uploading audio'
            })
        
        # Training requires storage
        if data.get('user_consented_training') and not data.get('user_consented_storage'):
            raise serializers.ValidationError({
                'user_consented_training': 'Cannot consent to training without storage consent'
            })
        
        return data


class ScamIncidentSerializer(serializers.ModelSerializer):
    """Serializer for scam incidents"""
    
    phone_number_hash_display = serializers.SerializerMethodField()
    evidence_summary = serializers.SerializerMethodField()
    
    class Meta:
        model = ScamIncident
        fields = [
            'id',
            'phone_number_hash_display',
            'scam_type',
            'severity',
            'source',
            'evidence_quality',
            'has_recording',
            'has_transcript',
            'verified',
            'verified_by_ai',
            'confidence_score',
            'incident_datetime',
            'reported_at',
            'victim_lost_money',
            'amount_lost',
            'region',
            'evidence_summary'
        ]
        read_only_fields = ['id', 'reported_at']
    
    def get_phone_number_hash_display(self, obj):
        """Get truncated hash for display"""
        return obj.get_display_hash(obj.phone_number_hash)
    
    def get_evidence_summary(self, obj):
        """Get summary of evidence"""
        evidence = obj.evidence.first()
        if not evidence:
            return 'No evidence'
        
        parts = []
        if evidence.narrative:
            parts.append('Text')
        if evidence.audio_file:
            parts.append('Audio')
        if evidence.transcript:
            parts.append('Transcript')
        if evidence.screenshot_1 or evidence.screenshot_2 or evidence.screenshot_3:
            parts.append('Screenshots')
        
        return ', '.join(parts) if parts else 'No evidence'


class MyReportsSerializer(serializers.Serializer):
    """Serializer for user's report history"""
    
    incidents = ScamIncidentSerializer(many=True)
    total_reports = serializers.IntegerField()
    verified_reports = serializers.IntegerField()
    pending_reports = serializers.IntegerField()
    credibility_tier = serializers.CharField()
    credibility_score = serializers.FloatField()


class PhoneNumberActiveSerializer(serializers.ModelSerializer):
    """Serializer for active scam numbers"""
    
    phone_number_hash_display = serializers.SerializerMethodField()
    risk_level = serializers.SerializerMethodField()
    
    class Meta:
        model = PhoneNumberActive
        fields = [
            'id',
            'phone_number_hash_display',
            'risk_score',
            'risk_level',
            'primary_scam_type',
            'report_count',
            'verified_reports',
            'first_reported_at',
            'last_reported_at',
            'last_incident_at',
            'decay_factor',
            'total_victims_estimated',
            'total_amount_lost_estimated',
            'days_since_last_incident',
            'eligible_for_archive'
        ]
    
    def get_phone_number_hash_display(self, obj):
        return obj.get_display_hash(obj.phone_number_hash)
    
    def get_risk_level(self, obj):
        return obj.get_risk_level()


class NumberDetailsSerializer(serializers.Serializer):
    """Detailed information about a number"""
    
    status = serializers.CharField()
    risk_score = serializers.IntegerField()
    risk_level = serializers.CharField()
    scam_type = serializers.CharField(allow_null=True)
    report_count = serializers.IntegerField()
    verified_reports = serializers.IntegerField()
    last_reported = serializers.DateTimeField(allow_null=True)
    
    # Statistics
    total_incidents = serializers.IntegerField()
    total_amount_lost = serializers.DecimalField(max_digits=12, decimal_places=2)
    scam_types_distribution = serializers.ListField()
    
    # Recent incidents (limited)
    recent_incidents = ScamIncidentSerializer(many=True)


class StatsSerializer(serializers.Serializer):
    """Overall statistics (admin only)"""
    
    total_active_numbers = serializers.IntegerField()
    total_archived_numbers = serializers.IntegerField()
    total_incidents = serializers.IntegerField()
    total_reports_today = serializers.IntegerField()
    total_reports_week = serializers.IntegerField()
    total_reports_month = serializers.IntegerField()
    
    # Risk distribution
    high_risk_count = serializers.IntegerField()
    medium_risk_count = serializers.IntegerField()
    
    # Scam types breakdown
    scam_types_breakdown = serializers.DictField()
    
    # Top scam types
    top_scam_types = serializers.ListField()