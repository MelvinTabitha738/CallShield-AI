# backend_apps/real_time_detection/models.py

import uuid
from django.db import models
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator
from django.conf import settings


class CallSession(models.Model):
    """
    Tracks a call protection session.

    PRIVACY POLICY:
    ─────────────────────────────────────────────────────────────
    - full_transcript: TEMPORARY. Built during call, deleted after.
    - Non-scam calls: Only metadata kept. No content stored.
    - Confirmed scams + consent: PII-redacted transcript stored
      in ConfirmedScamConversation, then full_transcript cleared.
    - No consent: ALL content deleted immediately.
    - All stored content: Auto-deleted after 90 days maximum.
    ─────────────────────────────────────────────────────────────
    """

    SESSION_STATUS = [
        ('active',    'Active'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
        ('error',     'Error'),
    ]

    DELETION_REASONS = [
        ('non_scam',    'Not a scam – deleted immediately'),
        ('no_consent',  'Scam confirmed but no storage consent given'),
        ('user_request','User explicitly requested deletion'),
        ('auto_expired','Auto-expired after 90 days'),
        ('session_end', 'Session ended without user confirmation'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # User who tapped the Shield button
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='call_sessions',
    )

    # Caller phone – HASH ONLY, never plaintext
    caller_number_hash = models.CharField(
        max_length=64, db_index=True,
        help_text='SHA-256 hash of caller number. Plaintext never stored.',
    )

    status = models.CharField(max_length=20, choices=SESSION_STATUS, default='active')

    # ── CUMULATIVE TRANSCRIPT (TEMPORARY - deleted after session) ────
    full_transcript = models.TextField(
        blank=True,
        help_text='Cumulative transcript built from all chunks. TEMPORARY - deleted post-call.',
    )
    
    # ── Risk Tracking (metadata only) ─────────────────────────────────
    initial_risk_score = models.IntegerField(
        default=0,
        help_text='Risk score from pre-call DB lookup.',
    )
    current_risk_score = models.IntegerField(
        default=0,
        help_text='Most recent ML model risk score.',
    )
    peak_risk_score = models.IntegerField(
        default=0,
        help_text='Highest risk score recorded during the call.',
    )
    final_risk_score = models.IntegerField(
        default=0,
        help_text='Risk score at the moment the call ended.',
    )
    ml_confidence = models.FloatField(
        default=0.0,
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)],
        help_text='ML model confidence at end of session (0.0–1.0).',
    )

    # ── Alert Tracking ────────────────────────────────────────────────
    alert_triggered = models.BooleanField(
        default=False,
        help_text='Whether a scam alert overlay was shown to the user.',
    )
    alert_count = models.IntegerField(
        default=0,
        help_text='Number of alerts shown during the call.',
    )
    alert_threshold = models.IntegerField(
        default=70,
        help_text='Risk score at which an alert is triggered.',
    )

    # ── Call Metadata (no conversation content) ──────────────────────
    call_duration_seconds = models.IntegerField(null=True, blank=True)
    chunks_processed = models.IntegerField(
        default=0,
        help_text='Number of audio chunks analyzed by the ML model.',
    )

    # ── User Feedback ─────────────────────────────────────────────────
    user_confirmed_scam = models.BooleanField(
        null=True, blank=True,
        help_text='AI decides scam status. This is for user override only.',
    )
    user_consented_storage = models.BooleanField(
        default=False,
        help_text='Did user consent to store conversation for training?',
    )
    user_feedback_notes = models.TextField(blank=True)

    # ── Detection Results (labels only, no raw transcript) ────────────
    detected_patterns = models.JSONField(
        default=list,
        help_text='Scam pattern labels returned by the ML model.',
    )
    detected_scam_type = models.CharField(max_length=50, blank=True)

    scam_detected_by_ai = models.BooleanField(
        default=False,
        help_text='True if AI determined peak_risk >= 70%. AI decision, not user.',
    )

    auto_report_recommended = models.BooleanField(
        default=False,
        help_text='True if risk score reached threshold for auto-reporting (≥70).',
    )

    # ── Content Deletion Tracking ─────────────────────────────────────
    content_deleted = models.BooleanField(
        default=False,
        help_text='True once full_transcript has been cleared.',
    )
    content_deleted_at = models.DateTimeField(null=True, blank=True)
    deletion_reason = models.CharField(
        max_length=20, blank=True, choices=DELETION_REASONS,
    )

    # ── Device Info ───────────────────────────────────────────────────
    device_id   = models.CharField(max_length=255, blank=True)
    app_version = models.CharField(max_length=20,  blank=True)

    # ── Timestamps ────────────────────────────────────────────────────
    started_at   = models.DateTimeField(auto_now_add=True)
    ended_at     = models.DateTimeField(null=True, blank=True)
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'call_sessions'
        verbose_name = 'Call Session'
        verbose_name_plural = 'Call Sessions'
        ordering = ['-started_at']
        indexes = [
            models.Index(fields=['user', '-started_at']),
            models.Index(fields=['status']),
            models.Index(fields=['content_deleted']),
            models.Index(fields=['caller_number_hash']),
            models.Index(fields=['scam_detected_by_ai']),
        ]

    def __str__(self):
        return (
            f'Session {str(self.id)[:8]} | '
            f'{self.status} | risk {self.current_risk_score}'
        )

    def get_duration_display(self):
        if not self.call_duration_seconds:
            return 'Unknown'
        m, s = divmod(self.call_duration_seconds, 60)
        return f'{m}m {s}s'

    def update_risk(self, new_risk_score, confidence=0.0, new_transcript_chunk='', patterns=None):
        """
        Update risk tracking during an active session.
        Called after every audio chunk is analyzed.
        
        Args:
            new_risk_score: Risk score from ML model (0-100)
            confidence: ML model confidence (0.0-1.0)
            new_transcript_chunk: New text to append to full_transcript
            patterns: List of detected patterns
        """
        # Append to cumulative transcript
        if new_transcript_chunk:
            if self.full_transcript:
                self.full_transcript += " " + new_transcript_chunk
            else:
                self.full_transcript = new_transcript_chunk
        
        # Update risk scores
        self.current_risk_score = new_risk_score
        self.ml_confidence = confidence

        if new_risk_score > self.peak_risk_score:
            self.peak_risk_score = new_risk_score

        # Track patterns
        if patterns:
            for pattern in patterns:
                if pattern not in self.detected_patterns:
                    self.detected_patterns.append(pattern)

        # Check if alert should trigger
        if new_risk_score >= self.alert_threshold and not self.alert_triggered:
            self.alert_triggered = True
            self.alert_count += 1

        # Mark as scam if threshold crossed
        if new_risk_score >= 70:
            self.scam_detected_by_ai = True

        # Increment chunks processed
        self.chunks_processed += 1

        self.save(update_fields=[
            'full_transcript', 'current_risk_score', 'ml_confidence',
            'peak_risk_score', 'alert_triggered', 'alert_count',
            'detected_patterns', 'scam_detected_by_ai', 'chunks_processed',
            'last_updated',
        ])

    def delete_content(self, reason='non_scam'):
        """
        Delete conversation content (full_transcript).
        Metadata (risk scores, duration, patterns) is kept.
        
        Args:
            reason: Why content is being deleted (from DELETION_REASONS)
        """
        # Clear the transcript
        self.full_transcript = ''
        
        # Delete confirmed scam conversation if exists
        if hasattr(self, 'confirmed_scam_conversation'):
            self.confirmed_scam_conversation.delete()

        self.content_deleted    = True
        self.content_deleted_at = timezone.now()
        self.deletion_reason    = reason
        
        self.save(update_fields=[
            'full_transcript', 'content_deleted', 
            'content_deleted_at', 'deletion_reason',
        ])
        
        return True


class RiskAlert(models.Model):
    """
    Records every alert overlay shown to the user during a call.
    Stores metadata only – no transcript content.
    Retained after session ends for analytics and false-positive tracking.
    """

    ALERT_TYPES = [
        ('ml_detection',       'ML Model Detection'),
        ('pattern_detected',   'Scam Pattern Detected'),
        ('high_risk_threshold','High Risk Threshold Crossed'),
        ('combined_detection', 'Combined Signal Detection'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    session = models.ForeignKey(
        CallSession, on_delete=models.CASCADE, related_name='alerts',
    )

    alert_type             = models.CharField(max_length=30, choices=ALERT_TYPES)
    risk_score_at_alert    = models.IntegerField()
    confidence_at_alert    = models.FloatField(default=0.0)
    trigger_patterns       = models.JSONField(default=list)
    detected_scam_type     = models.CharField(max_length=50, blank=True)
    alert_message          = models.TextField()

    # User response
    user_dismissed  = models.BooleanField(default=False)
    user_ended_call = models.BooleanField(default=False)

    triggered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'risk_alerts'
        verbose_name = 'Risk Alert'
        verbose_name_plural = 'Risk Alerts'
        ordering = ['-triggered_at']

    def __str__(self):
        return (
            f'Alert: {self.alert_type} | '
            f'Risk: {self.risk_score_at_alert} | '
            f'Session: {str(self.session.id)[:8]}'
        )


class ConfirmedScamConversation(models.Model):
    """
    Stores a full conversation transcript.

    Created ONLY when ALL three conditions are met:
    ─────────────────────────────────────────────────────────────
    1. scam_detected_by_ai = True  (AI determined risk >= 70%)
    2. user_consented_storage = True (user agreed to store)
    3. PII has been redacted from the transcript before saving
    ─────────────────────────────────────────────────────────────

    Privacy guarantees:
    - PII redacted before storage
    - Auto-deleted after 90 days (enforced in save())
    - User can request deletion at any time
    - Used only to improve the ML model
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    session = models.OneToOneField(
        CallSession, on_delete=models.CASCADE,
        related_name='confirmed_scam_conversation',
    )

    # Caller – hash only
    caller_number_hash = models.CharField(max_length=64, db_index=True)

    # PII-redacted transcript
    full_transcript = models.TextField(
        help_text='Full conversation with PII redacted.',
    )

    # ML analysis results
    final_risk_score       = models.IntegerField(default=0)
    final_scam_type        = models.CharField(max_length=50, blank=True)
    confidence_score       = models.FloatField(default=0.0)
    all_patterns_detected  = models.JSONField(default=list)

    # Privacy processing flags
    pii_redacted      = models.BooleanField(default=False)
    voice_anonymized  = models.BooleanField(default=False)

    # Explicit consent (both must be True before this record is created)
    user_consented_storage  = models.BooleanField(default=False)
    user_consented_training = models.BooleanField(default=False)

    # ML training status
    used_for_training  = models.BooleanField(default=False)
    training_used_at   = models.DateTimeField(null=True, blank=True)

    # Mandatory auto-deletion
    auto_delete_at = models.DateTimeField(
        help_text='Hard deletion deadline. Set to now + 90 days automatically.',
    )

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'confirmed_scam_conversations'
        verbose_name = 'Confirmed Scam Conversation'
        verbose_name_plural = 'Confirmed Scam Conversations'
        ordering = ['-created_at']

    def __str__(self):
        return (
            f'Scam Conversation | '
            f'Risk: {self.final_risk_score} | '
            f'Type: {self.final_scam_type} | '
            f'Expires: {self.auto_delete_at.date() if self.auto_delete_at else "N/A"}'
        )

    def save(self, *args, **kwargs):
        """Always enforce 90-day auto-deletion."""
        if not self.auto_delete_at:
            from datetime import timedelta
            self.auto_delete_at = timezone.now() + timedelta(days=90)
        super().save(*args, **kwargs)