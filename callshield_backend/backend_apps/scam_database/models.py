# backend_apps/scam_database/models.py

import uuid
import hashlib
import math
from datetime import timedelta
from django.db import models
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator
from django.core.exceptions import ValidationError
from django.conf import settings


class ScamType(models.TextChoices):
    """Scam type categories"""
    KRA_IMPERSONATION = 'kra_impersonation', 'KRA Impersonation'
    MPESA_FRAUD = 'mpesa_fraud', 'M-Pesa Fraud'
    BANK_IMPERSONATION = 'bank_impersonation', 'Bank Impersonation'
    LOTTERY_PRIZE = 'lottery_prize', 'Lottery/Prize Scam'
    EMERGENCY_SCAM = 'emergency_scam', 'Emergency Scam'
    LOAN_SCAM = 'loan_scam', 'Loan Scam'
    INVESTMENT_SCAM = 'investment_scam', 'Investment Scam'
    ROMANCE_SCAM = 'romance_scam', 'Romance Scam'
    PHISHING = 'phishing', 'Phishing'
    OTHER = 'other', 'Other'


class PhoneNumberHashMixin(models.Model):
    """Mixin for hashing phone numbers"""
    
    class Meta:
        abstract = True
    
    @staticmethod
    def hash_phone_number(phone_number):
        """Hash a phone number using SHA-256"""
        return hashlib.sha256(phone_number.encode()).hexdigest()
    
    @staticmethod
    def get_display_hash(phone_hash):
        """Get truncated hash for display"""
        return f"{phone_hash[:8]}..." if phone_hash else "N/A"


class PhoneNumberActive(PhoneNumberHashMixin):
    """Active scam database (risk 30-100) - HASH ONLY"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Phone number (HASH ONLY - NO PLAINTEXT)
    phone_number_hash = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        help_text="SHA-256 hash of phone number (privacy-protected)"
    )
    
    # Risk scoring
    risk_score = models.IntegerField(
        default=50,
        validators=[MinValueValidator(30), MaxValueValidator(100)],
        help_text="Risk score: 30-100 (HIGH: 70-100, MEDIUM: 30-69)"
    )
    
    # Scam classification
    primary_scam_type = models.CharField(
        max_length=50,
        choices=ScamType.choices,
        default=ScamType.OTHER
    )
    
    # Statistics
    report_count = models.IntegerField(default=0)
    verified_reports = models.IntegerField(default=0)
    false_positive_count = models.IntegerField(default=0)
    
    # Timestamps
    first_reported_at = models.DateTimeField(auto_now_add=True)
    last_reported_at = models.DateTimeField(auto_now=True)
    last_incident_at = models.DateTimeField(null=True, blank=True)
    
    # Time decay tracking
    last_decay_calculated = models.DateTimeField(auto_now=True)
    decay_factor = models.FloatField(default=1.0)
    
    # Metadata
    total_victims_estimated = models.IntegerField(default=0)
    total_amount_lost_estimated = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        default=0,
        help_text="Estimated total amount lost in KES"
    )
    
    # Geographic data (anonymized)
    regions_reported = models.JSONField(default=list, blank=True)
    
    # Archive eligibility
    eligible_for_archive = models.BooleanField(default=False)
    days_since_last_incident = models.IntegerField(default=0)
    
    class Meta:
        db_table = 'phone_numbers_active'
        verbose_name = 'Active Scam Number'
        verbose_name_plural = 'Active Scam Numbers'
        ordering = ['-risk_score', '-last_reported_at']
        indexes = [
            models.Index(fields=['risk_score', '-last_reported_at']),
            models.Index(fields=['phone_number_hash']),
        ]
    
    def __str__(self):
        return f"Hash: {self.get_display_hash(self.phone_number_hash)} - Risk: {self.risk_score}"
    
    def get_risk_level(self):
        """Get risk level category"""
        if self.risk_score >= 70:
            return 'HIGH'
        elif self.risk_score >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    @classmethod
    def lookup_by_number(cls, phone_number):
        """Lookup number in database (hashes automatically)"""
        phone_hash = cls.hash_phone_number(phone_number)
        try:
            return cls.objects.get(phone_number_hash=phone_hash)
        except cls.DoesNotExist:
            return None
    
    @classmethod
    def create_from_number(cls, phone_number, **kwargs):
        """Create record from plaintext number (auto-hashes)"""
        phone_hash = cls.hash_phone_number(phone_number)
        return cls.objects.create(phone_number_hash=phone_hash, **kwargs)


class PhoneNumberArchived(PhoneNumberHashMixin):
    """Archived/recovered numbers (risk 0-14) - HASH ONLY"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Phone number (HASH ONLY - NO PLAINTEXT)
    phone_number_hash = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        help_text="SHA-256 hash of phone number (privacy-protected)"
    )
    
    # Risk score (0-14)
    risk_score = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(14)]
    )
    
    # Historical data
    historical_peak_risk = models.IntegerField(default=0)
    historical_report_count = models.IntegerField(default=0)
    historical_scam_type = models.CharField(
        max_length=50,
        choices=ScamType.choices,
        default=ScamType.OTHER
    )
    
    # Archive metadata
    archived_at = models.DateTimeField(auto_now_add=True)
    archived_from_active_at = models.DateTimeField(null=True, blank=True)
    days_in_active_db = models.IntegerField(default=0)
    
    # Recovery tracking
    recovery_start_date = models.DateTimeField(null=True, blank=True)
    normal_calls_since_archive = models.IntegerField(default=0)
    
    # Re-offense tracking
    reactivation_count = models.IntegerField(default=0)
    last_reactivation_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'phone_numbers_archived'
        verbose_name = 'Archived Number'
        verbose_name_plural = 'Archived Numbers'
        ordering = ['-archived_at']
        indexes = [
            models.Index(fields=['phone_number_hash']),
        ]
    
    def __str__(self):
        return f"Hash: {self.get_display_hash(self.phone_number_hash)} - Archived (Peak: {self.historical_peak_risk})"
    
    @classmethod
    def lookup_by_number(cls, phone_number):
        """Lookup number in archive (hashes automatically)"""
        phone_hash = cls.hash_phone_number(phone_number)
        try:
            return cls.objects.get(phone_number_hash=phone_hash)
        except cls.DoesNotExist:
            return None


class ScamIncident(PhoneNumberHashMixin):
    """Individual scam incident/event - HASH ONLY"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Related phone number (HASH ONLY - NO PLAINTEXT)
    phone_number_hash = models.CharField(
        max_length=64,
        db_index=True,
        help_text="SHA-256 hash of reported phone number"
    )
    
    # Incident details
    scam_type = models.CharField(
        max_length=50,
        choices=ScamType.choices,
        default=ScamType.OTHER
    )
    severity = models.IntegerField(
        default=50,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text="Severity score: 0-100"
    )
    
    # Source of incident
    source = models.CharField(
        max_length=20,
        choices=[
            ('user_report', 'User Report'),
            ('ai_detection', 'AI Detection'),
            ('manual_review', 'Manual Review'),
        ],
        default='user_report'
    )
    
    # Reporter
    reported_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reported_incidents'
    )
    
    # Evidence flags (updated by ScamEvidence model)
    has_recording = models.BooleanField(default=False)
    has_transcript = models.BooleanField(default=False)
    evidence_quality = models.CharField(
        max_length=20,
        choices=[
            ('none', 'No Evidence'),
            ('low', 'Low Quality'),
            ('medium', 'Medium Quality'),
            ('high', 'High Quality'),
        ],
        default='none'
    )
    
    # Verification
    verified = models.BooleanField(default=False)
    verified_by_ai = models.BooleanField(default=False)
    confidence_score = models.FloatField(
        default=0.5,
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)]
    )
    
    # Timestamps
    incident_datetime = models.DateTimeField(default=timezone.now)
    reported_at = models.DateTimeField(auto_now_add=True)
    
    # Additional metadata
    victim_lost_money = models.BooleanField(default=False)
    amount_lost = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True
    )
    
    # Geographic data (anonymized)
    region = models.CharField(max_length=100, blank=True)
    
    class Meta:
        db_table = 'scam_incidents'
        verbose_name = 'Scam Incident'
        verbose_name_plural = 'Scam Incidents'
        ordering = ['-incident_datetime']
        indexes = [
            models.Index(fields=['phone_number_hash', '-incident_datetime']),
            models.Index(fields=['scam_type', '-incident_datetime']),
        ]
    
    def __str__(self):
        return f"{self.scam_type} - Hash: {self.get_display_hash(self.phone_number_hash)} ({self.incident_datetime.date()})"
    
    @classmethod
    def create_from_number(cls, phone_number, **kwargs):
        """Create incident from plaintext number (auto-hashes)"""
        phone_hash = cls.hash_phone_number(phone_number)
        return cls.objects.create(phone_number_hash=phone_hash, **kwargs)
    
    @classmethod
    def get_incidents_for_number(cls, phone_number):
        """Get all incidents for a phone number"""
        phone_hash = cls.hash_phone_number(phone_number)
        return cls.objects.filter(phone_number_hash=phone_hash)


class ScamEvidence(models.Model):
    """Evidence attached to scam incident - AT LEAST ONE REQUIRED"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Related incident
    incident = models.ForeignKey(
        ScamIncident,
        on_delete=models.CASCADE,
        related_name='evidence'
    )
    
    # Text evidence (narrative) - ENCOURAGED
    narrative = models.TextField(
        blank=True,
        help_text="Detailed description of what happened (min 50 chars)"
    )
    narrative_language = models.CharField(
        max_length=10,
        default='en',
        choices=[('en', 'English'), ('sw', 'Swahili')]
    )
    
    # Audio evidence
    audio_file = models.FileField(
        upload_to='evidence/audio/%Y/%m/%d/',
        null=True,
        blank=True,
        help_text="Call recording (voice-anonymized)"
    )
    audio_duration_seconds = models.IntegerField(null=True, blank=True)
    audio_anonymized = models.BooleanField(default=False)
    
    # Transcript evidence
    transcript = models.TextField(
        blank=True,
        help_text="Conversation transcript (PII redacted)"
    )
    transcript_source = models.CharField(
        max_length=20,
        choices=[
            ('user_typed', 'User Typed'),
            ('auto_generated', 'Auto-Generated'),
        ],
        default='user_typed'
    )
    transcript_pii_redacted = models.BooleanField(default=False)
    
    # Screenshots
    screenshot_1 = models.ImageField(
        upload_to='evidence/screenshots/%Y/%m/%d/',
        null=True,
        blank=True
    )
    screenshot_2 = models.ImageField(
        upload_to='evidence/screenshots/%Y/%m/%d/',
        null=True,
        blank=True
    )
    screenshot_3 = models.ImageField(
        upload_to='evidence/screenshots/%Y/%m/%d/',
        null=True,
        blank=True
    )
    
    # Metadata
    call_duration_seconds = models.IntegerField(null=True, blank=True)
    user_confidence_level = models.IntegerField(
        default=5,
        validators=[MinValueValidator(1), MaxValueValidator(10)],
        help_text="User's confidence this is a scam (1-10)"
    )
    tags = models.JSONField(default=list, blank=True)
    
    # Verification tracking
    verified_by_moderator = models.BooleanField(default=False)
    moderator_notes = models.TextField(blank=True)
    
    # Timestamps
    submitted_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    
    # User consent (CRITICAL for privacy)
    user_consented_storage = models.BooleanField(
        default=False,
        help_text="User consented to storing this evidence"
    )
    user_consented_training = models.BooleanField(
        default=False,
        help_text="User consented to using for ML training"
    )
    
    # Auto-deletion
    auto_delete_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'scam_evidence'
        verbose_name = 'Scam Evidence'
        verbose_name_plural = 'Scam Evidence'
        ordering = ['-submitted_at']
    
    def __str__(self):
        return f"Evidence for {self.incident.scam_type} - {self.submitted_at.date()}"
    
    def clean(self):
        """Validate - AT LEAST ONE piece of evidence REQUIRED"""
        errors = {}
        
        # CRITICAL: Must provide at least ONE piece of evidence
        has_narrative = self.narrative and len(self.narrative.strip()) >= 50
        has_audio = bool(self.audio_file)
        has_transcript = self.transcript and len(self.transcript.strip()) >= 100
        has_screenshot = any([self.screenshot_1, self.screenshot_2, self.screenshot_3])
        
        has_any_evidence = any([has_narrative, has_audio, has_transcript, has_screenshot])
        
        if not has_any_evidence:
            raise ValidationError({
                '__all__': 'You must provide at least ONE of: Detailed narrative (50+ chars), audio recording, transcript (100+ chars), or screenshot'
            })
        
        # Narrative validation
        if self.narrative and len(self.narrative.strip()) < 50:
            errors['narrative'] = 'Narrative too short. Please provide at least 50 characters.'
        
        # Audio requires consent
        if self.audio_file and not self.user_consented_storage:
            errors['user_consented_storage'] = 'You must consent to storage when uploading audio'
        
        # Training requires storage
        if self.user_consented_training and not self.user_consented_storage:
            errors['user_consented_training'] = 'Cannot consent to training without storage consent'
        
        if errors:
            raise ValidationError(errors)
    
    def calculate_evidence_quality(self):
        """Auto-calculate evidence quality"""
        score = 0
        
        # Narrative
        if self.narrative and len(self.narrative.strip()) >= 50:
            score += 1
        
        # Audio (strongest evidence)
        if self.audio_file:
            score += 2
        
        # Transcript
        if self.transcript and len(self.transcript.strip()) >= 100:
            score += 1
        
        # Screenshots
        if self.screenshot_1 or self.screenshot_2 or self.screenshot_3:
            score += 1
        
        # User confidence
        if self.user_confidence_level >= 8:
            score += 1
        
        # Determine quality
        if score == 0:
            return 'none'
        elif score <= 2:
            return 'low'
        elif score <= 4:
            return 'medium'
        else:
            return 'high'
    
    def save(self, *args, **kwargs):
        """Auto-calculate quality and set auto-delete date"""
        
        # Calculate quality
        quality = self.calculate_evidence_quality()
        
        # Update incident
        if self.incident:
            self.incident.evidence_quality = quality
            if self.audio_file:
                self.incident.has_recording = True
            if self.transcript:
                self.incident.has_transcript = True
            self.incident.save()
        
        # Set auto-delete date (90 days)
        if self.user_consented_storage and not self.auto_delete_at:
            self.auto_delete_at = timezone.now() + timedelta(days=90)
        
        super().save(*args, **kwargs)


class ReporterCredibility(models.Model):
    """Track reporter accuracy to prevent abuse"""
    
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='reporter_credibility'
    )
    
    # Report statistics
    total_reports = models.IntegerField(default=0)
    verified_reports = models.IntegerField(default=0)
    false_reports = models.IntegerField(default=0)
    pending_reports = models.IntegerField(default=0)
    
    # Credibility score (0.0 to 1.0)
    credibility_score = models.FloatField(
        default=0.5,
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)]
    )
    
    # Tier level
    credibility_tier = models.CharField(
        max_length=20,
        choices=[
            ('new', 'New Reporter'),
            ('bronze', 'Bronze Reporter'),
            ('silver', 'Silver Reporter'),
            ('gold', 'Gold Reporter'),
            ('flagged', 'Flagged Suspicious')
        ],
        default='new'
    )
    
    # Timestamps
    first_report_at = models.DateTimeField(auto_now_add=True)
    last_report_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'reporter_credibility'
        verbose_name = 'Reporter Credibility'
        verbose_name_plural = 'Reporter Credibilities'
    
    def __str__(self):
        return f"{self.user.display_name} - {self.credibility_tier} ({self.credibility_score:.2f})"
    
    def calculate_credibility_score(self):
        """Calculate credibility based on accuracy"""
        if self.total_reports == 0:
            return 0.5
        
        score = 0.5
        verified_bonus = min(self.verified_reports * 0.1, 0.5)
        false_penalty = self.false_reports * 0.2
        final_score = score + verified_bonus - false_penalty
        
        return max(0.0, min(1.0, final_score))
    
    def update_tier(self):
        """Update credibility tier"""
        if self.false_reports >= 3:
            self.credibility_tier = 'flagged'
        elif self.verified_reports >= 25:
            self.credibility_tier = 'gold'
        elif self.verified_reports >= 10:
            self.credibility_tier = 'silver'
        elif self.verified_reports >= 3:
            self.credibility_tier = 'bronze'
        else:
            self.credibility_tier = 'new'
    
    def get_report_weight(self):
        """Get weight for risk calculation"""
        weights = {
            'new': 0.5,
            'bronze': 0.8,
            'silver': 1.0,
            'gold': 1.5,
            'flagged': 0.1
        }
        return weights.get(self.credibility_tier, 0.5)
    
    def can_report(self):
        """Check if user can submit reports"""
        if self.credibility_tier == 'flagged':
            return False, "Reporting privileges suspended due to false reports"
        
        # New users: 3 reports per day limit
        if self.credibility_tier == 'new':
            from datetime import timedelta
            recent_reports = ScamIncident.objects.filter(
                reported_by=self.user,
                reported_at__gte=timezone.now() - timedelta(days=1)
            ).count()
            
            if recent_reports >= 3:
                return False, "New reporters limited to 3 reports per day"
        
        return True, ""