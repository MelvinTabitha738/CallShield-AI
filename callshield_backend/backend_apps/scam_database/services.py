# backend_apps/scam_database/services.py

import math
from datetime import timedelta
from django.utils import timezone
from django.db.models import Count, Avg, Sum
from .models import (
    PhoneNumberActive,
    PhoneNumberArchived,
    ScamIncident,
    ScamEvidence,
    ReporterCredibility,
    ScamType
)


class RiskScoringService:
    """Risk scoring engine with time decay"""
    
    # Risk thresholds
    ACTIVE_MIN_RISK = 30
    ACTIVE_MAX_RISK = 100
    ARCHIVE_MAX_RISK = 14
    
    # Time decay (half-life model)
    HALF_LIFE_DAYS = 90
    
    # Scoring weights
    VERIFIED_REPORT_WEIGHT = 20
    TOTAL_REPORT_WEIGHT = 10
    SEVERITY_MAX_MODIFIER = 20
    EVIDENCE_QUALITY_BONUS = {
        'none': 0,
        'low': 10,
        'medium': 20,
        'high': 30
    }
    FALSE_POSITIVE_PENALTY = 5
    
    @classmethod
    def calculate_base_score(cls, report_count, verified_reports, false_positives=0):
        """Calculate base risk score"""
        base = (verified_reports * cls.VERIFIED_REPORT_WEIGHT) + \
               (report_count * cls.TOTAL_REPORT_WEIGHT)
        penalty = false_positives * cls.FALSE_POSITIVE_PENALTY
        return max(0, base - penalty)
    
    @classmethod
    def calculate_severity_modifier(cls, incidents):
        """Calculate severity modifier"""
        if not incidents.exists():
            return 0
        
        avg_severity = incidents.aggregate(Avg('severity'))['severity__avg'] or 50
        modifier = ((avg_severity - 50) / 50) * cls.SEVERITY_MAX_MODIFIER
        return modifier
    
    @classmethod
    def calculate_evidence_bonus(cls, incidents):
        """Calculate evidence quality bonus"""
        if not incidents.exists():
            return 0
        
        quality_counts = incidents.values('evidence_quality').annotate(count=Count('id'))
        max_bonus = 0
        
        for item in quality_counts:
            quality = item['evidence_quality']
            bonus = cls.EVIDENCE_QUALITY_BONUS.get(quality, 0)
            if bonus > max_bonus:
                max_bonus = bonus
        
        return max_bonus
    
    @classmethod
    def calculate_time_decay(cls, last_incident_date):
        """Calculate time decay using half-life model"""
        if not last_incident_date:
            return 1.0
        
        days_since = (timezone.now() - last_incident_date).days
        if days_since <= 0:
            return 1.0
        
        decay = math.pow(0.5, days_since / cls.HALF_LIFE_DAYS)
        return max(0.5, decay)
    
    @classmethod
    def calculate_risk_score(cls, phone_number_hash):
        """Calculate complete risk score"""
        try:
            active_record = PhoneNumberActive.objects.get(
                phone_number_hash=phone_number_hash
            )
        except PhoneNumberActive.DoesNotExist:
            return {
                'risk_score': 0,
                'base_score': 0,
                'severity_modifier': 0,
                'evidence_bonus': 0,
                'time_decay': 1.0,
                'final_score': 0
            }
        
        incidents = ScamIncident.objects.filter(phone_number_hash=phone_number_hash)
        
        base_score = cls.calculate_base_score(
            active_record.report_count,
            active_record.verified_reports,
            active_record.false_positive_count
        )
        
        severity_modifier = cls.calculate_severity_modifier(incidents)
        evidence_bonus = cls.calculate_evidence_bonus(incidents)
        time_decay = cls.calculate_time_decay(active_record.last_incident_at)
        
        score_before_decay = base_score + severity_modifier + evidence_bonus
        final_score = score_before_decay * time_decay
        
        if final_score < cls.ACTIVE_MIN_RISK:
            risk_score = int(final_score)
        else:
            risk_score = min(int(final_score), cls.ACTIVE_MAX_RISK)
        
        return {
            'risk_score': risk_score,
            'base_score': base_score,
            'severity_modifier': severity_modifier,
            'evidence_bonus': evidence_bonus,
            'time_decay': time_decay,
            'final_score': final_score
        }
    
    @classmethod
    def update_risk_score(cls, phone_number_hash):
        """Recalculate and update risk score"""
        try:
            active_record = PhoneNumberActive.objects.get(
                phone_number_hash=phone_number_hash
            )
        except PhoneNumberActive.DoesNotExist:
            return None
        
        score_data = cls.calculate_risk_score(phone_number_hash)
        
        active_record.risk_score = score_data['risk_score']
        active_record.decay_factor = score_data['time_decay']
        active_record.last_decay_calculated = timezone.now()
        
        if active_record.last_incident_at:
            active_record.days_since_last_incident = (
                timezone.now() - active_record.last_incident_at
            ).days
        
        if score_data['risk_score'] <= cls.ARCHIVE_MAX_RISK:
            active_record.eligible_for_archive = True
        else:
            active_record.eligible_for_archive = False
        
        active_record.save()
        return active_record


class NumberLookupService:
    """Number lookup in scam databases"""
    
    @classmethod
    def check_number(cls, phone_number):
        """Check if number is in active or archived database"""
        phone_hash = PhoneNumberActive.hash_phone_number(phone_number)
        
        # Check active
        active_record = PhoneNumberActive.lookup_by_number(phone_number)
        if active_record:
            return {
                'status': 'active',
                'risk_score': active_record.risk_score,
                'risk_level': active_record.get_risk_level(),
                'scam_type': active_record.primary_scam_type,
                'report_count': active_record.report_count,
                'verified_reports': active_record.verified_reports,
                'last_reported': active_record.last_reported_at,
                'should_warn': True
            }
        
        # Check archived
        archived_record = PhoneNumberArchived.lookup_by_number(phone_number)
        if archived_record:
            return {
                'status': 'archived',
                'risk_score': archived_record.risk_score,
                'risk_level': 'RECOVERED',
                'scam_type': archived_record.historical_scam_type,
                'report_count': archived_record.historical_report_count,
                'verified_reports': 0,
                'last_reported': archived_record.archived_at,
                'should_warn': False
            }
        
        # Clean
        return {
            'status': 'clean',
            'risk_score': 0,
            'risk_level': 'UNKNOWN',
            'scam_type': None,
            'report_count': 0,
            'verified_reports': 0,
            'last_reported': None,
            'should_warn': False
        }


class ReportService:
    """Handle scam report submissions with evidence"""
    
    @classmethod
    def submit_report(cls, phone_number, scam_type, severity, reported_by,
                     narrative='', audio_file=None, transcript='',
                     screenshot_1=None, screenshot_2=None, screenshot_3=None,
                     call_duration=None, user_confidence=5, tags=None,
                     amount_lost=None, region=None,
                     user_consented_storage=False, user_consented_training=False):
        """
        Submit comprehensive scam report with evidence
        
        Evidence requirement: AT LEAST ONE of narrative/audio/screenshot/transcript
        """
        phone_hash = PhoneNumberActive.hash_phone_number(phone_number)
        
        # Get or create reporter credibility
        credibility, _ = ReporterCredibility.objects.get_or_create(
            user=reported_by
        )
        
        # Check if reporter can report
        can_report, reason = credibility.can_report()
        if not can_report:
            return {
                'success': False,
                'message': reason,
                'incident': None,
                'evidence': None,
                'active_record': None
            }
        
        # Create incident
        incident = ScamIncident.create_from_number(
            phone_number=phone_number,
            scam_type=scam_type,
            severity=severity,
            source='user_report',
            reported_by=reported_by,
            amount_lost=amount_lost,
            region=region
        )
        
        # Create evidence
        evidence = ScamEvidence.objects.create(
            incident=incident,
            narrative=narrative,
            audio_file=audio_file,
            transcript=transcript,
            screenshot_1=screenshot_1,
            screenshot_2=screenshot_2,
            screenshot_3=screenshot_3,
            call_duration_seconds=call_duration,
            user_confidence_level=user_confidence,
            tags=tags or [],
            user_consented_storage=user_consented_storage,
            user_consented_training=user_consented_training
        )
        
        # Get or create active record
        active_record, is_new = PhoneNumberActive.objects.get_or_create(
            phone_number_hash=phone_hash,
            defaults={
                'risk_score': RiskScoringService.ACTIVE_MIN_RISK,
                'primary_scam_type': scam_type,
                'report_count': 1,
                'verified_reports': 0,
                'last_incident_at': timezone.now()
            }
        )
        
        if not is_new:
            active_record.report_count += 1
            active_record.last_incident_at = timezone.now()
            if severity > 70:
                active_record.primary_scam_type = scam_type
            active_record.save()
        
        # Update reporter credibility
        credibility.total_reports += 1
        credibility.pending_reports += 1
        credibility.last_report_at = timezone.now()
        credibility.save()
        
        # Recalculate risk score
        RiskScoringService.update_risk_score(phone_hash)
        
        # Refresh
        active_record.refresh_from_db()
        
        return {
            'success': True,
            'message': 'Report submitted successfully',
            'incident': incident,
            'evidence': evidence,
            'active_record': active_record,
            'is_new_number': is_new
        }