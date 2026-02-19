# backend_apps/real_time_detection/services.py

import hashlib
import re
import logging
from django.utils import timezone
from .models import (
    CallSession,
    TranscriptChunk,
    RiskAlert,
    ConfirmedScamConversation,
)
from .ml_integration import RiskCalculator, MLModelInterface

logger = logging.getLogger(__name__)




class CallSessionService:
    """Manages the full lifecycle of a call protection session."""

    # start_session   

    @classmethod
    def start_session(cls, user, phone_number, device_id='', app_version=''):
        """Create a new active CallSession when the user taps the Shield button."""
        phone_hash = hashlib.sha256(phone_number.encode()).hexdigest()

        # Pre-call risk from scam database
        from backend_apps.scam_database.services import NumberLookupService
        lookup       = NumberLookupService.check_number(phone_number)
        initial_risk = lookup.get('risk_score', 0)

        session = CallSession.objects.create(
            user=user,
            caller_number_hash=phone_hash,
            status='active',
            initial_risk_score=initial_risk,
            current_risk_score=initial_risk,
            peak_risk_score=initial_risk,
            device_id=device_id,
            app_version=app_version,
        )

        logger.info(
            'Session started: %s | user: %s | initial_risk: %d',
            str(session.id)[:8], user.id, initial_risk,
        )
        return session
   
    # end_session -  with auto-reporting logic    

    @classmethod
    def end_session(
        cls,
        session_id,
        user,
        call_duration=None,
        user_confirmed_scam=None,
        user_feedback_notes='',
        user_consented_storage=False,
        user_consented_training=False,
    ):
        """
        End a session with AUTO-REPORTING for high-risk calls.

        NEW LOGIC:
        ──────────
        HIGH RISK (≥70):
            → Auto-report to scam database (always)
            → Store transcript ONLY if user explicitly consents
            → Future users get warned automatically ✅

        MEDIUM RISK (40-69):
            → Report ONLY if user confirms
            → No storage without consent

        LOW RISK (<40):
            → Delete immediately
            → No reporting
        """
        try:
            session = CallSession.objects.get(
                id=session_id, user=user, status='active',
            )
        except CallSession.DoesNotExist:
            return {'success': False, 'message': 'Session not found or already ended.'}

        # Persist final metadata
        session.status               = 'completed'
        session.ended_at             = timezone.now()
        session.call_duration_seconds = call_duration
        session.user_confirmed_scam  = user_confirmed_scam
        session.user_feedback_notes  = user_feedback_notes
        session.final_risk_score     = session.current_risk_score
        session.save()

        #AUTO-REPORTING LOGIC 
        
        if session.peak_risk_score >= 70:
            # HIGH RISK: Always report to protect future users
            cls._report_to_scam_database(session, user)
            
            # Store transcript ONLY if explicit consent given
            if user_consented_storage and user_consented_training:
                cls._store_confirmed_scam(session, user, user_consented_training)
                storage_action = 'auto_reported_and_stored'
            else:
                storage_action = 'auto_reported_transcript_deleted'
            
            # Delete raw chunks
            session.delete_content(reason='non_scam')
            auto_reported = True

        elif session.peak_risk_score >= 40:
            # MEDIUM RISK: Report only if user explicitly confirms
            if user_confirmed_scam:
                cls._report_to_scam_database(session, user)
                
                if user_consented_storage and user_consented_training:
                    cls._store_confirmed_scam(session, user, user_consented_training)
                    storage_action = 'user_confirmed_and_stored'
                else:
                    storage_action = 'user_confirmed_transcript_deleted'
            else:
                storage_action = 'deleted_medium_risk_unconfirmed'
            
            session.delete_content(reason='non_scam')
            auto_reported = False

        else:
            # LOW RISK: Just delete everything
            session.delete_content(reason='non_scam')
            storage_action = 'deleted_low_risk'
            auto_reported = False

        logger.info(
            'Session ended: %s | action: %s | peak_risk: %d | auto_reported: %s',
            str(session.id)[:8], storage_action, session.peak_risk_score, auto_reported,
        )

        return {
            'success':          True,
            'session_id':       str(session.id),
            'final_risk_score': session.final_risk_score,
            'peak_risk_score':  session.peak_risk_score,
            'call_duration':    call_duration,
            'alert_triggered':  session.alert_triggered,
            'patterns_detected':session.detected_patterns,
            'detected_scam_type':session.detected_scam_type,
            'storage_action':   storage_action,
            'auto_reported':    auto_reported,  # ← NEW
            'recommendation':   cls._recommendation(session, auto_reported),
            'privacy_notice':   cls._privacy_notice(storage_action, auto_reported),
        }

    
    # Private helpers 

    @classmethod
    def _store_confirmed_scam(cls, session, user, user_consented_training):
        """Store PII-redacted transcript for ML training."""
        chunks = TranscriptChunk.objects.filter(
            session=session
        ).order_by('chunk_number')

        if not chunks.exists():
            logger.warning('No chunks to store for session %s', str(session.id)[:8])
            return

        full_transcript = '\n'.join(
            f'[{c.speaker.upper()}]: {c.transcript_text}' for c in chunks
        )
        redacted = cls._redact_pii(full_transcript)

        ConfirmedScamConversation.objects.create(
            session=session,
            caller_number_hash=session.caller_number_hash,
            full_transcript=redacted,
            final_risk_score=session.final_risk_score,
            final_scam_type=session.detected_scam_type,
            confidence_score=session.ml_confidence,
            all_patterns_detected=session.detected_patterns,
            pii_redacted=True,
            user_consented_storage=True,
            user_consented_training=user_consented_training,
        )

    @classmethod
    def _report_to_scam_database(cls, session, user):
        """Create ScamIncident and update PhoneNumberActive."""
        from backend_apps.scam_database.models import ScamIncident, PhoneNumberActive
        from backend_apps.scam_database.services import RiskScoringService

        ScamIncident.objects.create(
            phone_number_hash=session.caller_number_hash,
            scam_type=session.detected_scam_type or 'other',
            severity=session.peak_risk_score,
            source='ai_detection',
            reported_by=user,
            verified_by_ai=True,
            confidence_score=session.ml_confidence,
        )

        active, is_new = PhoneNumberActive.objects.get_or_create(
            phone_number_hash=session.caller_number_hash,
            defaults={
                'risk_score':        50,
                'primary_scam_type': session.detected_scam_type or 'other',
                'report_count':      1,
                'last_incident_at':  timezone.now(),
            },
        )
        if not is_new:
            active.report_count     += 1
            active.last_incident_at  = timezone.now()
            active.save(update_fields=['report_count', 'last_incident_at'])

        RiskScoringService.update_risk_score(session.caller_number_hash)

    @staticmethod
    def _redact_pii(text):
        """Remove PII before storage."""
        # Kenyan phone numbers
        text = re.sub(
            r'\+?254\d{9}|\b07\d{8}\b|\b01\d{8}\b',
            '[PHONE_REDACTED]', text,
        )
        # National ID
        text = re.sub(r'\b\d{8}\b', '[ID_REDACTED]', text)
        # Monetary amounts
        text = re.sub(
            r'(KES|Ksh|kshs?)\s*[\d,]+',
            '[AMOUNT_REDACTED]', text, flags=re.IGNORECASE,
        )
        return text

    @staticmethod
    def _recommendation(session, auto_reported):
        """Generate recommendation message."""
        if auto_reported:
            return (
                'This number has been flagged automatically. '
                'Future users will receive a warning.'
            )
        if session.user_confirmed_scam:
            return 'Thank you for reporting! This number has been flagged.'
        if session.peak_risk_score >= 40:
            return 'Suspicious activity detected. Stay cautious.'
        return 'Call appears safe. Stay vigilant!'

    @staticmethod
    def _privacy_notice(action, auto_reported):
        """Generate privacy notice."""
        notices = {
            'auto_reported_and_stored': (
                '✅ Number auto-reported to protect others. '
                'Transcript stored for 90 days to improve AI. Thank you!'
            ),
            'auto_reported_transcript_deleted': (
                '✅ Number auto-reported to protect future users. '
                'Transcript deleted immediately.'
            ),
            'user_confirmed_and_stored': (
                '✅ Number reported. '
                'Transcript stored for 90 days to improve scam detection.'
            ),
            'user_confirmed_transcript_deleted': (
                '✅ Number reported. Transcript deleted.'
            ),
            'deleted_medium_risk_unconfirmed': (
                '✅ Transcript deleted. No data stored.'
            ),
            'deleted_low_risk': (
                '✅ Transcript deleted immediately. No data stored.'
            ),
        }
        return notices.get(
            action,
            '✅ Data handled per privacy policy.'
        )

class TranscriptProcessingService:
    """Handles real-time processing of transcript chunks during a call."""

    @classmethod
    def process_chunk(
        cls, session_id, user, transcript_text,
        chunk_number, timestamp, speaker='unknown',
    ):
        """Process chunk and flag for auto-reporting if needed."""
        try:
            session = CallSession.objects.get(
                id=session_id, user=user, status='active',
            )
        except CallSession.DoesNotExist:
            return {'success': False, 'message': 'Session not found or not active.'}

        # Build full transcript
        previous = TranscriptChunk.objects.filter(
            session=session
        ).order_by('chunk_number')

        full_transcript = (
            '\n'.join(c.transcript_text for c in previous)
            + '\n' + transcript_text
        )

        # Elapsed time
        try:
            elapsed = int((timestamp - session.started_at).total_seconds())
        except Exception:
            elapsed = 0

        # Run ML analysis
        risk_result = RiskCalculator.calculate_risk(
            transcript=transcript_text,
            full_transcript=full_transcript,
            metadata={
                'duration_seconds': elapsed,
                'chunk_count':      previous.count() + 1,
            },
        )

        # Persist chunk
        chunk = TranscriptChunk.objects.create(
            session=session,
            chunk_number=chunk_number,
            transcript_text=transcript_text,
            speaker=speaker,
            chunk_risk_score=risk_result['risk_score'],
            ml_analyzed=risk_result['ml_model_used'],
            ml_confidence=risk_result['ml_confidence'],
            timestamp=timestamp,
        )

        # Update session metadata
        session.update_risk(
            risk_result['risk_score'],
            confidence=risk_result['ml_confidence'],
        )
        session.chunks_processed += 1

        #  Flag for auto-reporting if high risk
        if risk_result['risk_score'] >= 70:
            session.auto_report_recommended = True

        if risk_result['patterns_detected']:
            merged = set(session.detected_patterns) | set(risk_result['patterns_detected'])
            session.detected_patterns = list(merged)

        if risk_result['scam_type'] and not session.detected_scam_type:
            session.detected_scam_type = risk_result['scam_type']

        session.save(update_fields=[
            'chunks_processed',
            'detected_patterns',
            'detected_scam_type',
            'auto_report_recommended',  # ← NEW
        ])

        # Create alert if needed
        if risk_result['should_alert']:
            cls._create_alert(session, risk_result)

        return {
            'success':        True,
            'session_id':     str(session.id),
            'chunk_number':   chunk_number,
            'current_risk':   risk_result['risk_score'],
            'risk_level':     risk_result['risk_level'],
            'should_alert':   risk_result['should_alert'],
            'alert_message':  risk_result['alert_message'],
            'patterns_detected': risk_result['patterns_detected'],
            'scam_type':      risk_result['scam_type'],
            'ml_confidence':  risk_result['ml_confidence'],
            'ml_model_used':  risk_result['ml_model_used'],
            'analyzed':       risk_result['analyzed'],
            'error':          risk_result['error'],
            
            #Tell Android this call will be auto-reported
            'auto_report_recommended': risk_result['risk_score'] >= 70,
            
            'privacy_notice': (
                '⚠️ Transcript is temporary and will be deleted when the call ends.'
            ),
        }

    @classmethod
    def _create_alert(cls, session, risk_result):
        """Persist RiskAlert."""
        if risk_result['risk_score'] < 40:
            return

        if risk_result['ml_model_used'] and risk_result['ml_confidence'] >= 0.70:
            alert_type = 'ml_detection'
        elif risk_result['patterns_detected']:
            alert_type = 'pattern_detected'
        else:
            alert_type = 'high_risk_threshold'

        RiskAlert.objects.create(
            session=session,
            alert_type=alert_type,
            risk_score_at_alert=risk_result['risk_score'],
            confidence_at_alert=risk_result['ml_confidence'],
            trigger_patterns=risk_result['patterns_detected'],
            detected_scam_type=risk_result['scam_type'] or '',
            alert_message=(
                risk_result['alert_message'] or '⚠️ Suspicious activity detected.'
            ),
        )
class PrivacyCleanupService:
    """
    Automated cleanup tasks that enforce the privacy policy.

    Schedule to run daily via cron or Celery beat:
        python manage.py run_privacy_cleanup

    Or add to crontab:
        0 2 * * * /path/to/venv/bin/python manage.py run_privacy_cleanup
    """

    @classmethod
    def delete_expired_conversations(cls):
        """Delete ConfirmedScamConversation records past their auto_delete_at date."""
        expired = ConfirmedScamConversation.objects.filter(
            auto_delete_at__lte=timezone.now()
        )
        count = expired.count()
        expired.delete()
        logger.info('Privacy cleanup: deleted %d expired conversations.', count)
        return count

    @classmethod
    def delete_orphaned_chunks(cls):
        """
        Safety net: delete any TranscriptChunks that remain attached to
        completed sessions (should already have been cleaned up by end_session).
        """
        orphaned = CallSession.objects.filter(
            status='completed', content_deleted=False,
        )
        count = 0
        for session in orphaned:
            count += session.transcript_chunks.count()
            session.delete_content(reason='auto_expired')
        logger.info('Privacy cleanup: cleaned %d orphaned chunks.', count)
        return count

    @classmethod
    def run_all_cleanup(cls):
        """Run all cleanup tasks and return a summary dict."""
        logger.info('Running full privacy cleanup…')
        return {
            'expired_conversations_deleted': cls.delete_expired_conversations(),
            'orphaned_chunks_deleted':       cls.delete_orphaned_chunks(),
        }