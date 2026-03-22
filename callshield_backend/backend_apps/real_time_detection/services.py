# backend_apps/real_time_detection/services.py

import hashlib
import re
import logging
from django.utils import timezone
from .models import (
    CallSession,
    RiskAlert,
    ConfirmedScamConversation,
)
from .ml_integration import MLModelInterface

logger = logging.getLogger(__name__)


class CallSessionService:
    """Manages the full lifecycle of a call protection session."""

    @classmethod
    def start_session(cls, user, phone_number, device_id='', app_version='', user_consented=True):
        """Create a new active CallSession when the user taps the Shield button."""
        # Use a placeholder hash for unknown/private callers
        safe_number = phone_number.strip() if phone_number else ''
        phone_hash = hashlib.sha256(safe_number.encode()).hexdigest() if safe_number else 'unknown'

        # Pre-call risk from scam database (skip for unknown callers)
        from backend_apps.scam_database.services import NumberLookupService
        lookup = NumberLookupService.check_number(safe_number) if safe_number else {}
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

    @classmethod
    def end_session(
        cls,
        session_id,
        user,
        call_duration=None,
        user_consented_storage=False,
        user_consented_training=False,
        user_feedback_notes='',
    ):
        """
        End a session with AI-BASED AUTO-DETECTION and privacy-aware storage.

        LOGIC:
        ──────────
        AI DETECTED SCAM (scam_detected_by_ai = True):
            → ALWAYS update scam database (no consent needed)
            → Store transcript ONLY if user_consented_storage = True
            → Delete transcript if user_consented_storage = False

        AI SAYS CLEAN (scam_detected_by_ai = False):
            → Don't update scam database
            → Store transcript ONLY if user_consented_storage = True
            → Delete transcript if user_consented_storage = False
        """
        try:
            session = CallSession.objects.get(
                id=session_id, user=user, status='active',
            )
        except CallSession.DoesNotExist:
            return {'success': False, 'message': 'Session not found or already ended.'}

        # Persist final metadata
        session.status = 'completed'
        session.ended_at = timezone.now()
        session.call_duration_seconds = call_duration
        session.user_consented_storage = user_consented_storage
        session.user_feedback_notes = user_feedback_notes
        session.final_risk_score = session.peak_risk_score
        session.save()

        # DECISION VARIABLES
        scam_detected = session.scam_detected_by_ai  # AI decides
        user_consents = user_consented_storage  # User decides storage
        scam_db_updated = False
        storage_action = ''

        # AUTO-REPORTING LOGIC (AI-based, no user input needed)
        if scam_detected:
            # AI says SCAM → Always report to database
            cls._report_to_scam_database(session, user)
            scam_db_updated = True

            # Storage based on user consent
            if user_consents:
                cls._store_confirmed_scam(session, user, user_consented_training)
                storage_action = 'scam_detected_stored'
            else:
                session.delete_content(reason='no_consent')
                storage_action = 'scam_detected_deleted'

        else:
            # AI says CLEAN
            if user_consents:
                # User wants to keep even clean calls (for analytics)
                storage_action = 'clean_call_stored'
                # Don't create ConfirmedScamConversation for clean calls
                # Just mark session as stored
            else:
                session.delete_content(reason='non_scam')
                storage_action = 'clean_call_deleted'

        logger.info(
            'Session ended: %s | scam_detected: %s | storage: %s | db_updated: %s',
            str(session.id)[:8], scam_detected, storage_action, scam_db_updated,
        )

        return {
            'success': True,
            'session_id': str(session.id),
            'scam_detected': scam_detected,  # AI decision
            'final_risk_score': session.final_risk_score,
            'peak_risk_score': session.peak_risk_score,
            'scam_type': session.detected_scam_type or None,
            'call_duration': call_duration,
            'alert_triggered': session.alert_triggered,
            'patterns_detected': session.detected_patterns,
            'storage_action': storage_action,
            'scam_db_updated': scam_db_updated,
            'recommendation': cls._recommendation(scam_detected, scam_db_updated),
            'privacy_notice': cls._privacy_notice(storage_action, scam_detected),
        }

    @classmethod
    def _store_confirmed_scam(cls, session, user, user_consented_training):
        """Store PII-redacted transcript for ML training."""
        if not session.full_transcript:
            logger.warning('No transcript to store for session %s', str(session.id)[:8])
            return

        redacted = cls._redact_pii(session.full_transcript)

        ConfirmedScamConversation.objects.create(
            session=session,
            caller_number_hash=session.caller_number_hash,
            full_transcript=redacted,
            final_risk_score=session.final_risk_score,
            final_scam_type=session.detected_scam_type or 'other',
            confidence_score=session.ml_confidence,
            all_patterns_detected=session.detected_patterns,
            pii_redacted=True,
            user_consented_storage=True,
            user_consented_training=user_consented_training,
        )
        logger.info('Stored redacted transcript for session %s', str(session.id)[:8])

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
                'risk_score': session.peak_risk_score,
                'primary_scam_type': session.detected_scam_type or 'other',
                'report_count': 1,
                'last_incident_at': timezone.now(),
            },
        )
        if not is_new:
            active.report_count += 1
            active.last_incident_at = timezone.now()
            # Update risk if higher
            if session.peak_risk_score > active.risk_score:
                active.risk_score = session.peak_risk_score
            active.save(update_fields=['report_count', 'last_incident_at', 'risk_score'])

        RiskScoringService.update_risk_score(session.caller_number_hash)
        logger.info('Reported to scam DB: %s | risk: %d', str(session.id)[:8], session.peak_risk_score)

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
    def _recommendation(scam_detected, scam_db_updated):
        """Generate recommendation message."""
        if scam_detected and scam_db_updated:
            return 'Scam detected and reported automatically. Future users will be warned.'
        if scam_detected:
            return 'Scam detected. Stay safe!'
        return 'Call appears safe. Stay vigilant!'

    @staticmethod
    def _privacy_notice(action, scam_detected):
        """Generate privacy notice."""
        notices = {
            'scam_detected_stored': (
                'Scam reported to database. '
                'Transcript stored for 90 days to improve AI detection.'
            ),
            'scam_detected_deleted': (
                'Scam reported to database. '
                'Transcript deleted immediately per your choice.'
            ),
            'clean_call_stored': (
                'Transcript stored for 90 days to improve detection accuracy.'
            ),
            'clean_call_deleted': (
                'Transcript deleted immediately. No data stored.'
            ),
        }
        return notices.get(action, 'Data handled per privacy policy.')


class AudioProcessingService:
    """Handles real-time processing of audio chunks during a call."""

    @classmethod
    def process_audio_chunk(
        cls, session_id, user, audio_file,
        chunk_number, timestamp, caller_number="",
    ):
        """
        Process audio chunk: transcribe + detect scam in one AI call → update session.

        Args:
            session_id:   UUID of active session
            user:         Current user
            audio_file:   Binary audio file (UploadedFile)
            chunk_number: Sequential chunk number
            timestamp:    When chunk was captured

        Returns:
            dict with analysis results
        """
        try:
            session = CallSession.objects.get(
                id=session_id, user=user, status='active',
            )
        except CallSession.DoesNotExist:
            return {'success': False, 'message': 'Session not found or not active.'}

        # Read audio bytes
        try:
            audio_bytes = audio_file.read()
        except Exception as e:
            logger.error('Failed to read audio file: %s', str(e))
            return {'success': False, 'message': 'Failed to read audio file.'}

        # Single AI call: speech-to-text + scam detection
        try:
            result = MLModelInterface.transcribe_and_detect(
                audio_bytes=audio_bytes,
                chunk_number=chunk_number,
                session_id=str(session_id),
                caller_number=caller_number,
            )
            transcript_chunk = result.get('transcript', '')
            analysis = {
                'risk_score':   result.get('risk_score', 0),
                'confidence':   result.get('confidence', 0.0),
                'scam_type':    result.get('scam_type'),
                'patterns':     result.get('patterns', []),
                'should_alert': result.get('should_alert', False),
                'alert_message': result.get('alert_message'),
            }
        except Exception as e:
            logger.error('AI model error — chunk %d: %s', chunk_number, str(e))
            transcript_chunk = '[analysis failed]'
            analysis = {
                'risk_score': 0, 'confidence': 0.0, 'scam_type': None,
                'patterns': [], 'should_alert': False, 'alert_message': None,
            }

        # Update session risk + transcript
        session.update_risk(
            new_risk_score=analysis['risk_score'],
            confidence=analysis['confidence'],
            new_transcript_chunk=transcript_chunk,
            patterns=analysis['patterns'],
        )

        # Persist first detected scam type
        if analysis['scam_type'] and not session.detected_scam_type:
            session.detected_scam_type = analysis['scam_type']
            session.save(update_fields=['detected_scam_type'])

        # Trigger alert once when threshold crossed
        if analysis['should_alert']:
            cls._create_alert(session, analysis)

        risk_level = cls._get_risk_level(analysis['risk_score'])

        logger.info(
            'Chunk processed: session=%s chunk=%d risk=%d transcript="%s..."',
            str(session.id)[:8], chunk_number, analysis['risk_score'],
            transcript_chunk[:50],
        )

        return {
            'success':          True,
            'session_id':       str(session.id),
            'chunk_number':     chunk_number,
            'analyzed':         True,
            'current_risk':     analysis['risk_score'],
            'peak_risk':        session.peak_risk_score,
            'risk_level':       risk_level,
            'should_alert':     analysis['should_alert'],
            'alert_message':    analysis.get('alert_message'),
            'patterns_detected': analysis['patterns'],
            'scam_type':        analysis['scam_type'],
            'transcript_chunk': transcript_chunk,
            'ml_confidence':    analysis['confidence'],
            'ml_model_used':    True,
        }

    @classmethod
    def _create_alert(cls, session, analysis):
        """Create RiskAlert record when threshold crossed."""
        if session.alert_triggered:
            # Only create one alert per session
            return

        alert_message = analysis.get('alert_message') or '⚠️ Scam detected - hang up now!'

        RiskAlert.objects.create(
            session=session,
            alert_type='ml_detection',
            risk_score_at_alert=analysis['risk_score'],
            confidence_at_alert=analysis['confidence'],
            trigger_patterns=analysis['patterns'],
            detected_scam_type=analysis['scam_type'] or '',
            alert_message=alert_message,
        )

        logger.warning(
            'Alert triggered: session=%s risk=%d type=%s',
            str(session.id)[:8], analysis['risk_score'], analysis['scam_type'],
        )

    @staticmethod
    def _get_risk_level(risk_score):
        """Convert numeric risk to label."""
        if risk_score >= 80:
            return 'CRITICAL'
        elif risk_score >= 70:
            return 'HIGH'
        elif risk_score >= 50:
            return 'MODERATE'
        elif risk_score >= 30:
            return 'LOW'
        else:
            return 'SAFE'


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
    def delete_orphaned_sessions(cls):
        """
        Safety net: delete full_transcript from completed sessions
        that haven't been properly cleaned up.
        """
        orphaned = CallSession.objects.filter(
            status='completed',
            content_deleted=False,
        )
        count = 0
        for session in orphaned:
            if session.full_transcript:
                count += 1
            session.delete_content(reason='auto_expired')

        logger.info('Privacy cleanup: cleaned %d orphaned sessions.', count)
        return count

    @classmethod
    def run_all_cleanup(cls):
        """Run all cleanup tasks and return a summary dict."""
        logger.info('Running full privacy cleanup…')
        return {
            'expired_conversations_deleted': cls.delete_expired_conversations(),
            'orphaned_sessions_deleted': cls.delete_orphaned_sessions(),
        }