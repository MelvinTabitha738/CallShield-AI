# backend_apps/real_time_detection/ml_integration.py
#
# ═══════════════════════════════════════════════════════════════════════
#  CALLSHIELD – REAL AI MODEL INTEGRATION
#  Deployed endpoint: POST https://carolinembithe-scam-detector.hf.space/analyze-audio
# ═══════════════════════════════════════════════════════════════════════

import logging
import requests
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Endpoint ──────────────────────────────────────────────────────────
AI_MODEL_URL = "https://carolinembithe-scam-detector.hf.space/analyze-audio"
REQUEST_TIMEOUT = 60  # seconds


class RealAIModel:
    """
    Calls the deployed HuggingFace scam-detection model.

    Single HTTP call combines:
        1. Speech-to-Text  → transcript
        2. Scam Detection  → risk_score, confidence, scam_type, patterns

    Request:
        POST /analyze-audio
        Content-Type: multipart/form-data
        Fields:
            audio        (file)  – audio chunk (WAV preferred, any format accepted)
            chunk_number (int)   – sequential 1-based index
            session_id   (str)   – UUID of active CallSession

    Response (all known field-name variants handled):
        {
            "transcript":  "...",
            "risk_score":  85,       # integer 0-100 OR float 0.0-1.0
            "confidence":  0.92,     # float 0.0-1.0
            "scam_type":   "kra_impersonation",
            "patterns":    ["urgency_language", ...],
            "should_alert": true
        }
    """

    def __init__(self):
        self.api_url = AI_MODEL_URL
        self.timeout = REQUEST_TIMEOUT
        logger.info("RealAIModel ready → %s", self.api_url)

    # ──────────────────────────────────────────────────────────────────
    # Primary entry-point
    # ──────────────────────────────────────────────────────────────────

    def transcribe_and_detect(
        self,
        audio_bytes: bytes,
        chunk_number: int,
        session_id: str = "",
        caller_number: str = "",
    ) -> Dict:
        """
        Send audio to the AI model; receive transcript + scam analysis.

        Returns a normalised dict with keys:
            transcript, risk_score, confidence, scam_type,
            patterns, should_alert, alert_message
        """
        try:
            data = {"chunk_number": chunk_number, "session_id": session_id}
            if caller_number:
                data["caller_number"] = caller_number
            response = requests.post(
                self.api_url,
                files={"audio": ("chunk.wav", audio_bytes, "audio/wav")},
                data=data,
                timeout=self.timeout,
            )
            response.raise_for_status()
            raw = response.json()
            logger.debug(
                "AI raw response chunk=%d: %s", chunk_number, str(raw)[:300]
            )
            return self._normalize(raw, chunk_number)

        except requests.exceptions.Timeout:
            logger.warning("AI model timeout — chunk %d", chunk_number)
            return self._fallback("timeout")
        except requests.exceptions.ConnectionError as exc:
            logger.error("AI model connection error — chunk %d: %s", chunk_number, exc)
            return self._fallback("connection_error")
        except requests.exceptions.HTTPError as exc:
            body = getattr(exc.response, "text", "")[:300]
            logger.error("AI model HTTP %s — chunk %d body: %s", exc, chunk_number, body)
            return self._fallback("http_error")
        except ValueError as exc:
            logger.error("AI model JSON parse error — chunk %d: %s", chunk_number, exc)
            return self._fallback("json_error")
        except Exception as exc:
            logger.error("Unexpected AI model error — chunk %d: %s", chunk_number, exc)
            return self._fallback("unknown_error")

    # Compatibility shim used by services.py
    def transcribe_audio(self, audio_bytes: bytes, chunk_number: int) -> str:
        """Return only the transcript portion (used by legacy code paths)."""
        return self.transcribe_and_detect(audio_bytes, chunk_number).get("transcript", "")

    # ──────────────────────────────────────────────────────────────────
    # Normalisation
    # ──────────────────────────────────────────────────────────────────

    def _normalize(self, data: Dict, chunk_number: int) -> Dict:
        """Map any plausible field-naming from the model to our standard schema."""

        # Transcript
        transcript: str = (
            data.get("transcribed_text")
            or data.get("transcript")
            or data.get("transcription")
            or data.get("text")
            or data.get("speech_text")
            or data.get("recognized_text")
            or ""
        )

        # Risk score → int 0-100
        raw_risk = (
            data.get("scam_risk")
            if data.get("scam_risk") is not None
            else data.get("risk_score")
            if data.get("risk_score") is not None
            else data.get("ml_score")
            if data.get("ml_score") is not None
            else data.get("risk")
            if data.get("risk") is not None
            else data.get("scam_probability")
            if data.get("scam_probability") is not None
            else data.get("probability")
            if data.get("probability") is not None
            else data.get("scam_score", 0)
        )
        try:
            raw_risk = float(raw_risk)
        except (TypeError, ValueError):
            raw_risk = 0.0
        risk_score = int(raw_risk * 100) if raw_risk <= 1.0 else int(raw_risk)
        risk_score = max(0, min(100, risk_score))

        # Confidence → float 0.0-1.0
        # model returns ml_score (0-100), convert to 0.0-1.0
        raw_conf = (
            data.get("confidence")
            if data.get("confidence") is not None
            else data.get("confidence_score")
            if data.get("confidence_score") is not None
            else data.get("ml_score")
            if data.get("ml_score") is not None
            else data.get("certainty", 0.5)
        )
        try:
            confidence = float(raw_conf)
        except (TypeError, ValueError):
            confidence = 0.5
        if confidence > 1.0:
            confidence /= 100.0
        confidence = round(max(0.0, min(1.0, confidence)), 2)

        # Scam type
        raw_type = (
            data.get("scam_type")
            or data.get("scam_category")
            or data.get("category")
            or data.get("label")
            or None
        )
        scam_type: Optional[str] = None
        if raw_type and str(raw_type).lower() not in ("none", "safe", "clean", "normal", ""):
            scam_type = str(raw_type).lower().replace(" ", "_")

        # Patterns
        raw_patterns = (
            data.get("matched_flags")
            or data.get("patterns")
            or data.get("detected_patterns")
            or data.get("features")
            or data.get("indicators")
            or []
        )
        patterns: List[str] = (
            [str(p) for p in raw_patterns] if isinstance(raw_patterns, list) else []
        )

        # Should alert — alertable threshold is 60 %
        raw_alert = (
            data.get("is_spam")
            if data.get("is_spam") is not None
            else data.get("should_alert")
            if data.get("should_alert") is not None
            else data.get("is_scam")
        )
        should_alert = bool(raw_alert) if raw_alert is not None else risk_score >= 60

        alert_message = (
            self._alert_message(scam_type, risk_score) if should_alert else None
        )

        logger.info(
            "AI analysis — chunk=%d risk=%d type=%s patterns=%d transcript_len=%d",
            chunk_number, risk_score, scam_type, len(patterns), len(transcript),
        )

        return {
            "transcript": transcript,
            "risk_score": risk_score,
            "confidence": confidence,
            "scam_type": scam_type,
            "patterns": patterns,
            "should_alert": should_alert,
            "alert_message": alert_message,
        }

    def _fallback(self, error_type: str) -> Dict:
        """Zero-risk safe response when the model cannot be reached."""
        return {
            "transcript": "",
            "risk_score": 0,
            "confidence": 0.0,
            "scam_type": None,
            "patterns": [],
            "should_alert": False,
            "alert_message": None,
            "error": error_type,
        }

    def _alert_message(self, scam_type: Optional[str], risk_score: int) -> str:
        messages = {
            "kra_impersonation": "SCAM ALERT: KRA Impersonation - Hang up now!",
            "mpesa_fraud": "SCAM ALERT: M-Pesa Fraud - Do NOT send money!",
            "bank_impersonation": "SCAM ALERT: Bank Impersonation - Do NOT share your PIN!",
            "lottery_prize": "SCAM ALERT: Fake Prize Scam - Hang up immediately!",
            "emergency_scam": "SCAM ALERT: Emergency Scam - Verify with family first!",
            "loan_scam": "SCAM ALERT: Loan Scam - Do NOT share personal info!",
        }
        if scam_type and scam_type in messages:
            return messages[scam_type]
        if risk_score >= 80:
            return "CRITICAL: High-risk scam detected - End call immediately!"
        return "WARNING: Suspicious call detected - Be very cautious!"

    def is_ready(self) -> bool:
        """Lightweight reachability check (does not analyse audio)."""
        try:
            base = self.api_url.rsplit("/", 1)[0]
            resp = requests.head(base, timeout=5)
            return resp.status_code < 500
        except Exception:
            return True  # Assume reachable; errors surface on real requests

    def get_model_info(self) -> Dict:
        return {
            "name": "CallShield Scam Detector (HuggingFace)",
            "version": "1.0.0",
            "type": "deployed_api",
            "endpoint": self.api_url,
            "speech_to_text": "integrated",
            "scam_detection": "active",
            "status": "production",
            "ready": True,
        }


# ──────────────────────────────────────────────────────────────────────
# Singleton facade — used by AudioProcessingService and analytics
# ──────────────────────────────────────────────────────────────────────

class MLModelInterface:
    """
    Singleton wrapper around RealAIModel.

    Keeps one instance alive for the Django process so connection-pool
    resources are shared across all requests.

    Used by:
        • AudioProcessingService  (real-time chunk analysis)
        • AdminAnalyticsService   (get_model_info for admin dashboard)
    """

    _model: Optional[RealAIModel] = None

    @classmethod
    def _get(cls) -> RealAIModel:
        if cls._model is None:
            cls._model = RealAIModel()
        return cls._model

    @classmethod
    def transcribe_and_detect(
        cls,
        audio_bytes: bytes,
        chunk_number: int,
        session_id: str = "",
        caller_number: str = "",
    ) -> Dict:
        return cls._get().transcribe_and_detect(audio_bytes, chunk_number, session_id, caller_number)

    @classmethod
    def get_model_info(cls) -> Dict:
        """Called by AdminAnalyticsService → populate admin dashboard."""
        model = cls._get()
        info = model.get_model_info()
        info["ready"] = model.is_ready()
        return info

    # Legacy method expected by analytics/services.py AdminAnalyticsService
    @classmethod
    def is_ready(cls) -> bool:
        return cls._get().is_ready()


# ──────────────────────────────────────────────────────────────────────
# RiskCalculator (kept for any code that calls calculate_risk directly)
# ──────────────────────────────────────────────────────────────────────

class RiskCalculator:
    """
    Text-only fallback risk calculator.

    AudioProcessingService uses the full audio pipeline (transcribe_and_detect).
    This class is retained for any analytics or testing code that works with
    already-transcribed text.
    """

    @classmethod
    def calculate_risk(cls, transcript: str, full_transcript: str = "", metadata: dict = None) -> Dict:
        """Analyse a text transcript and return a risk dict."""
        text = (full_transcript or transcript or "").lower()
        if not text.strip():
            return cls._empty()

        scam_keyword_map = {
            "kra_impersonation": ["kra", "tax", "kenya revenue", "tax compliance", "revenue authority"],
            "mpesa_fraud": ["mpesa", "send money", "paybill", "till number", "lipa na"],
            "bank_impersonation": ["bank account", "atm", "pin", "account suspended", "blocked card"],
            "lottery_prize": ["winner", "prize", "lottery", "congratulations", "claim reward"],
            "emergency_scam": ["accident", "hospital", "emergency", "police custody", "bail"],
            "loan_scam": ["instant loan", "collateral", "processing fee", "loan approved"],
        }

        pattern_map = {
            "urgency_language": ["urgent", "immediately", "right now", "asap", "deadline"],
            "authority_impersonation": ["officer", "official", "government", "kra", "police", "detective"],
            "threatens_legal_action": ["arrest", "warrant", "court", "prosecute", "legal action"],
            "requests_money": ["send money", "pay", "transfer", "deposit", "top up"],
            "requests_otp": ["otp", "pin", "code", "verify", "confirmation code"],
        }

        detected_type = None
        keyword_hits = 0
        for stype, keywords in scam_keyword_map.items():
            hits = sum(1 for k in keywords if k in text)
            if hits > keyword_hits:
                keyword_hits = hits
                detected_type = stype

        detected_patterns = [
            p for p, words in pattern_map.items() if any(w in text for w in words)
        ]

        risk_score = min(keyword_hits * 15 + len(detected_patterns) * 8, 95)
        confidence = round(min(0.3 + risk_score / 150, 0.90), 2)
        should_alert = risk_score >= 60

        risk_level = (
            "CRITICAL" if risk_score >= 80
            else "HIGH" if risk_score >= 70
            else "MODERATE" if risk_score >= 50
            else "LOW" if risk_score >= 30
            else "SAFE"
        )

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "should_alert": should_alert,
            "is_scam": risk_score >= 60,
            "confidence": confidence,
            "scam_type": detected_type,
            "patterns_detected": detected_patterns,
            "alert_message": None,
            "ml_model_used": False,
            "ml_confidence": confidence,
            "model_version": "text_fallback",
            "analyzed": True,
            "error": None,
        }

    @staticmethod
    def _empty() -> Dict:
        return {
            "risk_score": 0, "risk_level": "SAFE", "should_alert": False,
            "is_scam": False, "confidence": 0.0, "scam_type": None,
            "patterns_detected": [], "alert_message": None,
            "ml_model_used": False, "ml_confidence": 0.0,
            "model_version": None, "analyzed": False,
            "error": "Empty transcript.",
        }
