# backend_apps/real_time_detection/ml_integration.py
#
# ═══════════════════════════════════════════════════════════════════════
#  CALLSHIELD – ML MODEL INTEGRATION
# ═══════════════════════════════════════════════════════════════════════
#
#  This is the ONLY file in the project that talks to the ML model.
#  All other files call RiskCalculator.calculate_risk() which
#  delegates here.
#
#  WHEN YOUR ML TEAM DELIVERS THE MODEL
#  ──────────────────────────────────────
#  Search this file for the tag:
#
#       # ⚙️ INTEGRATION POINT
#
#  There are exactly 4 integration points:
#
#       POINT 1 – Model file path & loading method
#       POINT 2 – Model file structure (plain model vs dict)
#       POINT 3 – Input format  (what model.predict() expects)
#       POINT 4 – Output format (what model.predict() returns)
#
#  Everything else in this file should remain unchanged.
#
# ═══════════════════════════════════════════════════════════════════════

import os
import logging
from django.conf import settings

logger = logging.getLogger(__name__)


class MLModelInterface:
    """
    Wraps the trained scam-detection ML model.

    DETECTION PHILOSOPHY
    ────────────────────
    Detection is done exclusively by the ML model.
    No keyword lists. No hardcoded rules. No score constants.

    Why:
    • Keywords produce false positives – a real KRA call gets flagged.
    • Keywords miss sophisticated scammers who avoid trigger words.
    • The model understands context, tone, intent, and conversation flow.
    • The model supports English, Swahili, and Sheng.
    • The model improves over time as more training data is added.

    When the model file is absent the interface returns analyzed=False
    and risk_score=0. The Android app shows "Analysis unavailable –
    stay cautious." No guessing. No false alerts.
    """

    _model         = None
    _model_loaded  = False
    _model_version = None
    _model_meta    = {}

    # ───────────────────────────────────────────────────────────────────
    # ⚙️ INTEGRATION POINT 1 – MODEL FILE PATH AND LOADING METHOD
    # ───────────────────────────────────────────────────────────────────
    # Triggered once when Django starts (via apps.py → ready()).
    #
    # Steps for your ML team:
    #   1. Create the directory:  callshield_backend/ml_models/
    #   2. Place the model file inside that directory.
    #   3. Update `model_filename` to match the file name.
    #   4. Uncomment the loader that matches the file format
    #      (pickle / joblib / TensorFlow / PyTorch / HuggingFace / ONNX).
    #   5. Leave everything else in this method unchanged.
    # ───────────────────────────────────────────────────────────────────
    @classmethod
    def load_model(cls):
        """Load the trained model once when the server starts."""

        # ⚙️ INTEGRATION POINT 1a – update this filename
        model_filename = 'scam_detector.pkl'
        # ── other examples ──────────────────────────────────────────
        # model_filename = 'scam_detector.joblib'
        # model_filename = 'scam_detector.h5'
        # model_filename = 'scam_detector.pt'
        # model_filename = 'scam_detector.onnx'

        model_path = os.path.join(settings.BASE_DIR, 'ml_models', model_filename)

        if not os.path.exists(model_path):
            logger.warning(
                '⚠️  ML model not found at: %s\n'
                '    Detection will return "unanalyzed" until the model is deployed.\n'
                '    Place the model file at the path above to enable detection.',
                model_path,
            )
            cls._model_loaded = False
            return

        try:
            # ⚙️ INTEGRATION POINT 1b – uncomment the loader for your format
            # Only ONE loader should be active at a time.

            # ── Option A: Pickle (.pkl) ──────────────────────────────
            import pickle
            with open(model_path, 'rb') as f:
                raw = pickle.load(f)

            # ── Option B: Joblib (.joblib) ───────────────────────────
            # import joblib
            # raw = joblib.load(model_path)

            # ── Option C: TensorFlow / Keras (.h5 or SavedModel dir) ─
            # import tensorflow as tf
            # raw = tf.keras.models.load_model(model_path)

            # ── Option D: PyTorch (.pt) ──────────────────────────────
            # import torch
            # raw = torch.load(model_path, map_location='cpu')

            # ── Option E: HuggingFace pipeline ───────────────────────
            # from transformers import pipeline
            # raw = pipeline('text-classification', model=model_path)

            # ── Option F: ONNX Runtime (.onnx) ───────────────────────
            # import onnxruntime as ort
            # raw = ort.InferenceSession(model_path)

            # ───────────────────────────────────────────────────────────
            # ⚙️ INTEGRATION POINT 2 – MODEL FILE STRUCTURE
            # ───────────────────────────────────────────────────────────
            # Tell us how your file is structured.
            #
            # Structure A – file contains ONLY the model object:
            #   cls._model         = raw
            #   cls._model_version = 'unknown'
            #   cls._model_meta    = {}
            #
            # Structure B – file contains a dict with model + metadata:
            #   {
            #     'model':               <trained model object>,
            #     'version':             '1.0.0',
            #     'trained_at':          '2024-02-15',
            #     'accuracy':            0.94,
            #     'supported_languages': ['en', 'sw', 'sheng'],
            #   }
            # ───────────────────────────────────────────────────────────
            if isinstance(raw, dict) and 'model' in raw:
                # Structure B
                cls._model         = raw['model']
                cls._model_version = raw.get('version', 'unknown')
                cls._model_meta    = {
                    'trained_at':          raw.get('trained_at', 'unknown'),
                    'accuracy':            raw.get('accuracy', 'unknown'),
                    'supported_languages': raw.get('supported_languages', ['en']),
                }
            else:
                # Structure A
                cls._model         = raw
                cls._model_version = 'unknown'
                cls._model_meta    = {}

            cls._model_loaded = True
            logger.info('✅ ML model loaded. Version: %s', cls._model_version)

        except Exception as exc:
            logger.error(
                '❌ ML model loading failed: %s\n'
                '   Detection will be unavailable until this is fixed.',
                exc,
            )
            cls._model_loaded = False

    # ───────────────────────────────────────────────────────────────────
    # ⚙️ INTEGRATION POINT 3 – INPUT FORMAT
    # ───────────────────────────────────────────────────────────────────
    # Converts our standard data into whatever structure
    # your model's predict() method expects.
    #
    # Common formats:
    #
    #   Format A – raw string:
    #       return full_transcript
    #
    #   Format B – dict with text only:
    #       return {'text': full_transcript}
    #
    #   Format C – dict with text + metadata (current default):
    #       return {
    #           'text':             full_transcript,
    #           'duration_seconds': metadata.get('duration_seconds', 0),
    #           'language':         metadata.get('language', 'en'),
    #       }
    #
    #   Format D – pre-tokenised tensors:
    #       tokens = your_tokenizer(full_transcript, return_tensors='pt')
    #       return tokens
    # ───────────────────────────────────────────────────────────────────
    @classmethod
    def _prepare_input(cls, full_transcript, metadata):
        """
        Build the input structure that model.predict() expects.

        ⚙️ INTEGRATION POINT 3 – replace the return value below
        with the format your model requires.
        """
        # ── Default (Format C) – update when model is provided ──────
        return {
            'text': full_transcript,
            'metadata': {
                'duration_seconds': metadata.get('duration_seconds', 0),
                'chunk_count':      metadata.get('chunk_count', 0),
                'language':         metadata.get('language', 'en'),
            },
        }

    # ───────────────────────────────────────────────────────────────────
    # ⚙️ INTEGRATION POINT 4 – OUTPUT FORMAT
    # ───────────────────────────────────────────────────────────────────
    # Converts your model's raw output into the standard dict
    # that the rest of CallShield uses.
    #
    # Common output formats:
    #
    #   Format A – label + confidence dict:
    #       {
    #           'label':      'SCAM',            # or 'SAFE'
    #           'confidence': 0.95,
    #           'scam_type':  'kra_impersonation',
    #           'patterns':   ['urgency', 'impersonation'],
    #       }
    #
    #   Format B – probability pair [safe_prob, scam_prob]:
    #       [0.05, 0.95]
    #
    #   Format C – detailed dict:
    #       {
    #           'is_scam':          True,
    #           'scam_probability': 0.95,
    #           'safe_probability': 0.05,
    #           'scam_type':        'mpesa_fraud',
    #           'detected_tactics': ['urgency', 'pin_request'],
    #           'confidence':       0.95,
    #       }
    #
    #   Format D – HuggingFace pipeline list:
    #       [{'label': 'SCAM', 'score': 0.95}]
    # ───────────────────────────────────────────────────────────────────
    @classmethod
    def _parse_prediction(cls, raw):
        """
        Parse the model's raw output into CallShield's standard dict.

        ⚙️ INTEGRATION POINT 4 – add or replace a branch below to
        match your model's output format.
        """

        # ── Format A / C: dict output ───────────────────────────────
        if isinstance(raw, dict):
            is_scam = (
                raw.get('label') == 'SCAM'
                or raw.get('is_scam', False)
            )
            confidence = float(
                raw.get('confidence')
                or raw.get('scam_probability', 0.0)
            )
            scam_type = raw.get('scam_type') or raw.get('type')
            patterns  = (
                raw.get('patterns')
                or raw.get('detected_tactics')
                or []
            )

        # ── Format D: HuggingFace pipeline list ─────────────────────
        elif (isinstance(raw, (list, tuple))
              and len(raw) > 0
              and isinstance(raw[0], dict)):
            top        = raw[0]
            is_scam    = top.get('label') == 'SCAM'
            confidence = float(top.get('score', 0.0))
            scam_type  = None
            patterns   = []

        # ── Format B: [safe_prob, scam_prob] ────────────────────────
        elif isinstance(raw, (list, tuple)) and len(raw) == 2:
            safe_prob, scam_prob = float(raw[0]), float(raw[1])
            is_scam    = scam_prob > 0.5
            confidence = scam_prob if is_scam else safe_prob
            scam_type  = None
            patterns   = []

        else:
            logger.warning('Unrecognised model output type: %s', type(raw))
            return cls._error_response('Unrecognised model output format.')

        # ── Derive risk score ────────────────────────────────────────
        # Scam  → risk proportional to confidence  (20–100)
        # Safe  → low risk capped at 15
        risk_score = int(confidence * 100) if is_scam else int((1.0 - confidence) * 15)
        risk_level = cls._risk_level(risk_score)

        # Alert when model is ≥ 70 % confident it is a scam
        should_alert  = is_scam and confidence >= 0.70
        alert_message = (
            cls._build_alert_message(confidence, scam_type, patterns)
            if should_alert else None
        )

        return {
            'analyzed':         True,
            'is_scam':          is_scam,
            'confidence':       confidence,
            'risk_score':       risk_score,
            'risk_level':       risk_level,
            'scam_type':        scam_type,
            'patterns_detected':patterns,
            'should_alert':     should_alert,
            'alert_message':    alert_message,
            'model_version':    cls._model_version,
            'error':            None,
        }

    # ───────────────────────────────────────────────────────────────────
    # PUBLIC API  (do not change)
    # ───────────────────────────────────────────────────────────────────

    @classmethod
    def is_ready(cls):
        """True if the model is loaded and ready to run inference."""
        return cls._model_loaded and cls._model is not None

    @classmethod
    def get_model_info(cls):
        """Return current model status for health-check endpoint."""
        return {
            'loaded':   cls._model_loaded,
            'version':  cls._model_version,
            'ready':    cls.is_ready(),
            'metadata': cls._model_meta,
        }

    @classmethod
    def analyze(cls, full_transcript, metadata=None):
        """
        Run the ML model on the full conversation transcript so far.

        Args:
            full_transcript (str): The complete conversation text.
            metadata (dict | None): Optional session context:
                {
                    'duration_seconds': int,
                    'chunk_count':      int,
                    'language':         str,   # 'en' / 'sw' / 'mixed'
                }

        Returns:
            dict with keys:
                analyzed         bool    – False when model not ready
                is_scam          bool|None
                confidence       float   – 0.0–1.0
                risk_score       int     – 0–100
                risk_level       str     – SAFE / LOW / MEDIUM / HIGH
                scam_type        str|None
                patterns_detected list
                should_alert     bool
                alert_message    str|None
                model_version    str|None
                error            str|None
        """
        if not cls.is_ready():
            return cls._not_ready_response()

        if not full_transcript or not full_transcript.strip():
            return cls._empty_response()

        try:
            model_input = cls._prepare_input(full_transcript, metadata or {})
            raw         = cls._model.predict(model_input)
            result      = cls._parse_prediction(raw)
            logger.info(
                'ML analysis complete: is_scam=%s confidence=%.2f risk=%d',
                result['is_scam'], result['confidence'], result['risk_score'],
            )
            return result

        except Exception as exc:
            logger.error('ML inference error: %s', exc, exc_info=True)
            return cls._error_response(str(exc))

    # ───────────────────────────────────────────────────────────────────
    # PRIVATE HELPERS  (do not change)
    # ───────────────────────────────────────────────────────────────────

    @classmethod
    def _risk_level(cls, score):
        if score >= 70: return 'HIGH'
        if score >= 40: return 'MEDIUM'
        if score >= 20: return 'LOW'
        return 'SAFE'

    @classmethod
    def _build_alert_message(cls, confidence, scam_type, patterns):
        """Build the overlay message shown on the user's phone."""
        certainty = (
            'Very likely' if confidence >= 0.90
            else 'Likely'   if confidence >= 0.75
            else 'Possibly'
        )

        # ⚙️ INTEGRATION POINT – update keys to match your model's
        #    scam_type strings if they differ from those below.
        labels = {
            'kra_impersonation':  'KRA / Government Impersonation',
            'mpesa_fraud':        'M-Pesa Fraud',
            'bank_impersonation': 'Bank Impersonation',
            'lottery_prize':      'Lottery / Prize Scam',
            'emergency_scam':     'Emergency / Family Scam',
            'investment_scam':    'Investment Fraud',
            'loan_scam':          'Loan Scam',
            'romance_scam':       'Romance Scam',
            'other':              'Phone Scam',
        }
        label   = labels.get(scam_type, 'Suspicious Activity')
        message = f'⚠️ {certainty} a {label}!'
        if patterns:
            message += f'\nDetected: {", ".join(patterns[:2])}'
        message += f'\nConfidence: {int(confidence * 100)}%'
        return message

    @classmethod
    def _not_ready_response(cls):
        return {
            'analyzed': False, 'is_scam': None, 'confidence': 0.0,
            'risk_score': 0, 'risk_level': 'UNKNOWN', 'scam_type': None,
            'patterns_detected': [], 'should_alert': False,
            'alert_message': None, 'model_version': None,
            'error': 'ML model not loaded. Detection unavailable.',
        }

    @classmethod
    def _empty_response(cls):
        return {
            'analyzed': False, 'is_scam': None, 'confidence': 0.0,
            'risk_score': 0, 'risk_level': 'UNKNOWN', 'scam_type': None,
            'patterns_detected': [], 'should_alert': False,
            'alert_message': None, 'model_version': cls._model_version,
            'error': 'Empty transcript – nothing to analyze.',
        }

    @classmethod
    def _error_response(cls, msg):
        return {
            'analyzed': False, 'is_scam': None, 'confidence': 0.0,
            'risk_score': 0, 'risk_level': 'UNKNOWN', 'scam_type': None,
            'patterns_detected': [], 'should_alert': False,
            'alert_message': None, 'model_version': cls._model_version,
            'error': msg,
        }


class RiskCalculator:
    """
    Thin wrapper that calls MLModelInterface and returns
    a clean risk dict to services.py and views.py.
    No logic lives here – everything is in MLModelInterface.
    """

    @classmethod
    def calculate_risk(cls, transcript, full_transcript=None, metadata=None):
        """
        Calculate the current risk score for the conversation.

        Args:
            transcript      (str): Most recent chunk text.
            full_transcript (str): Entire conversation so far (preferred).
            metadata       (dict): Optional session context.

        Returns:
            dict: Standardised risk result used by the rest of the system.
        """
        result = MLModelInterface.analyze(
            full_transcript=full_transcript or transcript,
            metadata=metadata or {},
        )

        return {
            # Core decision
            'risk_score':       result['risk_score'],
            'risk_level':       result['risk_level'],
            'should_alert':     result['should_alert'],
            # Detection detail
            'is_scam':          result['is_scam'],
            'confidence':       result['confidence'],
            'scam_type':        result['scam_type'],
            'patterns_detected':result['patterns_detected'],
            # Alert
            'alert_message':    result['alert_message'],
            # Model meta
            'ml_model_used':    result['analyzed'],
            'ml_confidence':    result['confidence'],
            'model_version':    result['model_version'],
            # Status
            'analyzed':         result['analyzed'],
            'error':            result['error'],
        }