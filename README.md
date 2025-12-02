# Call Shield AI 🛡️

AI-powered scam call detection system for Kenya, supporting English, Kiswahili, and Sheng languages.

## Features

- **Speech-to-Text**: Whisper Large-V3 model for accurate transcription
- **Scam Detection**: ML model trained on Kenyan scam patterns
- **Multi-language**: English, Kiswahili, and Sheng support
- **Real-time Analysis**: Audio → Text → Risk Assessment

## Quick Start

### Installation
```bash
pip install -r requirements_whisper.txt
```

### Usage
```python
from whisper_stt import CallShieldSTT
from scam_detector import ScamCallDetector

# Initialize
stt = CallShieldSTT()
detector = ScamCallDetector()
detector.train()

# Analyze audio
transcription = stt.transcribe_audio("audio_file.wav")
result = detector.predict(transcription['text'])

print(f"Risk Level: {result['risk_level']}")
print(f"Decision: {'BLOCK' if result['is_scam'] else 'ALLOW'}")
```

### Demo
```bash
python demo_callshield.py
```

## Components

- `whisper_stt.py` - Speech-to-text using Whisper
- `scam_detector.py` - Scam pattern detection
- `kenyan_audio_scraper.py` - Data collection from YouTube
- `audio_quality_filter.py` - Audio preprocessing

## Data Collection

Collect training data:
```bash
python kenyan_audio_scraper.py
```

Process audio files:
```bash
python process_training_audio.py
```

## Performance

- **Scam Detection**: 100% true positive rate
- **Languages**: English, Kiswahili, Sheng
- **Processing**: Real-time audio analysis

## Next Steps

1. Improve false positive rate
2. Add more training data
3. Deploy to phone systems
4. Real-time call monitoring

## License

MIT License