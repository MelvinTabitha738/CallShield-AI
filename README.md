# CallShield-AI
An AI-powered call security assistant that detects and prevents scam calls in real-time.

## Features
- 🎤 **Audio-to-Text**: Whisper medium model for accurate speech transcription
- 🤖 **Spam Detection**: RoBERTa-based text classification
- 🌐 **Web Interface**: Easy-to-use Flask web app
- ⚡ **Real-time Analysis**: Fast processing pipeline

## Setup and Run

### 1. Install dependencies:
```bash
pip install -r requirements.txt
```

**Note**: You also need FFmpeg installed:
- **Windows**: Download from https://ffmpeg.org/download.html
- **Linux**: `sudo apt install ffmpeg`
- **Mac**: `brew install ffmpeg`

### 2. Train the spam detection model:
```bash
python train_model.py
```

### 3. Run the web app:
```bash
python app.py
```

### 4. Open browser:
Go to http://localhost:5000

## Usage

### Text Analysis
- Type or paste text in the text tab
- Click "Check Message"

### Audio Analysis
- Switch to Audio tab
- Upload audio file (WAV, MP3, OGG, M4A, FLAC)
- Click "Analyze Audio"
- System will transcribe and analyze for spam

## Command Line Usage

### Analyze audio file:
```bash
python call_analyzer.py
```

### Test transcription only:
```bash
python audio_transcriber.py
```

### Test spam detection only:
```bash
python predict.py
```
