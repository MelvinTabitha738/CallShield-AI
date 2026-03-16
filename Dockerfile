FROM python:3.10-slim

# System dependencies:
#   ffmpeg   — required by Whisper for audio decoding
#   portaudio19-dev + build tools — required by pyaudio (server mic, optional)
RUN apt-get update && apt-get install -y --no-install-recommends \
        ffmpeg \
        portaudio19-dev \
        gcc \
        g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install CPU-only PyTorch first (much smaller image than CUDA build)
RUN pip install --no-cache-dir \
        torch==2.1.0 \
        --index-url https://download.pytorch.org/whl/cpu

# Install remaining Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download the Whisper 'small' model during build so the first
# request isn't delayed by a 461 MB download at runtime.
RUN python -c "import whisper; whisper.load_model('small')"

# Copy application code and data files
COPY . .

# HF Spaces expects the app to listen on port 7860
EXPOSE 7860

CMD ["python", "app.py"]
