FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ffmpeg \
        gcc \
        g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install CPU-only PyTorch first
RUN pip install --no-cache-dir \
        torch==2.1.0 \
        --index-url https://download.pytorch.org/whl/cpu

# Install all dependencies (includes numpy) before whisper model download
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download Whisper small model
RUN python -c "import whisper; whisper.load_model('small')"

COPY . .

EXPOSE 7860

CMD ["python", "app.py"]
