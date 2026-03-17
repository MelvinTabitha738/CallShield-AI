FROM python:3.10-slim

# Install system dependencies as root
RUN apt-get update && apt-get install -y --no-install-recommends \
        ffmpeg \
        gcc \
        g++ \
    && rm -rf /var/lib/apt/lists/*

# HF Spaces requires UID 1000
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH \
    XDG_CACHE_HOME=/home/user/.cache

WORKDIR $HOME/app

# Install CPU-only PyTorch first (must be before whisper to avoid GPU torch being pulled in)
RUN pip install --no-cache-dir --user \
        torch==2.5.1 \
        --index-url https://download.pytorch.org/whl/cpu

# Install remaining dependencies
COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Pre-download Whisper base model so cold starts are instant
RUN python -c "import whisper; whisper.load_model('base')"

COPY --chown=user . .

EXPOSE 7860

CMD ["python", "app.py"]
