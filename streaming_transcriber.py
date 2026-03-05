import whisper
import torch
import numpy as np
from io import BytesIO
import wave
import tempfile
import os

class StreamingTranscriber:
    def __init__(self, model_size='small.en'):  # Using English-optimized model
        self.device = 'cuda' if torch.cuda.is_available() else 'cpu'
        print(f"Loading Whisper {model_size} model on {self.device}...")
        self.model = whisper.load_model(model_size, device=self.device)
    
    def transcribe_chunk(self, audio_data):
        """Transcribe audio chunk with optimized settings for English"""
        try:
            # Save to temp file for better processing
            with tempfile.NamedTemporaryFile(suffix='.webm', delete=False) as temp_file:
                temp_file.write(audio_data)
                temp_path = temp_file.name
            
            try:
                # Transcribe with optimized settings for accuracy
                result = self.model.transcribe(
                    temp_path,
                    language='en',
                    task='transcribe',
                    fp16=torch.cuda.is_available(),
                    temperature=0.0,  # More deterministic
                    compression_ratio_threshold=2.4,
                    logprob_threshold=-1.0,
                    no_speech_threshold=0.6,
                    condition_on_previous_text=True,
                    initial_prompt="This is a phone call conversation about banking, shopping, or services.",
                    word_timestamps=False
                )
                return result['text'].strip()
            finally:
                # Clean up temp file
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                    
        except Exception as e:
            print(f"Transcription error: {e}")
            return ""
