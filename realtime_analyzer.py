import pyaudio
import wave
import threading
import queue
import time
import numpy as np
from audio_transcriber import AudioTranscriber
from predict import SpamClassifier

class RealtimeAnalyzer:
    def __init__(self):
        self.transcriber = AudioTranscriber(model_size='small')
        self.classifier = SpamClassifier()
        self.audio_queue = queue.Queue()
        self.is_recording = False
        
        # Audio settings
        self.CHUNK = 1024
        self.FORMAT = pyaudio.paInt16
        self.CHANNELS = 1
        self.RATE = 16000
        self.RECORD_SECONDS = 3  # Process every 3 seconds
        
    def start_recording(self, callback):
        self.is_recording = True
        self.callback = callback
        threading.Thread(target=self._record_audio, daemon=True).start()
        threading.Thread(target=self._process_audio, daemon=True).start()
    
    def stop_recording(self):
        self.is_recording = False
    
    def _record_audio(self):
        p = pyaudio.PyAudio()
        stream = p.open(format=self.FORMAT, channels=self.CHANNELS,
                       rate=self.RATE, input=True, frames_per_buffer=self.CHUNK)
        
        frames = []
        chunk_count = 0
        chunks_per_segment = int(self.RATE / self.CHUNK * self.RECORD_SECONDS)
        
        while self.is_recording:
            data = stream.read(self.CHUNK)
            frames.append(data)
            chunk_count += 1
            
            if chunk_count >= chunks_per_segment:
                # Save chunk to temp file
                filename = f'temp_chunk_{time.time()}.wav'
                wf = wave.open(filename, 'wb')
                wf.setnchannels(self.CHANNELS)
                wf.setsampwidth(p.get_sample_size(self.FORMAT))
                wf.setframerate(self.RATE)
                wf.writeframes(b''.join(frames))
                wf.close()
                
                self.audio_queue.put(filename)
                frames = []
                chunk_count = 0
        
        stream.stop_stream()
        stream.close()
        p.terminate()
    
    def _process_audio(self):
        import os
        while self.is_recording:
            try:
                filename = self.audio_queue.get(timeout=1)
                
                # Transcribe
                text = self.transcriber.transcribe(filename)
                
                if text.strip():
                    # Classify
                    result = self.classifier.predict(text)
                    result['transcribed_text'] = text
                    self.callback(result)
                
                # Cleanup
                if os.path.exists(filename):
                    os.remove(filename)
                    
            except queue.Empty:
                continue
