import wave
import threading
import queue
import numpy as np
import os
import tempfile

try:
    import pyaudio
    PYAUDIO_AVAILABLE = True
except ImportError:
    PYAUDIO_AVAILABLE = False

class RealtimeAnalyzer:
    def __init__(self, transcriber=None, classifier=None):
        if not PYAUDIO_AVAILABLE:
            raise RuntimeError("pyaudio is not available on this system. Server-side microphone recording is disabled.")
        # Accept injected models — no duplicate loading
        self.transcriber = transcriber
        self.classifier = classifier
        self.audio_queue = queue.Queue(maxsize=3)  # Don't pile up chunks
        self.is_recording = False

        self.CHUNK = 1024
        self.FORMAT = pyaudio.paInt16
        self.CHANNELS = 1
        self.RATE = 16000
        self.RECORD_SECONDS = 3       # 3s chunks — fast enough, enough audio for Whisper
        self.SILENCE_THRESHOLD = 300  # Lower = more sensitive to quiet speech

    def start_recording(self, callback):
        self.is_recording = True
        self.callback = callback
        threading.Thread(target=self._record_audio, daemon=True).start()
        threading.Thread(target=self._process_audio, daemon=True).start()

    def stop_recording(self):
        self.is_recording = False

    def _is_speech(self, audio_data):
        audio_array = np.frombuffer(audio_data, dtype=np.int16)
        return np.abs(audio_array).mean() > self.SILENCE_THRESHOLD

    def _record_audio(self):
        p = pyaudio.PyAudio()
        stream = p.open(format=self.FORMAT, channels=self.CHANNELS,
                        rate=self.RATE, input=True, frames_per_buffer=self.CHUNK)

        frames = []
        chunk_count = 0
        chunks_per_segment = int(self.RATE / self.CHUNK * self.RECORD_SECONDS)
        has_speech = False

        while self.is_recording:
            data = stream.read(self.CHUNK, exception_on_overflow=False)
            if self._is_speech(data):
                has_speech = True
            frames.append(data)
            chunk_count += 1

            if chunk_count >= chunks_per_segment:
                if has_speech and not self.audio_queue.full():
                    with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as tmp:
                        filename = tmp.name
                    wf = wave.open(filename, 'wb')
                    wf.setnchannels(self.CHANNELS)
                    wf.setsampwidth(p.get_sample_size(self.FORMAT))
                    wf.setframerate(self.RATE)
                    wf.writeframes(b''.join(frames))
                    wf.close()
                    self.audio_queue.put(filename)

                frames = []
                chunk_count = 0
                has_speech = False

        stream.stop_stream()
        stream.close()
        p.terminate()

    def _process_audio(self):
        while self.is_recording:
            try:
                filename = self.audio_queue.get(timeout=1)
                try:
                    text = self.transcriber.transcribe(filename)
                finally:
                    try: os.remove(filename)
                    except: pass

                if text.strip():
                    result = self.classifier.predict(text)
                    result['transcribed_text'] = text
                    self.callback(result)

            except queue.Empty:
                continue
            except Exception as e:
                print(f"Realtime processing error: {e}")
