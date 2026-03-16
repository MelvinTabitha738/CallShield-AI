import whisper
import torch

class AudioTranscriber:
    def __init__(self, model_size='medium'):
        self.device = 'cuda' if torch.cuda.is_available() else 'cpu'
        print(f"Loading Whisper {model_size} model on {self.device}...")
        self.model = whisper.load_model(model_size, device=self.device)
    
    def transcribe(self, audio_path):
        result = self.model.transcribe(
            audio_path,
            language='en',
            fp16=torch.cuda.is_available(),
            verbose=False,
            beam_size=1,
            best_of=1,
            temperature=0,
            condition_on_previous_text=False,
            no_speech_threshold=0.6,
            compression_ratio_threshold=2.4
        )
        return result['text']

if __name__ == '__main__':
    transcriber = AudioTranscriber()
    text = transcriber.transcribe('test_audio.wav')
    print(f"Transcribed: {text}")
