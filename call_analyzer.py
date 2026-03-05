from audio_transcriber import AudioTranscriber
from predict import SpamClassifier

class CallAnalyzer:
    def __init__(self):
        print("Initializing Call Analyzer...")
        self.transcriber = AudioTranscriber(model_size='medium')
        self.spam_classifier = SpamClassifier()
    
    def analyze_audio(self, audio_path):
        # Step 1: Convert audio to text
        print("Transcribing audio...")
        text = self.transcriber.transcribe(audio_path)
        
        # Step 2: Classify text as spam or not
        print("Analyzing text for spam...")
        result = self.spam_classifier.predict(text)
        
        return {
            'transcribed_text': text,
            'is_spam': result['is_spam'],
            'label': result['label'],
            'confidence': result['confidence']
        }

if __name__ == '__main__':
    analyzer = CallAnalyzer()
    result = analyzer.analyze_audio('test_audio.wav')
    
    print("\n=== Call Analysis Result ===")
    print(f"Transcribed Text: {result['transcribed_text']}")
    print(f"Classification: {result['label'].upper()}")
    print(f"Confidence: {result['confidence']:.2%}")
    print(f"Is Spam: {result['is_spam']}")
