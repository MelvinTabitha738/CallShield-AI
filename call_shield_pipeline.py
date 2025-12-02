from whisper_stt import CallShieldSTT
from scam_detector import ScamCallDetector
import os

class CallShieldPipeline:
    def __init__(self):
        print("🛡️ Initializing Call Shield AI...")
        self.stt = CallShieldSTT()
        self.scam_detector = ScamCallDetector()
        self.scam_detector.train()
        print("✅ Pipeline ready")
    
    def analyze_call(self, audio_path):
        """Complete pipeline: Audio → Text → Scam Detection"""
        print(f"🎵 Analyzing: {audio_path}")
        
        # Step 1: Speech to Text
        transcription = self.stt.transcribe_audio(audio_path)
        
        if 'error' in transcription:
            return {'error': transcription['error']}
        
        # Step 2: Scam Detection
        scam_result = self.scam_detector.predict(transcription['text'])
        
        # Combine results
        result = {
            'audio_file': os.path.basename(audio_path),
            'transcription': transcription['text'],
            'language': transcription['language'],
            'is_scam': scam_result['is_scam'],
            'risk_level': scam_result['risk_level'],
            'confidence': scam_result['confidence'],
            'recommendation': 'BLOCK CALL' if scam_result['is_scam'] else 'ALLOW CALL'
        }
        
        return result
    
    def batch_analyze(self, audio_dir):
        """Analyze multiple audio files"""
        audio_files = [f for f in os.listdir(audio_dir) if f.endswith(('.wav', '.mp3'))]
        results = []
        
        for audio_file in audio_files:
            audio_path = os.path.join(audio_dir, audio_file)
            result = self.analyze_call(audio_path)
            results.append(result)
        
        return results
    
    def print_analysis(self, result):
        """Print formatted analysis result"""
        print("\n" + "="*50)
        print("🛡️ CALL SHIELD AI ANALYSIS")
        print("="*50)
        print(f"📁 File: {result['audio_file']}")
        print(f"🗣️ Language: {result['language']}")
        print(f"📝 Text: {result['transcription'][:100]}...")
        print(f"⚠️ Scam Risk: {result['risk_level']}")
        print(f"🎯 Confidence: {result['confidence']:.2f}")
        print(f"🚨 Action: {result['recommendation']}")
        print("="*50)

if __name__ == "__main__":
    # Initialize pipeline
    pipeline = CallShieldPipeline()
    
    # Test with podcast file
    test_file = "Friends from Hell ft. Rono _ 3 Truths No Lie Podcast [hXRFFA0wcNE].mp3"
    
    if os.path.exists(test_file):
        print("🧪 Testing with podcast file...")
        result = pipeline.analyze_call(test_file)
        pipeline.print_analysis(result)
    else:
        print("No test audio file found")
        print("Add audio files to test the complete pipeline")