import whisper
import os
from pathlib import Path

class CallShieldSTT:
    def __init__(self):
        print("Loading Whisper Large-V3...")
        self.model = whisper.load_model("base")  # Using base model to avoid download issues
        print("Whisper model loaded successfully")
    
    def transcribe_audio(self, audio_path):
        """Transcribe single audio file"""
        try:
            result = self.model.transcribe(audio_path)
            return {
                'text': result['text'].strip(),
                'language': result['language'],
                'confidence': result.get('avg_logprob', 0)
            }
        except Exception as e:
            return {'error': str(e)}
    
    def transcribe_chunks(self, chunks_dir="training_data/chunks"):
        """Transcribe all audio chunks"""
        if not os.path.exists(chunks_dir):
            print(f"❌ Directory not found: {chunks_dir}")
            return []
        
        audio_files = [f for f in os.listdir(chunks_dir) if f.endswith('.wav')]
        results = []
        
        print(f"🎵 Transcribing {len(audio_files)} audio chunks...")
        
        for i, audio_file in enumerate(audio_files):
            audio_path = os.path.join(chunks_dir, audio_file)
            result = self.transcribe_audio(audio_path)
            
            result['file'] = audio_file
            results.append(result)
            
            if i % 10 == 0:
                print(f"Progress: {i}/{len(audio_files)}")
        
        return results
    
    def save_transcriptions(self, results, output_file="whisper_transcriptions.csv"):
        """Save transcriptions to CSV"""
        import csv
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['audio_file', 'transcription', 'language', 'confidence'])
            
            for result in results:
                if 'error' not in result:
                    writer.writerow([
                        result['file'],
                        result['text'],
                        result['language'],
                        result['confidence']
                    ])
        
        print(f"💾 Saved transcriptions to {output_file}")

if __name__ == "__main__":
    # Initialize STT
    stt = CallShieldSTT()
    
    # Test with single file if available
    test_file = "Friends from Hell ft. Rono _ 3 Truths No Lie Podcast [hXRFFA0wcNE].mp3"
    if os.path.exists(test_file):
        print("🧪 Testing with podcast file...")
        result = stt.transcribe_audio(test_file)
        print(f"Sample transcription: {result['text'][:100]}...")
    
    # Transcribe chunks if they exist
    if os.path.exists("training_data/chunks"):
        results = stt.transcribe_chunks()
        if results:
            stt.save_transcriptions(results)