import whisper
import os
import shutil

def fix_whisper_model():
    """Fix corrupted Whisper model download"""
    
    # Clear Whisper cache
    cache_dir = os.path.expanduser("~/.cache/whisper")
    if os.path.exists(cache_dir):
        print("Clearing Whisper cache...")
        shutil.rmtree(cache_dir)
    
    # Try loading smaller model first
    print("Loading Whisper base model...")
    try:
        model = whisper.load_model("base")
        print("✅ Base model loaded successfully")
        return model
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

if __name__ == "__main__":
    model = fix_whisper_model()
    
    if model:
        # Test transcription
        test_file = "Friends from Hell ft. Rono _ 3 Truths No Lie Podcast [hXRFFA0wcNE].mp3"
        if os.path.exists(test_file):
            print("Testing transcription...")
            result = model.transcribe(test_file)
            print(f"Sample: {result['text'][:100]}...")