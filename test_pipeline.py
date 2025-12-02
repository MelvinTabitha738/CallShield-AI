from whisper_stt import CallShieldSTT
from scam_detector import ScamCallDetector
import os

print("Initializing Call Shield AI...")
stt = CallShieldSTT()
detector = ScamCallDetector()
detector.train()

# Test with podcast file
audio_file = "Friends from Hell ft. Rono _ 3 Truths No Lie Podcast [hXRFFA0wcNE].mp3"

if os.path.exists(audio_file):
    print("Analyzing audio file...")
    
    # Step 1: Transcribe
    transcription = stt.transcribe_audio(audio_file)
    print(f"Language: {transcription['language']}")
    print(f"Text sample: {transcription['text'][:200]}...")
    
    # Step 2: Detect scam
    scam_result = detector.predict(transcription['text'])
    
    print("\n" + "="*50)
    print("CALL SHIELD AI ANALYSIS")
    print("="*50)
    print(f"Audio: {audio_file}")
    print(f"Language: {transcription['language']}")
    print(f"Scam Risk: {scam_result['risk_level']}")
    print(f"Confidence: {scam_result['confidence']:.2f}")
    print(f"Recommendation: {'BLOCK CALL' if scam_result['is_scam'] else 'ALLOW CALL'}")
    print("="*50)
    
else:
    print("Audio file not found")
    
print("Call Shield AI test complete!")