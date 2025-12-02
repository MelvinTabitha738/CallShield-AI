from scam_detector import ScamCallDetector

print("CALL SHIELD AI - SCAM DETECTION DEMO")
print("="*50)

# Initialize scam detector
detector = ScamCallDetector()
detector.train()

# Test samples (simulating transcribed audio)
test_samples = [
    {
        'text': "Hello, congratulations! You have won 1 million shillings in our lottery. Send 500 KSH processing fee to claim your prize immediately!",
        'label': 'SCAM'
    },
    {
        'text': "Hi, this is John from the bank. Your account has been suspended due to suspicious activity. Please call back immediately to verify your details.",
        'label': 'SCAM'
    },
    {
        'text': "Hello, how are you doing today? I was wondering if we could meet for coffee tomorrow afternoon to discuss the project.",
        'label': 'NORMAL'
    },
    {
        'text': "Urgent! Government requires immediate payment of 2000 shillings tax penalty or you will face arrest. Pay now via mobile money.",
        'label': 'SCAM'
    },
    {
        'text': "Hi mom, just calling to check how you are doing. Hope you had a good day at work today.",
        'label': 'NORMAL'
    }
]

print("Testing scam detection on sample calls:")
print("-" * 50)

for i, sample in enumerate(test_samples, 1):
    result = detector.predict(sample['text'])
    
    print(f"\nSAMPLE {i} ({sample['label']}):")
    print(f"Text: {sample['text'][:60]}...")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"Decision: {'BLOCK CALL' if result['is_scam'] else 'ALLOW CALL'}")
    
    # Check if prediction matches expected
    correct = (result['is_scam'] and sample['label'] == 'SCAM') or (not result['is_scam'] and sample['label'] == 'NORMAL')
    print(f"Prediction: {'CORRECT' if correct else 'INCORRECT'}")

print("\n" + "="*50)
print("CALL SHIELD AI READY FOR DEPLOYMENT!")
print("Next steps:")
print("1. Add your audio files for transcription")
print("2. Integrate with phone system")
print("3. Set up real-time call monitoring")
print("="*50)