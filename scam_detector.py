import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import pandas as pd
import joblib

class ScamCallDetector:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.classifier = LogisticRegression()
        self.is_trained = False
        
        # Kenyan scam patterns
        self.scam_keywords = [
            'urgent', 'winner', 'lottery', 'prize', 'congratulations',
            'bank account', 'verify', 'suspended', 'expired',
            'click link', 'send money', 'transfer', 'fee required',
            'government', 'tax', 'penalty', 'arrest', 'legal action',
            'inheritance', 'beneficiary', 'million', 'dollars',
            'western union', 'mpesa', 'mobile money'
        ]
    
    def extract_features(self, text):
        """Extract scam indicators from text"""
        text_lower = text.lower()
        
        features = {
            'urgency_words': len([w for w in ['urgent', 'immediately', 'now', 'asap'] if w in text_lower]),
            'money_mentions': len(re.findall(r'\b\d+\s*(shilling|dollar|ksh|usd)\b', text_lower)),
            'phone_numbers': len(re.findall(r'\b\d{10,}\b', text)),
            'suspicious_requests': len([w for w in ['send', 'transfer', 'pay', 'deposit'] if w in text_lower]),
            'scam_keywords': sum([1 for keyword in self.scam_keywords if keyword in text_lower]),
            'text_length': len(text),
            'exclamation_marks': text.count('!'),
            'question_marks': text.count('?')
        }
        
        return features
    
    def create_training_data(self):
        """Create sample training data for scam detection"""
        scam_texts = [
            "Congratulations! You have won 1 million shillings. Send 500 KSH processing fee to claim your prize.",
            "Your bank account has been suspended. Call immediately to verify your details.",
            "Urgent! Government tax penalty. Pay 2000 shillings now or face arrest.",
            "You are selected as beneficiary of inheritance. Transfer fee required.",
            "Winner of lottery! Send mobile money to claim your prize now!"
        ]
        
        normal_texts = [
            "Hello, how are you doing today? Hope you are well.",
            "Can we meet for coffee tomorrow afternoon?",
            "The weather is really nice today, perfect for a walk.",
            "I'm calling to confirm our appointment next week.",
            "Thanks for helping me with the project yesterday."
        ]
        
        # Create DataFrame
        data = []
        for text in scam_texts:
            features = self.extract_features(text)
            features['text'] = text
            features['is_scam'] = 1
            data.append(features)
        
        for text in normal_texts:
            features = self.extract_features(text)
            features['text'] = text
            features['is_scam'] = 0
            data.append(features)
        
        return pd.DataFrame(data)
    
    def train(self, training_data=None):
        """Train the scam detector"""
        if training_data is None:
            training_data = self.create_training_data()
        
        # Prepare features
        feature_cols = ['urgency_words', 'money_mentions', 'phone_numbers', 
                       'suspicious_requests', 'scam_keywords', 'text_length',
                       'exclamation_marks', 'question_marks']
        
        X = training_data[feature_cols]
        y = training_data['is_scam']
        
        # Train classifier
        self.classifier.fit(X, y)
        self.is_trained = True
        
        print("Scam detector trained successfully")
        return self
    
    def predict(self, text):
        """Predict if text is a scam"""
        if not self.is_trained:
            print("⚠️ Model not trained. Training with sample data...")
            self.train()
        
        features = self.extract_features(text)
        feature_vector = [[
            features['urgency_words'], features['money_mentions'],
            features['phone_numbers'], features['suspicious_requests'],
            features['scam_keywords'], features['text_length'],
            features['exclamation_marks'], features['question_marks']
        ]]
        
        probability = self.classifier.predict_proba(feature_vector)[0][1]
        is_scam = probability > 0.5
        
        return {
            'is_scam': is_scam,
            'confidence': probability,
            'risk_level': 'HIGH' if probability > 0.7 else 'MEDIUM' if probability > 0.3 else 'LOW',
            'features': features
        }
    
    def save_model(self, filepath="scam_detector.pkl"):
        """Save trained model"""
        joblib.dump({
            'classifier': self.classifier,
            'vectorizer': self.vectorizer,
            'scam_keywords': self.scam_keywords
        }, filepath)
        print(f"💾 Model saved to {filepath}")

if __name__ == "__main__":
    # Initialize and train detector
    detector = ScamCallDetector()
    detector.train()
    
    # Test with sample texts
    test_texts = [
        "Congratulations! You won 500,000 KSH! Send 1000 processing fee now!",
        "Hi, can we meet for lunch tomorrow?",
        "Your account is suspended. Call immediately to verify details."
    ]
    
    print("\n🧪 Testing scam detection:")
    for text in test_texts:
        result = detector.predict(text)
        print(f"\nText: {text[:50]}...")
        print(f"Scam: {result['is_scam']} | Risk: {result['risk_level']} | Confidence: {result['confidence']:.2f}")
    
    # Save model
    detector.save_model()