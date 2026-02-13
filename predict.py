import torch
from transformers import RobertaTokenizer, RobertaForSequenceClassification

class SpamClassifier:
    def __init__(self, model_path='./spam_classifier_model'):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.tokenizer = RobertaTokenizer.from_pretrained(model_path)
        self.model = RobertaForSequenceClassification.from_pretrained(model_path)
        self.model.to(self.device)
        self.model.eval()
    
    def predict(self, text):
        inputs = self.tokenizer(text, return_tensors='pt', truncation=True, padding=True, max_length=128)
        inputs = {key: val.to(self.device) for key, val in inputs.items()}
        
        with torch.no_grad():
            outputs = self.model(**inputs)
            prediction = torch.argmax(outputs.logits, dim=-1).item()
            probabilities = torch.softmax(outputs.logits, dim=-1)[0]
        
        label = 'spam' if prediction == 1 else 'ham'
        confidence = probabilities[prediction].item()
        
        return {
            'label': label,
            'confidence': confidence,
            'is_spam': prediction == 1
        }

# Example usage
if __name__ == '__main__':
    classifier = SpamClassifier()
    
    # Test examples
    test_texts = [
        "Safaricom bonus offer: get 10,000 KES instantly. Just lipa processing fee ya 250.",
        "Hi, I wanted to follow up on the report before today's meeting.",
        "Congratulations! Umeshinda 100,000 KES. To claim, tuma 1000 kwa hii number."
    ]
    
    for text in test_texts:
        result = classifier.predict(text)
        print(f"\nText: {text}")
        print(f"Prediction: {result['label']} (confidence: {result['confidence']:.2%})")
