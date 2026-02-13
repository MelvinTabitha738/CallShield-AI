from flask import Flask, render_template, request, jsonify
import torch
from transformers import RobertaTokenizer, RobertaForSequenceClassification
import os

app = Flask(__name__)

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

# Initialize classifier
classifier = None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    global classifier
    
    if classifier is None:
        if not os.path.exists('./spam_classifier_model'):
            return jsonify({'error': 'Model not found. Please train the model first.'}), 400
        classifier = SpamClassifier()
    
    data = request.get_json()
    text = data.get('text', '')
    
    if not text:
        return jsonify({'error': 'No text provided'}), 400
    
    result = classifier.predict(text)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
