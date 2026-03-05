from flask import Flask, render_template, request, jsonify
import torch
from transformers import RobertaTokenizer, RobertaForSequenceClassification
import os
from werkzeug.utils import secure_filename
from audio_transcriber import AudioTranscriber
from flask_socketio import SocketIO, emit
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = 'callshield-secret'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
socketio = SocketIO(app, cors_allowed_origins="*")
ALLOWED_EXTENSIONS = {'wav', 'mp3', 'ogg', 'm4a', 'flac'}

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

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

# Initialize models globally at startup
print("Initializing models...")
classifier = None
transcriber = None

if os.path.exists('./spam_classifier_model'):
    print("Loading spam classifier...")
    classifier = SpamClassifier()
    print("Spam classifier loaded!")

print("Loading Whisper small model...")
transcriber = AudioTranscriber(model_size='small')
print("Whisper model loaded!")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if classifier is None:
        return jsonify({'error': 'Model not found. Train the model first.'}), 400
    
    data = request.get_json()
    text = data.get('text', '')
    
    if not text:
        return jsonify({'error': 'No text provided'}), 400
    
    result = classifier.predict(text)
    return jsonify(result)

@app.route('/analyze-audio', methods=['POST'])
def analyze_audio():
    if 'audio' not in request.files:
        return jsonify({'error': 'No audio file provided'}), 400
    
    file = request.files['audio']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400
    
    if classifier is None:
        return jsonify({'error': 'Model not found. Train the model first.'}), 400
    
    # Save file
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    try:
        # Transcribe
        text = transcriber.transcribe(filepath)
        
        if not text.strip():
            return jsonify({'error': 'No speech detected'}), 400
        
        # Classify
        result = classifier.predict(text)
        result['transcribed_text'] = text
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)

# Real-time text analysis
@socketio.on('analyze_text')
def handle_realtime_text(data):
    text = data.get('text', '')
    if text and len(text) > 10 and classifier:
        result = classifier.predict(text)
        emit('analysis_result', result)

# Real-time microphone
from realtime_analyzer import RealtimeAnalyzer
analyzer = None

@socketio.on('start_microphone')
def handle_start_mic():
    global analyzer
    if not analyzer:
        analyzer = RealtimeAnalyzer()
    
    def callback(result):
        socketio.emit('mic_result', result)
    
    analyzer.start_recording(callback)
    emit('mic_status', {'status': 'recording'})

@socketio.on('stop_microphone')
def handle_stop_mic():
    if analyzer:
        analyzer.stop_recording()
    emit('mic_status', {'status': 'stopped'})

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
