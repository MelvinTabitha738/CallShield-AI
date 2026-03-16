from flask import Flask, render_template, request, jsonify
import torch
from transformers import RobertaTokenizer, RobertaForSequenceClassification
import os
from werkzeug.utils import secure_filename
from audio_transcriber import AudioTranscriber
from flask_socketio import SocketIO, emit
import threading
from company_verifier import CompanyVerifier
from pattern_analyzer import get_analyzer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'callshield-secret'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
ALLOWED_EXTENSIONS = {'wav', 'mp3', 'ogg', 'm4a', 'flac', 'webm', 'opus', 'mp4'}

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

class SpamClassifier:
    def __init__(self, model_path='./spam_classifier_model'):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.tokenizer = RobertaTokenizer.from_pretrained(model_path)
        self.model = RobertaForSequenceClassification.from_pretrained(model_path)
        self.model.to(self.device)
        self.model.eval()
        self.pattern_analyzer = get_analyzer()

    def predict(self, text):
        # ML score
        inputs = self.tokenizer(text, return_tensors='pt', truncation=True, padding=True, max_length=256)
        inputs = {key: val.to(self.device) for key, val in inputs.items()}

        with torch.no_grad():
            outputs = self.model(**inputs)
            probabilities = torch.softmax(outputs.logits, dim=-1)[0]

        ml_score = round(probabilities[1].item() * 100, 1)

        # Rule-based pattern score
        pattern_result = self.pattern_analyzer.analyze(text)
        pattern_score = pattern_result['pattern_score']

        # Hybrid scoring logic:
        # - Pattern rules are high-precision (Kenyan-specific keywords).
        #   When they fire, trust them.
        # - The ML model was trained on limited/generic data and tends to
        #   over-flag legitimate professional communications (loans, payslips,
        #   dividends) that mention money. When no patterns match, dampen the
        #   ML score significantly to avoid false positives.
        if pattern_score == 0:
            # No rule-based evidence found — cap ML contribution at 45%
            # so it can still flag borderline cases but won't alarm on
            # legitimate SACCO/bank/payroll messages
            final_score = round(min(ml_score * 0.5, 45.0), 1)
        elif pattern_score >= 40:
            # Strong pattern evidence — take the higher of the two
            final_score = round(max(ml_score, pattern_score), 1)
        else:
            # Weak pattern signal — blend, slightly discounting ML
            final_score = round(max(ml_score * 0.7, pattern_score), 1)

        return {
            'scam_risk': final_score,
            'is_spam': final_score >= 50.0,
            'ml_score': ml_score,
            'pattern_score': pattern_score,
            'matched_flags': pattern_result['matched_flags'],
            'scam_type': pattern_result['scam_type'],
        }

# Initialize models globally at startup
print("Initializing models...")
classifier = None
transcriber = None
verifier = None

if os.path.exists('./spam_classifier_model'):
    print("Loading spam classifier...")
    classifier = SpamClassifier()
    print("Spam classifier loaded!")

print("Loading Whisper small model...")
transcriber = AudioTranscriber()
print("Whisper model loaded!")

print("Loading company verifier...")
verifier = CompanyVerifier()
print("Company verifier loaded!")

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
    
    # Accept webm/opus from browser mic even without extension
    fname = file.filename or 'audio.webm'
    if not allowed_file(fname):
        # Try by content-type
        ct = file.content_type or ''
        if not any(x in ct for x in ['audio', 'video/webm']):
            return jsonify({'error': 'Invalid file type'}), 400
    
    if classifier is None:
        return jsonify({'error': 'Model not found. Train the model first.'}), 400
    
    # Get caller number if provided
    caller_number = request.form.get('caller_number', '')
    
    # Save file
    fname = file.filename if file.filename else 'audio.webm'
    filename = secure_filename(fname) or 'audio.webm'
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
        
        # Verify company if caller number provided
        if caller_number and verifier:
            verification = verifier.verify_call(caller_number, text)
            if verification['is_impersonation']:
                result['is_spam'] = True
                result['scam_risk'] = max(result['scam_risk'], 90.0)
                result['warning'] = verification['warning']
        
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
        emit('analysis_result', {
            'scam_risk': result['scam_risk'],
            'is_spam': result['is_spam'],
            'matched_flags': result.get('matched_flags', []),
            'scam_type': result.get('scam_type'),
        })

# Real-time microphone
from realtime_analyzer import RealtimeAnalyzer
analyzer = None

print("Initializing real-time analyzer...")
try:
    analyzer = RealtimeAnalyzer(transcriber=transcriber, classifier=classifier)
    print("Real-time analyzer ready!")
except Exception as e:
    print(f"Warning: Could not initialize microphone: {e}")

@socketio.on('start_microphone')
def handle_start_mic():
    global analyzer
    if not analyzer:
        try:
            analyzer = RealtimeAnalyzer(transcriber=transcriber, classifier=classifier)
        except Exception as e:
            emit('mic_error', {'error': str(e)})
            return
    
    def callback(result):
        # Include transcribed text and verify company
        text = result.get('transcribed_text', '')
        caller_number = ''  # Get from call metadata if available
        
        response = {
            'scam_risk': result['scam_risk'],
            'is_spam': result['is_spam'],
            'transcribed_text': text
        }
        
        if verifier and text:
            verification = verifier.verify_call(caller_number, text)
            if verification['is_impersonation']:
                response['is_spam'] = True
                response['scam_risk'] = max(result['scam_risk'], 90.0)
                response['warning'] = verification['warning']
        
        socketio.emit('mic_result', response)
    
    analyzer.start_recording(callback)
    emit('mic_status', {'status': 'recording'})

@socketio.on('stop_microphone')
def handle_stop_mic():
    if analyzer:
        analyzer.stop_recording()
    emit('mic_status', {'status': 'stopped'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 7860))
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    socketio.run(app, host='0.0.0.0', port=port, debug=debug)
