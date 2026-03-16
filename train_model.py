import json
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import RobertaTokenizer, RobertaForSequenceClassification
from torch.optim import AdamW
from sklearn.model_selection import train_test_split
from tqdm import tqdm

class SpamDataset(Dataset):
    def __init__(self, texts, labels, tokenizer, max_length=256):
        self.encodings = tokenizer(texts, truncation=True, padding=True, max_length=max_length)
        self.labels = labels

    def __getitem__(self, idx):
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        item['labels'] = torch.tensor(self.labels[idx])
        return item

    def __len__(self):
        return len(self.labels)

texts = []
labels = []

# Load scampatterns.json (Kenyan-specific: KRA, police, M-Pesa, etc.)
print("Loading scampatterns.json...")
with open('scampatterns.json', 'r', encoding='utf-8') as f:
    data1 = json.load(f)
for item in data1:
    texts.append(item['text'])
    labels.append(1 if item['label'] == 'scam' else 0)
print(f"  scampatterns.json: {len(data1)} samples")

# Load training_data.json (generic English scam/non-scam)
print("Loading training_data.json...")
with open('training_data.json', 'r', encoding='utf-8') as f:
    data2 = json.load(f)
for item in data2:
    texts.append(item['text'])
    # Normalize: "scam" -> 1, everything else (non-scam, legitimate) -> 0
    labels.append(1 if item['label'] == 'scam' else 0)
print(f"  training_data.json: {len(data2)} samples")

total_scam = sum(labels)
total_legit = len(labels) - total_scam
print(f"\nTotal samples: {len(texts)} | Scam: {total_scam} | Legit: {total_legit}")

# Split data
train_texts, val_texts, train_labels, val_labels = train_test_split(
    texts, labels, test_size=0.2, random_state=42, stratify=labels
)

# Initialize tokenizer and model
tokenizer = RobertaTokenizer.from_pretrained('roberta-base')
model = RobertaForSequenceClassification.from_pretrained('roberta-base', num_labels=2)

# Create datasets
train_dataset = SpamDataset(train_texts, train_labels, tokenizer)
val_dataset = SpamDataset(val_texts, val_labels, tokenizer)

train_loader = DataLoader(train_dataset, batch_size=8, shuffle=True)
val_loader = DataLoader(val_dataset, batch_size=8)

# Class weights to handle imbalance
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"\nUsing device: {device}")

scam_ratio = total_legit / total_scam if total_scam > 0 else 1.0
class_weights = torch.tensor([1.0, scam_ratio], dtype=torch.float).to(device)
print(f"Class weights: legit=1.0, scam={scam_ratio:.2f}")

model.to(device)
optimizer = AdamW(model.parameters(), lr=2e-5, weight_decay=0.01)

loss_fn = torch.nn.CrossEntropyLoss(weight=class_weights)

# Training loop
epochs = 4
best_val_acc = 0.0

for epoch in range(epochs):
    model.train()
    total_loss = 0

    for batch in tqdm(train_loader, desc=f'Epoch {epoch+1}/{epochs}'):
        optimizer.zero_grad()
        input_ids = batch['input_ids'].to(device)
        attention_mask = batch['attention_mask'].to(device)
        batch_labels = batch['labels'].to(device)

        outputs = model(input_ids, attention_mask=attention_mask)
        loss = loss_fn(outputs.logits, batch_labels)
        total_loss += loss.item()

        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()

    # Validation
    model.eval()
    correct = 0
    total = 0
    true_positives = 0
    false_negatives = 0
    false_positives = 0

    with torch.no_grad():
        for batch in val_loader:
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            batch_labels = batch['labels'].to(device)

            outputs = model(input_ids, attention_mask=attention_mask)
            predictions = torch.argmax(outputs.logits, dim=-1)
            correct += (predictions == batch_labels).sum().item()
            total += batch_labels.size(0)

            # Track scam-specific metrics
            true_positives += ((predictions == 1) & (batch_labels == 1)).sum().item()
            false_negatives += ((predictions == 0) & (batch_labels == 1)).sum().item()
            false_positives += ((predictions == 1) & (batch_labels == 0)).sum().item()

    accuracy = correct / total
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print(f'Epoch {epoch+1} | Loss: {total_loss/len(train_loader):.4f} | '
          f'Acc: {accuracy:.4f} | Recall(scam): {recall:.4f} | '
          f'Precision(scam): {precision:.4f} | F1: {f1:.4f}')

    if accuracy > best_val_acc:
        best_val_acc = accuracy
        model.save_pretrained('./spam_classifier_model')
        tokenizer.save_pretrained('./spam_classifier_model')
        print(f'  -> Best model saved (acc={accuracy:.4f})')

print(f'\nTraining complete. Best accuracy: {best_val_acc:.4f}')
print('Model saved to ./spam_classifier_model')
