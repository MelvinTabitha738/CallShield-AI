---
title: CallShield AI
emoji: 🛡️
colorFrom: purple
colorTo: blue
sdk: docker
app_port: 7860
pinned: false
---

# 🛡️ CallShield AI

A real-time scam call detection system for Kenya, powered by a fine-tuned RoBERTa classifier and a rule-based Kenyan scam pattern engine.

## Features

- **Text Analysis** — Paste a call transcript and get an instant scam risk score
- **Audio Upload** — Upload a call recording (wav, mp3, m4a, etc.) — transcribed by Whisper then analyzed
- **Live Microphone** — Stream your microphone in real time for live call monitoring
- **Scam Type Detection** — Identifies the specific scam category (KRA Impersonation, M-Pesa Fraud, Phishing, etc.)
- **Impersonation Detection** — Cross-checks caller number against a registry of verified Kenyan agency numbers

## Scam Categories Detected

| Category | Examples |
|----------|---------|
| KRA Impersonation | Fake tax demands, iTax threats |
| M-Pesa Fraud | Fake reversals, wrong-number tricks |
| Bank Impersonation | Fake Equity, KCB, NCBA calls |
| Lottery/Prize Scam | You have won, unclaimed prizes |
| Emergency Scam | Accident/hospital money requests |
| Loan Scam | Job vacancy fees, advance fees |
| Investment Scam | Unrealistic returns, inheritance funds |
| Phishing | OTP theft, PIN requests, credential harvest |

## Tech Stack

- **ML Model**: RoBERTa fine-tuned for Kenyan scam/legitimate classification
- **Speech-to-Text**: OpenAI Whisper (small)
- **Rule Engine**: 23-flag Kenyan scam pattern analyzer (English + Swahili)
- **Backend**: Flask + Flask-SocketIO
- **Frontend**: Vanilla JS + Socket.IO
