# Scam Honeypot System

An autonomous AI Agent for scam detection and intelligence extraction, built for the **GUVI Hackathon**.

## ✅ GUVI Requirements Compliance

| Requirement | Status |
|-------------|--------|
| API Key Authentication (x-api-key header) | ✅ Implemented |
| Message format with `text` field | ✅ Implemented |
| Response format `{"status": "success", "reply": "..."}` | ✅ Implemented |
| Multi-turn conversation handling | ✅ Implemented |
| Scam detection & agent activation | ✅ Implemented |
| Intelligence extraction (bankAccounts, upiIds, etc.) | ✅ Implemented |
| GUVI Callback to `/updateHoneyPotFinalResult` | ✅ Implemented |
| Total messages tracking | ✅ Implemented |
| Agent notes generation | ✅ Implemented |
| Dynamic persona selection | ✅ Implemented |

## 📁 Project Structure

```
scam-honeypot/
├── config.py              # Configuration and settings
├── models.py              # Pydantic data models (GUVI format)
├── scam_detector.py       # Scam detection engine
├── intelligence_extractor.py  # Intelligence extraction module
├── agent.py               # Autonomous conversation agent
├── groq_handler.py        # Groq LLM integration (Llama 3.3 70B)
├── guvi_callback.py       # GUVI callback handler
├── honeypot.py            # Main handler/orchestrator
├── database.py            # MongoDB persistent storage
├── main.py                # FastAPI application with auth
├── requirements.txt       # Dependencies
└── README.md              # This file
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd scam-honeypot
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
# Copy example env file
cp .env.example .env

# Edit .env with your settings
API_KEY=your-secret-api-key
GROQ_API_KEY=your_groq_api_key
MONGODB_URI=your_mongodb_connection_string
```

### 3. Run the Server

```bash
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

Server runs at `http://localhost:8000`

## 📡 API Endpoints

### POST `/process` (Main Endpoint)

**Headers:**
```
x-api-key: YOUR_SECRET_API_KEY
Content-Type: application/json
```

**Request (GUVI Format):**
```json
{
  "sessionId": "wertyu-dfghj-ertyui",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked today. Verify immediately.",
    "timestamp": "2026-01-21T10:15:30Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "Why is my account being suspended?"
}
```

### Other Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Health check (no auth) |
| `/health` | GET | Detailed health check (no auth) |
| `/process` | POST | Process scammer message (with auth) |
| `/analyze` | POST | Analyze message for scam (with auth) |
| `/session/{id}/intelligence` | GET | Get extracted intelligence |
| `/session/{id}/summary` | GET | Get session summary with agentNotes |
| `/session/{id}/history` | GET | Get full conversation history |
| `/session/{id}/trigger-callback` | POST | Manually trigger GUVI callback |
| `/stats` | GET | Get overall statistics |

## 🔄 GUVI Callback

The system automatically sends results to GUVI when:
- Scam is detected
- Minimum engagement turns reached (default: 3)
- Significant intelligence extracted

**Callback Payload (sent automatically):**
```json
{
  "sessionId": "abc123-session-id",
  "scamDetected": true,
  "totalMessagesExchanged": 6,
  "extractedIntelligence": {
    "bankAccounts": ["50123456789"],
    "upiIds": ["scammer@ybl"],
    "phishingLinks": ["http://malicious-link.example"],
    "phoneNumbers": ["+919876543210"],
    "suspiciousKeywords": ["urgent", "verify now", "account blocked"]
  },
  "agentNotes": "Scammer used urgency tactics and payment redirection via UPI. Identified as phishing scam"
}
```

## 🎭 Dynamic Persona Selection

The agent automatically selects a persona based on the scammer's first message:

| Scam Type | Keywords Detected | Persona Selected |
|-----------|------------------|------------------|
| Tech/KYC Scam | otp, kyc, download, app, verify | **elderly** (confused about tech) |
| Authority Scam | police, legal, arrest, government | **cautious** (questioning) |
| Investment/Prize | lottery, congratulations, invest, profit | **naive** (easily excited) |

## 🔍 Scam Detection

Detects multiple scam types:
- **Phishing**: OTP, PIN, CVV requests
- **Impersonation/Threat**: Fake police/bank threats
- **Lottery Scam**: Fake prizes/winnings
- **Investment Scam**: Fake profit schemes
- **KYC Fraud**: Fake KYC update requests
- **Phishing Links**: Malicious URLs

## 🤖 Agent Behavior

The agent:
1. Detects scam intent automatically
2. Selects appropriate persona dynamically
3. Engages with human-like responses (Groq LLM)
4. Extracts intelligence organically
5. Never reveals detection

## 📊 Intelligence Extraction

Automatically extracts:
- Bank account numbers
- UPI IDs (e.g., scammer@ybl)
- Phone numbers (formatted as +91XXXXXXXXXX)
- Phishing URLs
- Suspicious keywords and tactics

## ⚙️ Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `API_KEY` | API key for authentication | your-secret-api-key |
| `API_HOST` | Host to bind | 0.0.0.0 |
| `API_PORT` | Port to listen | 8000 |
| `GROQ_API_KEY` | Groq API key (FREE tier: 14,400 req/day) | (required) |
| `GROQ_MODEL` | Groq model name | llama-3.3-70b-versatile |
| `MONGODB_URI` | MongoDB connection string | mongodb://localhost:27017 |
| `MONGODB_DB_NAME` | MongoDB database name | scam_honeypot |
| `MIN_ENGAGEMENT_TURNS` | Min turns before callback | 3 |

## 🧪 Testing with cURL

```bash
curl -X POST http://localhost:8000/process \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-secret-api-key" \
  -d '{
    "sessionId": "test-123",
    "message": {
      "sender": "scammer",
      "text": "Your account blocked. Share OTP now!",
      "timestamp": "2026-01-21T10:15:30Z"
    },
    "conversationHistory": [],
    "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
  }'
```

## 📜 License

MIT License - For GUVI Hackathon use.
