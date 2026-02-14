# Scam Honeypot System

An autonomous AI-powered honeypot agent that detects scam messages, engages scammers in realistic multi-turn conversations, extracts intelligence (bank accounts, UPI IDs, phone numbers, phishing links), and reports findings via callback. Built for the GUVI Hackathon.


## What This Project Does

This system acts as a fake victim that talks to scammers. When a scammer sends a message (via SMS, WhatsApp, or any channel), the system:

1. Analyzes the message to determine if it is a scam and what type (phishing, impersonation, lottery, investment, KYC fraud).
2. Selects a persona to play. For tech/KYC scams it plays an elderly person confused by technology. For authority/police threats it plays a cautious questioner. For lottery/investment scams it plays a naive, easily excited person.
3. Generates human-like replies using Groq LLM (llama-3.3-70b-versatile) that keep the scammer talking without revealing that detection has occurred.
4. Extracts intelligence from the conversation: bank account numbers, UPI IDs (including non-standard formats like scammer.fraud@fakebank), phone numbers, phishing URLs, and suspicious keywords.
5. Sends a callback to GUVI with all extracted intelligence once minimum engagement turns are reached and scam is confirmed.

The agent never breaks character. It progresses through a realistic 4-stage emotional arc across the conversation:
- Turns 1-3: High anxiety, cooperative, scared
- Turns 4-7: Technical confusion, things not working
- Turns 8-10: Frustration, why is this so hard
- Turns 11+: Suspicion, questioning legitimacy


## Tech Stack

- Python 3.12
- FastAPI for the REST API server
- Groq SDK for LLM inference (llama-3.3-70b-versatile model, temperature 0.9, max 140 tokens)
- MongoDB via pymongo for persistent session and intelligence storage
- Pydantic v2 for request/response validation
- aiohttp for async HTTP callbacks to GUVI
- python-dotenv for environment configuration
- uvicorn as the ASGI server


## Project Structure

```
scam-honeypot/
    main.py                    -- FastAPI application, API routes, authentication middleware
    config.py                  -- All configuration: API keys, ports, MongoDB URI, Groq model, thresholds
    models.py                  -- Pydantic models for requests, responses, session state
    honeypot.py                -- Main orchestrator, routes messages through detection and agent
    agent.py                   -- Autonomous conversation agent, persona selection, response generation
    groq_handler.py            -- Groq LLM integration, prompt construction, response sanitization
    master_prompt.py           -- Master system prompt generator with 10 behavioral constraints
    state_manager.py           -- Dynamic state tracking: emotional arc, topic detection, anti-repetition
    scam_detector.py           -- Scam detection engine with weighted keyword scoring and AI analysis
    intelligence_extractor.py  -- Extracts bank accounts, UPI IDs, phones, URLs, keywords from messages
    guvi_callback.py           -- Sends extracted intelligence to GUVI callback endpoint
    database.py                -- MongoDB operations for sessions, history, intelligence storage
    check_session.py           -- Utility to inspect session data from the database
    test_guvi_flow.py          -- End-to-end test for the full GUVI flow
    requirements.txt           -- Python dependencies
    Dockerfile                 -- Docker container configuration
    fly.toml                   -- Fly.io deployment configuration
    Procfile                   -- Process file for deployment
    .env.example               -- Template for environment variables
```


## Key Features

Dynamic State Management (state_manager.py, 580 lines):
- Per-session state tracking across all conversation turns
- 4-stage emotional progression (anxiety, confusion, frustration, suspicion)
- Topic detection for OTP, UPI, bank account, link, phone conversations
- Fact extraction with turn-number tracking to prevent re-asking known information
- Anti-repetition engine that blocks duplicate responses and sentence patterns
- Forbidden phrase enforcement to keep responses sounding natural
- Variable openers so the agent never starts two messages the same way

Master Prompt System (master_prompt.py, 319 lines):
- Generates a detailed system prompt for the LLM on every turn
- Enforces 10 core behavioral constraints:
  1. Contextual mirroring (acknowledge what the scammer just said)
  2. Memory retention (never ask for information already provided)
  3. Anti-repetition (no repeated sentences, excuses, or stalling phrases)
  4. Direct question answering (respond to yes/no questions before stalling)
  5. Emotional arc (match tone to current conversation stage)
  6. Variable openers (never use the same opening phrase twice)
  7. Bumbling factor (use physical delays like "my phone is slow" not just questions)
  8. Logical friction (challenge contradictions instead of blindly complying)
  9. Data poisoning (give intentionally wrong data to waste scammer time)
  10. Sentiment shift (after turn 7, drop fear and show annoyance)
- Absolute ban on unnatural phrases ("Oh no", "My God this is too much")
- Tone rule: periods and commas only, no exclamation marks

Groq LLM Handler (groq_handler.py):
- Integrates with Groq API using llama-3.3-70b-versatile
- Post-generation sanitization: strips banned phrases, replaces exclamation marks with periods
- Multi-layer guardrails: checks response length, relevance, and naturalness
- Console logging with source tags: [GROQ], [RULE-BASED], [GROQ-GUARDRAIL], [GROQ-SANITIZED], [GROQ-FALLBACK]
- Fallback response generation when LLM fails or returns inappropriate content

AI-First Scam Detection (scam_detector.py, honeypot.py):
- Primary detection via LLM analysis of message content and conversation context
- Fallback to rule-based weighted keyword scoring if LLM is unavailable
- Detects: phishing, impersonation/threats, lottery scams, investment scams, KYC fraud, malicious links
- Configurable confidence threshold (default 0.4)

Intelligence Extraction (intelligence_extractor.py):
- Bank account numbers (8-18 digit patterns with context validation)
- UPI IDs including non-standard formats (catch-all regex for handle@provider patterns)
- Phone numbers (Indian format, normalized to +91XXXXXXXXXX)
- Phishing URLs
- Suspicious keywords and tactics used by the scammer
- Email exclusion list to avoid false positives from common email addresses

GUVI Callback (guvi_callback.py):
- Automatically triggers when: scam detected, minimum turns reached (default 3), intelligence extracted
- Sends sessionId, scamDetected flag, totalMessagesExchanged, extractedIntelligence, and agentNotes
- Manual trigger available via API endpoint


## API Endpoints

GET /
    Health check. No authentication required. Returns basic server status.

GET /health
    Detailed health check. No authentication required. Returns server status with database connectivity.

POST /process
    Main message processing endpoint. Requires x-api-key header.
    Accepts a scammer message with sessionId, message (sender, text, timestamp),
    conversationHistory, and metadata (channel, language, locale).
    Returns {"status": "success", "reply": "agent response text"}.

POST /analyze
    Analyzes a message for scam indicators without engaging in conversation.
    Requires x-api-key header. Returns scam type, confidence, and detected indicators.

GET /session/{id}/intelligence
    Returns all extracted intelligence for a session: bank accounts, UPI IDs, phone numbers,
    phishing links, and suspicious keywords.

GET /session/{id}/summary
    Returns session summary including scam detection status, total messages exchanged,
    and generated agent notes.

GET /session/{id}/history
    Returns the full conversation history for a session (all scammer messages and agent replies).

POST /session/{id}/trigger-callback
    Manually triggers the GUVI callback for a session. Useful for testing or forcing
    a report before automatic trigger conditions are met.

GET /stats
    Returns overall system statistics: total sessions, scams detected, messages processed.


## How to Run

1. Install dependencies:

    pip install -r requirements.txt

2. Create a .env file from the template:

    cp .env.example .env

3. Fill in the required values in .env:

    API_KEY=your-secret-api-key
    GROQ_API_KEY=your-groq-api-key
    MONGODB_URI=your-mongodb-connection-string
    MONGODB_DB_NAME=scam_honeypot
    GROQ_MODEL=llama-3.3-70b-versatile
    USE_LLM=true
    API_HOST=0.0.0.0
    API_PORT=8000
    MIN_ENGAGEMENT_TURNS=3

4. Start the server:

    python main.py

    The server starts on port 8000 by default.

5. Send a test request:

    curl -X POST http://localhost:8000/process \
      -H "Content-Type: application/json" \
      -H "x-api-key: your-secret-api-key" \
      -d '{
        "sessionId": "test-123",
        "message": {
          "sender": "scammer",
          "text": "Your account blocked. Share OTP now.",
          "timestamp": "2026-01-21T10:15:30Z"
        },
        "conversationHistory": [],
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
      }'


## Environment Variables

    API_KEY             -- API key for x-api-key header authentication (default: your-secret-api-key)
    API_HOST            -- Host to bind the server to (default: 0.0.0.0)
    API_PORT            -- Port to listen on (default: 8000)
    GROQ_API_KEY        -- Groq API key for LLM access (required)
    GROQ_MODEL          -- Groq model name (default: llama-3.3-70b-versatile)
    USE_LLM             -- Enable LLM-based responses, set to "true" (default: false)
    MONGODB_URI         -- MongoDB connection string (default: mongodb://localhost:27017)
    MONGODB_DB_NAME     -- MongoDB database name (default: scam_honeypot)
    MIN_ENGAGEMENT_TURNS -- Minimum conversation turns before triggering GUVI callback (default: 3)
    SCAM_CONFIDENCE_THRESHOLD -- Minimum confidence score to classify a message as scam (default: 0.4)


## Deployment

The project includes deployment configuration for Docker and Fly.io:

- Dockerfile builds the application container
- fly.toml configures the Fly.io deployment (app name, region, scaling)
- Procfile defines the process command for platform deployments

To deploy with Docker:

    docker build -t scam-honeypot .
    docker run -p 8000:8000 --env-file .env scam-honeypot

To deploy on Fly.io:

    fly deploy


## Console Logging

When the server runs, each response is tagged with its source in the console:

    [GROQ]           -- Response generated by Groq LLM
    [RULE-BASED]     -- Fallback response from predefined templates (LLM unavailable)
    [GROQ-GUARDRAIL] -- LLM response was overridden by a guardrail check
    [GROQ-SANITIZED] -- LLM response was modified (banned phrases stripped, punctuation fixed)
    [GROQ-FALLBACK]  -- LLM call failed, fallback response used

This helps during development and debugging to verify response sources.

