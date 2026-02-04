"""
Configuration settings for the Scam Honeypot System
"""
import os
from dotenv import load_dotenv

load_dotenv()

# API Configuration
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", 8000))

# API Key for authentication (required by GUVI)
API_KEY = os.getenv("API_KEY", "your-secret-api-key")

# MongoDB Configuration
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "scam_honeypot")

# Groq API Configuration (Fast LLM with Llama 3.3)
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

# Enable LLM-based responses
USE_LLM = os.getenv("USE_LLM", "false").lower() == "true"

# Minimum turns before sending GUVI callback (3 turns minimum)
MIN_ENGAGEMENT_TURNS = int(os.getenv("MIN_ENGAGEMENT_TURNS", 3))

# Scam Detection Thresholds
SCAM_CONFIDENCE_THRESHOLD = 0.4  # Minimum confidence to classify as scam

# Scam Indicator Keywords (weighted)
SCAM_KEYWORDS = {
    # Urgency indicators
    "urgent": 0.3,
    "immediately": 0.3,
    "suspended": 0.4,
    "blocked": 0.4,
    "verify now": 0.5,
    "action required": 0.4,
    "limited time": 0.3,
    "expires today": 0.4,
    "last chance": 0.3,
    "hurry": 0.3,
    
    # Threat indicators
    "legal action": 0.5,
    "arrest": 0.6,
    "police": 0.4,
    "court": 0.4,
    "lawsuit": 0.5,
    "warrant": 0.6,
    "penalty": 0.4,
    "fine": 0.3,
    
    # Financial requests
    "send money": 0.6,
    "transfer": 0.3,
    "payment": 0.3,
    "upi": 0.4,
    "bank account": 0.4,
    "account number": 0.5,
    "otp": 0.6,
    "pin": 0.5,
    "cvv": 0.6,
    "card number": 0.5,
    
    # Reward/Prize scams
    "congratulations": 0.3,
    "winner": 0.4,
    "lottery": 0.6,
    "prize": 0.4,
    "reward": 0.3,
    "free gift": 0.5,
    "cashback": 0.3,
    
    # Job scams
    "work from home": 0.3,
    "easy money": 0.5,
    "part time job": 0.3,
    "daily earning": 0.4,
    "investment opportunity": 0.5,
    
    # Investment scams
    "invest": 0.4,
    "profit": 0.4,
    "earning": 0.3,
    "guaranteed return": 0.6,
    "double your money": 0.7,
    "high returns": 0.5,
    "scheme": 0.3,
    "register": 0.2,
    "limited slots": 0.4,
    
    # Verification scams
    "kyc": 0.4,
    "verify identity": 0.4,
    "update details": 0.4,
    "confirm account": 0.4,
    "link aadhaar": 0.5,
    "pan card": 0.3,
}

# Phishing URL patterns
SUSPICIOUS_URL_PATTERNS = [
    r"bit\.ly",
    r"tinyurl\.com",
    r"t\.co",
    r"goo\.gl",
    r"shorturl",
    r"cutt\.ly",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP addresses
    r"\.xyz",
    r"\.top",
    r"\.click",
    r"\.loan",
    r"secure.*login",
    r"verify.*account",
    r"update.*payment",
]

# Agent Persona Templates
AGENT_PERSONAS = {
    "naive": {
        "description": "A naive, trusting person who easily believes claims",
        "tone": "friendly, trusting, slightly confused",
        "behavior": "asks basic questions, seems willing to help"
    },
    "cautious": {
        "description": "A slightly suspicious but still engaging person",
        "tone": "polite but questioning",
        "behavior": "asks for clarification, wants more details"
    },
    "elderly": {
        "description": "An elderly person unfamiliar with technology",
        "tone": "confused, polite, needs step-by-step help",
        "behavior": "asks many questions, needs things explained simply"
    }
}

# Default persona (used as fallback, actual persona is selected dynamically based on scammer's first message)
DEFAULT_PERSONA = "naive"
