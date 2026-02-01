"""
Data models for the Scam Honeypot System
Matches GUVI Hackathon API specification
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class SenderType(str, Enum):
    SCAMMER = "scammer"
    USER = "user"


class Message(BaseModel):
    """Represents a single message in the conversation - matches GUVI format"""
    sender: SenderType
    text: str  # GUVI uses 'text' not 'content'
    timestamp: Optional[datetime] = Field(default_factory=datetime.now)


class ConversationMetadata(BaseModel):
    """Metadata about the conversation channel and context"""
    channel: str = "SMS"
    language: str = "English"
    locale: str = "IN"


class IncomingRequest(BaseModel):
    """Input request format matching GUVI API specification"""
    sessionId: str
    message: Message
    conversationHistory: List[Message] = Field(default_factory=list)
    metadata: Optional[ConversationMetadata] = Field(default_factory=ConversationMetadata)


class ScamIndicator(BaseModel):
    """Represents a detected scam indicator"""
    indicator_type: str
    value: str
    confidence: float
    context: Optional[str] = None


class ScamDetectionResult(BaseModel):
    """Result of scam detection analysis"""
    is_scam: bool
    confidence: float
    indicators: List[ScamIndicator] = Field(default_factory=list)
    scam_type: Optional[str] = None
    risk_level: str = "unknown"


class ExtractedIntelligence(BaseModel):
    """Intelligence extracted - matches GUVI callback format"""
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    suspiciousKeywords: List[str] = Field(default_factory=list)


class AgentResponse(BaseModel):
    """Response format - matches GUVI expected output"""
    status: str = "success"
    reply: str


class GuviCallbackPayload(BaseModel):
    """Payload format for GUVI final result callback"""
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: ExtractedIntelligence
    agentNotes: str


class SessionState(BaseModel):
    """Internal state tracking for a conversation session"""
    session_id: str
    scam_detected: bool = False
    detection_result: Optional[ScamDetectionResult] = None
    extracted_intelligence: ExtractedIntelligence = Field(default_factory=ExtractedIntelligence)
    persona: str = "naive"
    turn_count: int = 0
    total_messages: int = 0
    engagement_strategy: str = "cooperative"
    tactics_observed: List[str] = Field(default_factory=list)
    callback_sent: bool = False
    callback_had_all_intel: bool = False  # Track if callback was sent with all 4 intel types
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
