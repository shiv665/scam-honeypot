"""
Autonomous Agent Conversation Handler
Manages multi-turn conversations with scammers to extract intelligence
"""
import random
from datetime import datetime
from typing import List, Dict, Optional
from models import (
    Message, SenderType, SessionState, ScamDetectionResult,
    ExtractedIntelligence, AgentResponse
)
from config import AGENT_PERSONAS, DEFAULT_PERSONA
import re


class ConversationAgent:
    """
    Autonomous agent that engages with scammers in realistic,
    human-like conversations to extract intelligence.
    Uses Groq LLM (Llama 3.1) when available, falls back to rule-based responses.
    Uses MongoDB for persistent storage when available.
    """
    
    def __init__(self):
        self.personas = AGENT_PERSONAS
        self.session_states: Dict[str, SessionState] = {}  # In-memory fallback
        self.llm = None
        self.db = None
        self._init_llm()
        self._init_database()
    
    def _init_llm(self):
        """Initialize Groq LLM handler if available"""
        try:
            from groq_handler import groq_handler
            self.llm = groq_handler
            if self.llm.is_available():
                print("🤖 Agent using Groq LLM (Llama 3.1) for responses")
            else:
                print("📝 Agent using rule-based responses (Groq not configured)")
        except Exception as e:
            print(f"📝 Agent using rule-based responses: {e}")
            self.llm = None
    
    def _init_database(self):
        """Initialize MongoDB database handler"""
        try:
            from database import db_handler
            self.db = db_handler
            if self.db.is_connected():
                print("💾 Agent using MongoDB for persistent storage")
            else:
                print("📝 Agent using in-memory storage (MongoDB not available)")
        except Exception as e:
            print(f"📝 Agent using in-memory storage: {e}")
            self.db = None
    
    def get_or_create_session(self, session_id: str) -> SessionState:
        """Get existing session or create new one (checks MongoDB first)"""
        # Try to get from MongoDB first
        if self.db and self.db.is_connected():
            db_session = self.db.get_session(session_id)
            if db_session:
                # Convert dict to SessionState
                return self._dict_to_session(db_session)
        
        # Fallback to in-memory
        if session_id not in self.session_states:
            self.session_states[session_id] = SessionState(
                session_id=session_id,
                persona=DEFAULT_PERSONA
            )
        return self.session_states[session_id]
    
    def _dict_to_session(self, data: Dict) -> SessionState:
        """Convert MongoDB dict to SessionState object"""
        from models import ExtractedIntelligence, ScamDetectionResult
        
        # Handle extracted_intelligence
        intel_data = data.get("extracted_intelligence", {})
        if isinstance(intel_data, dict):
            extracted_intelligence = ExtractedIntelligence(**intel_data)
        else:
            extracted_intelligence = ExtractedIntelligence()
        
        # Handle detection_result
        detection_data = data.get("detection_result")
        detection_result = None
        if detection_data and isinstance(detection_data, dict):
            detection_result = ScamDetectionResult(**detection_data)
        
        return SessionState(
            session_id=data.get("session_id", ""),
            scam_detected=data.get("scam_detected", False),
            detection_result=detection_result,
            extracted_intelligence=extracted_intelligence,
            persona=data.get("persona", DEFAULT_PERSONA),
            turn_count=data.get("turn_count", 0),
            total_messages=data.get("total_messages", 0),
            engagement_strategy=data.get("engagement_strategy", "cooperative"),
            tactics_observed=data.get("tactics_observed", []),
            callback_sent=data.get("callback_sent", False)
        )
    
    def select_persona_from_message(self, message_text: str) -> str:
        """
        Analyze the first scammer message and select the best persona to engage.
        
        Args:
            message_text: The first message from the scammer
            
        Returns:
            Persona key ('naive', 'cautious', or 'elderly')
        """
        text_lower = message_text.lower()
        
        # Technical scams (KYC, OTP, app install) -> elderly persona (confused about tech)
        tech_patterns = [
            r'\b(otp|kyc|app|download|install|anydesk|teamviewer|link|click|update)\b',
            r'\b(verify|verification|authenticate|login|password)\b',
            r'\b(software|application|browser|website)\b'
        ]
        for pattern in tech_patterns:
            if re.search(pattern, text_lower):
                return "elderly"
        
        # Authority/threat scams (police, legal, govt) -> cautious persona
        authority_patterns = [
            r'\b(police|court|legal|arrest|warrant|government|rbi|sebi|tax)\b',
            r'\b(investigation|complaint|case|violation|penalty|fine)\b',
            r'\b(officer|inspector|department|ministry|authority)\b'
        ]
        for pattern in authority_patterns:
            if re.search(pattern, text_lower):
                return "cautious"
        
        # Investment/lottery/prize scams -> naive persona (easily excited)
        reward_patterns = [
            r'\b(congratulations|winner|lottery|prize|reward|gift|bonus)\b',
            r'\b(invest|profit|returns|earning|double|guaranteed|scheme)\b',
            r'\b(offer|discount|cashback|refund|selected|chosen)\b'
        ]
        for pattern in reward_patterns:
            if re.search(pattern, text_lower):
                return "naive"
        
        # Bank/account issues -> elderly (needs help understanding)
        bank_patterns = [
            r'\b(bank|account|blocked|suspended|frozen|deactivated)\b',
            r'\b(transaction|transfer|payment|upi|credit|debit)\b'
        ]
        for pattern in bank_patterns:
            if re.search(pattern, text_lower):
                return "elderly"
        
        # Default to naive for maximum engagement
        return "naive"
    
    def update_session(self, session_id: str, 
                       detection_result: Optional[ScamDetectionResult] = None,
                       intelligence: Optional[ExtractedIntelligence] = None,
                       first_message: Optional[str] = None) -> SessionState:
        """Update session with new detection results and intelligence"""
        session = self.get_or_create_session(session_id)
        
        # On first turn, select persona based on scammer's opening message
        if session.turn_count == 0 and first_message:
            selected_persona = self.select_persona_from_message(first_message)
            session.persona = selected_persona
            print(f"🎭 Selected persona '{selected_persona}' based on scammer's message")
        
        # Identify and store tactics from the message
        if first_message:
            from intelligence_extractor import intelligence_extractor
            new_tactics = intelligence_extractor.identify_tactics(first_message)
            for tactic in new_tactics:
                if tactic not in session.tactics_observed:
                    session.tactics_observed.append(tactic)
        
        if detection_result:
            session.scam_detected = detection_result.is_scam
            session.detection_result = detection_result
        
        if intelligence:
            # Merge intelligence with existing data (don't replace)
            existing = session.extracted_intelligence
            # Add new items if not already present
            for acc in intelligence.bankAccounts:
                if acc not in existing.bankAccounts:
                    existing.bankAccounts.append(acc)
            for upi in intelligence.upiIds:
                if upi not in existing.upiIds:
                    existing.upiIds.append(upi)
            for phone in intelligence.phoneNumbers:
                if phone not in existing.phoneNumbers:
                    existing.phoneNumbers.append(phone)
            for link in intelligence.phishingLinks:
                if link not in existing.phishingLinks:
                    existing.phishingLinks.append(link)
            for kw in intelligence.suspiciousKeywords:
                if kw not in existing.suspiciousKeywords:
                    existing.suspiciousKeywords.append(kw)
        
        session.turn_count += 1
        session.updated_at = datetime.now()
        
        # Also update in-memory cache
        self.session_states[session_id] = session
        
        # Save to MongoDB if available
        if self.db and self.db.is_connected():
            self.db.save_session(session.model_dump())
        
        return session
    
    def save_conversation_turn(self, session_id: str, 
                                scammer_message: Message, 
                                agent_reply: str) -> bool:
        """Save a conversation turn to MongoDB"""
        if self.db and self.db.is_connected():
            return self.db.save_conversation_turn(
                session_id,
                {"text": scammer_message.text, "timestamp": scammer_message.timestamp},
                agent_reply
            )
        return False
    
    def get_full_history(self, session_id: str) -> List[Dict]:
        """Get full conversation history from MongoDB"""
        if self.db and self.db.is_connected():
            return self.db.get_conversation_history(session_id)
        return []
    
    def _convert_mongo_history(self, mongo_history: List[Dict]) -> List[Message]:
        """Convert MongoDB conversation history to Message objects for Groq"""
        messages = []
        for turn in mongo_history:
            # Each turn has scammer_message and agent_reply
            if "scammer_message" in turn:
                scammer_msg = turn["scammer_message"]
                messages.append(Message(
                    text=scammer_msg.get("text", ""),
                    sender="agent",  # In our model, "agent" = scammer
                    timestamp=scammer_msg.get("timestamp", "")
                ))
            if "agent_reply" in turn:
                messages.append(Message(
                    text=turn["agent_reply"],
                    sender="user",  # In our model, "user" = our honeypot
                    timestamp=turn.get("timestamp", "")
                ))
        return messages
    
    def mark_callback_sent(self, session_id: str) -> bool:
        """Mark that GUVI callback has been sent for this session"""
        session = self.get_or_create_session(session_id)
        session.callback_sent = True
        self.session_states[session_id] = session
        
        if self.db and self.db.is_connected():
            self.db.save_session(session.model_dump())
            return True
        return False
    
    def generate_response(self, 
                          message: Message,
                          conversation_history: List[Message],
                          detection_result: ScamDetectionResult,
                          session: SessionState) -> str:
        """
        Generate a contextual response to engage the scammer.
        
        Uses Groq LLM (Llama 3.1) for intelligent responses when available,
        falls back to rule-based logic with persona-aware responses.
        
        Prioritizes MongoDB history for better context continuity.
        """
        # Get full conversation history from MongoDB if available
        # This ensures Groq has complete context across API calls
        full_history = conversation_history  # Default to request history
        if self.db and self.db.is_connected():
            mongo_history = self.get_full_history(session.session_id)
            if mongo_history:
                # Convert MongoDB history to Message format for Groq
                full_history = self._convert_mongo_history(mongo_history)
        
        # Try Groq LLM first for smarter responses
        if self.llm and self.llm.is_available():
            llm_response = self.llm.generate_response(
                message.text,
                full_history,  # Use MongoDB history for better context
                detection_result,
                session
            )
            if llm_response:
                return llm_response
        
        # Fallback to rule-based responses
        scammer_text = message.text.lower()
        persona = self.personas.get(session.persona, self.personas[DEFAULT_PERSONA])
        
        # Determine scam type and generate appropriate response
        if detection_result.scam_type:
            return self._get_response_for_scam_type(
                detection_result.scam_type,
                scammer_text,
                session,
                persona
            )
        
        # Generic engagement response
        return self._get_generic_response(scammer_text, session, persona)
    
    def _get_response_for_scam_type(self, scam_type: str, 
                                     scammer_text: str,
                                     session: SessionState,
                                     persona: dict) -> str:
        """Generate response based on detected scam type"""
        
        responses = {
            "phishing": self._handle_phishing_scam,
            "impersonation_threat": self._handle_threat_scam,
            "lottery_scam": self._handle_lottery_scam,
            "job_scam": self._handle_job_scam,
            "phishing_link": self._handle_link_scam,
            "kyc_fraud": self._handle_kyc_scam,
            "generic_scam": self._handle_generic_scam,
        }
        
        handler = responses.get(scam_type, self._handle_generic_scam)
        return handler(scammer_text, session)
    
    def _handle_phishing_scam(self, text: str, session: SessionState) -> str:
        """Handle OTP/PIN/CVV phishing attempts"""
        turn = session.turn_count
        
        responses = [
            # Early engagement - appear confused but willing
            [
                "Oh, you need my OTP? I'm not sure what that is. Can you explain why you need it?",
                "I received a code on my phone. But I thought we shouldn't share this with anyone?",
                "Wait, my bank says never to share OTP. Are you sure you're from the bank?",
                "Let me check... I got an OTP but I'm a bit confused about this process.",
            ],
            # Middle engagement - ask for verification
            [
                "Before I share anything, can you give me your employee ID and your supervisor's name?",
                "I want to verify this is legitimate. What's the official bank helpline number I can call back?",
                "My son told me to never share OTPs. Can you confirm this is safe?",
                "What exactly will happen after I share this code? I want to understand the process.",
            ],
            # Intelligence extraction - ask for their details
            [
                "I'm still not sure. Can you give me your direct phone number so I can call you back?",
                "What's the account number you're referring to? I have multiple accounts.",
                "Which branch are you calling from? I'll visit in person to complete this.",
                "Send me the details on my registered email so I can verify. What email do you have on file?",
            ],
        ]
        
        stage = min(turn // 2, len(responses) - 1)
        return random.choice(responses[stage])
    
    def _handle_threat_scam(self, text: str, session: SessionState) -> str:
        """Handle threat/impersonation scams"""
        turn = session.turn_count
        
        responses = [
            # Initial fear response
            [
                "Oh my god, what? Arrest? What have I done wrong? Please explain!",
                "Sir/Madam, I'm very scared. Please tell me what this is about.",
                "I haven't done anything illegal! What case is this about?",
                "This must be a mistake. I'm a law-abiding citizen. What should I do?",
            ],
            # Seeking more details
            [
                "What is the case number? I need to consult my family about this.",
                "Can you give me the FIR number so I can verify at the police station?",
                "Which department are you from? I need your badge number for my records.",
                "How much is the fine? And where should I pay it officially?",
            ],
            # Intelligence extraction
            [
                "If I need to pay, what are the official payment options? Do you have a bank account number?",
                "Can you send me the official notice? What's the email or address?",
                "I'll cooperate fully. Just give me your contact number so I can call back.",
                "My lawyer wants to know the case details. Can you provide your department's address?",
            ],
        ]
        
        stage = min(turn // 2, len(responses) - 1)
        return random.choice(responses[stage])
    
    def _handle_lottery_scam(self, text: str, session: SessionState) -> str:
        """Handle lottery/prize scams"""
        turn = session.turn_count
        
        responses = [
            # Initial excitement
            [
                "Wow, really? I won something? That's amazing! What did I win?",
                "Oh my goodness! I never win anything! How much is the prize?",
                "This is wonderful news! How do I claim my prize?",
                "Are you serious? I actually won? When was this lottery?",
            ],
            # Cautious engagement
            [
                "Wait, I don't remember entering any lottery. Which company is this from?",
                "What's the process to claim? I don't want to miss this opportunity!",
                "Is there any fee I need to pay? That seems strange for a prize...",
                "My family won't believe this! Can you send me official documentation?",
            ],
            # Intelligence extraction
            [
                "Where should I collect the prize? What's the office address?",
                "If there's a processing fee, where do I send it? What's the account or UPI?",
                "Can you call me back on your official number? What number should I save?",
                "Send me the details on WhatsApp. What's the official number?",
            ],
        ]
        
        stage = min(turn // 2, len(responses) - 1)
        return random.choice(responses[stage])
    
    def _handle_job_scam(self, text: str, session: SessionState) -> str:
        """Handle job/investment scams"""
        turn = session.turn_count
        
        responses = [
            # Interest shown
            [
                "Work from home? That sounds perfect for me! Tell me more about this.",
                "How much can I earn? I really need extra income right now.",
                "What kind of work is this? Is it legitimate?",
                "I'm very interested! What do I need to do to get started?",
            ],
            # Asking for details
            [
                "What's the company name? I want to research before joining.",
                "How do I receive payments? Is it weekly or monthly?",
                "Is there any training provided? Who will be my supervisor?",
                "What's the registration process? Is there a joining fee?",
            ],
            # Intelligence extraction
            [
                "Where is your office located? I'd like to visit before joining.",
                "What's the company's website and registration number?",
                "If I need to deposit anything, what's the account I send it to?",
                "Give me your HR's contact number so I can verify this opportunity.",
            ],
        ]
        
        stage = min(turn // 2, len(responses) - 1)
        return random.choice(responses[stage])
    
    def _handle_link_scam(self, text: str, session: SessionState) -> str:
        """Handle phishing link scams"""
        turn = session.turn_count
        
        responses = [
            # Initial caution
            [
                "I see there's a link. What happens when I click it?",
                "My phone is very slow. Can you tell me what's on that page?",
                "I'm on my computer. The link isn't loading. What should I do?",
                "Before I click, can you explain what this is for?",
            ],
            # Technical excuses
            [
                "I clicked but nothing happened. Maybe my internet is slow?",
                "The page shows an error. Can you send me an alternative link?",
                "I'm not able to access it. Can you tell me the steps over phone?",
                "My browser is blocking it. What website is this from?",
            ],
            # Request alternatives
            [
                "Can you just tell me what to do step by step instead of the link?",
                "I'll try from my daughter's phone. What's the URL again so I can type it?",
                "Just send me the details directly. What information do you need from me?",
                "This seems complicated. Can I visit your office instead? Where is it?",
            ],
        ]
        
        stage = min(turn // 2, len(responses) - 1)
        return random.choice(responses[stage])
    
    def _handle_kyc_scam(self, text: str, session: SessionState) -> str:
        """Handle KYC/verification fraud"""
        turn = session.turn_count
        
        responses = [
            # Confused compliance
            [
                "KYC update? I thought I already did this at the branch last year.",
                "Oh, my account will be blocked? That's concerning! What do I need to do?",
                "I didn't receive any SMS about this. When was it sent?",
                "Which account are you referring to? I have multiple bank accounts.",
            ],
            # Verification requests
            [
                "How can I verify you're really from the bank? What's your employee ID?",
                "Can I complete this at the branch instead? Which branch should I visit?",
                "My relationship manager's name is different. Who is handling my account now?",
                "What's the customer care number I can call to confirm this is genuine?",
            ],
            # Intelligence extraction
            [
                "If I need to submit documents, where should I email them?",
                "What's the official bank portal for KYC? I'll do it there.",
                "Give me your callback number and I'll call back in 5 minutes.",
                "Which specific documents do you need? And what's the process fee if any?",
            ],
        ]
        
        stage = min(turn // 2, len(responses) - 1)
        return random.choice(responses[stage])
    
    def _handle_generic_scam(self, text: str, session: SessionState) -> str:
        """Handle generic/unclassified scams"""
        turn = session.turn_count
        
        responses = [
            # General engagement
            [
                "I see, can you explain this in more detail?",
                "I'm not sure I understand. Can you tell me more?",
                "What exactly do you need from me?",
                "This sounds important. How can I help?",
            ],
            # Information gathering
            [
                "Who are you representing? What organization is this?",
                "Can you provide more details about yourself?",
                "What's the purpose of this contact? I want to understand better.",
                "Is there an official way I can verify this information?",
            ],
            # Intelligence extraction
            [
                "What's the best number to reach you at?",
                "Can you send this information to my email?",
                "Where can I come to discuss this in person?",
                "If any payment is needed, what are the official options?",
            ],
        ]
        
        stage = min(turn // 2, len(responses) - 1)
        return random.choice(responses[stage])
    
    def _get_generic_response(self, text: str, session: SessionState, persona: dict) -> str:
        """Generate a generic engaging response"""
        generic_responses = [
            "I see, tell me more about this.",
            "That's interesting. What should I do next?",
            "I want to help. Can you explain the process?",
            "Okay, I'm listening. Please continue.",
            "I understand. What information do you need from me?",
        ]
        return random.choice(generic_responses)
    
    def create_response(self, reply_text: str) -> AgentResponse:
        """Create the final JSON response"""
        return AgentResponse(
            status="success",
            reply=reply_text
        )


# Singleton instance
conversation_agent = ConversationAgent()
