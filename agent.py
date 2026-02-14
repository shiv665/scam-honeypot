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
    Uses Groq LLM when available, falls back to rule-based responses.
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
                print("Agent using Groq LLM for responses")
            else:
                print("Agent using rule-based responses (Groq not configured)")
        except Exception as e:
            print(f"Agent using rule-based responses: {e}")
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
        from models import ExtractedIntelligence, ScamDetectionResult, ConversationTurn
        
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
        
        # Handle conversation_history
        history_data = data.get("conversation_history", [])
        conversation_history = []
        for turn_data in history_data:
            if isinstance(turn_data, dict):
                conversation_history.append(ConversationTurn(**turn_data))
        
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
            callback_sent=data.get("callback_sent", False),
            callback_had_all_intel=data.get("callback_had_all_intel", False),
            last_callback_turn=data.get("last_callback_turn", 0),
            conversation_history=conversation_history
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
        """Convert MongoDB conversation history to Message objects for LLM use"""
        messages = []
        for entry in mongo_history:
            # Current Mongo format: {"sender": "scammer|agent", "text": "...", ...}
            if "sender" in entry and "text" in entry:
                sender = str(entry.get("sender", "")).lower()
                mapped_sender = "scammer" if sender == "scammer" else "user"
                messages.append(
                    Message(
                        text=entry.get("text", ""),
                        sender=mapped_sender,
                        timestamp=entry.get("timestamp", ""),
                    )
                )
                continue

            # Legacy format fallback: {"scammer_message": {...}, "agent_reply": "..."}
            if "scammer_message" in entry:
                scammer_msg = entry["scammer_message"]
                messages.append(
                    Message(
                        text=scammer_msg.get("text", ""),
                        sender="scammer",
                        timestamp=scammer_msg.get("timestamp", ""),
                    )
                )
            if "agent_reply" in entry:
                messages.append(
                    Message(
                        text=entry["agent_reply"],
                        sender="user",
                        timestamp=entry.get("timestamp", ""),
                    )
                )
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
        
        Uses Groq LLM for intelligent responses when available,
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
        print(f"[RULE-BASED] Groq unavailable or returned None, using hardcoded response")
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
        """Handle OTP/PIN/CVV phishing attempts - Intel-aware responses"""
        turn = session.turn_count
        intel = session.extracted_intelligence
        
        # Check what intel we already have
        has_upi = len(intel.upiIds) > 0
        has_phone = len(intel.phoneNumbers) > 0
        has_bank = len(intel.bankAccounts) > 0
        has_link = len(intel.phishingLinks) > 0
        
        # Build questions for missing intel
        missing_questions = []
        if not has_phone:
            missing_questions.append("What is your direct phone number so I can call you back?")
            missing_questions.append("Can you give me a callback number to verify?")
        if not has_upi:
            missing_questions.append("What is your UPI ID for the payment?")
            missing_questions.append("Which UPI ID should I send the verification amount to?")
        if not has_bank:
            missing_questions.append("What is the account number you are referring to?")
            missing_questions.append("Can you confirm the bank account number?")
        if not has_link:
            missing_questions.append("What is your official email ID for verification?")
            missing_questions.append("Can you send me the details via email? What is your email?")
        
        # OTP deflection responses (vary by turn)
        otp_deflections = [
            "I didn't receive any OTP on my phone.",
            "No OTP came to my phone yet.",
            "I'm checking but there's no OTP message.",
            "My phone shows no new OTP.",
            "I haven't received any code yet.",
        ]
        
        # Combine OTP deflection with intel question if available
        deflection = otp_deflections[turn % len(otp_deflections)]
        
        if missing_questions:
            question = missing_questions[turn % len(missing_questions)]
            return f"{deflection} {question}"
        else:
            # All intel collected, just keep engaging
            engaging_responses = [
                "I'm still waiting for the OTP. Can you explain the process again?",
                "Let me check my messages again. What should I do after I get the OTP?",
                "My phone is slow. Can you tell me more about why this is needed?",
            ]
            return random.choice(engaging_responses)
    
    def _handle_threat_scam(self, text: str, session: SessionState) -> str:
        """Handle threat/impersonation scams - Intel-aware responses"""
        turn = session.turn_count
        intel = session.extracted_intelligence
        
        # Check what intel we already have
        has_upi = len(intel.upiIds) > 0
        has_phone = len(intel.phoneNumbers) > 0
        has_bank = len(intel.bankAccounts) > 0
        has_link = len(intel.phishingLinks) > 0
        
        # Build questions for missing intel
        missing_questions = []
        if not has_phone:
            missing_questions.append("What is your official contact number?")
            missing_questions.append("Can you give me your department's phone number?")
        if not has_upi:
            missing_questions.append("If I need to pay a fine, what is the UPI ID?")
            missing_questions.append("What is the official UPI for payment?")
        if not has_bank:
            missing_questions.append("What is the official bank account for payment?")
            missing_questions.append("Can you provide the bank account details?")
        if not has_link:
            missing_questions.append("What is your official email ID for sending documents?")
            missing_questions.append("Can you email me the case details?")
        
        # Fear/concern responses (vary by turn)
        fear_responses = [
            "Oh my god, I'm very scared.",
            "Sir/Madam, please tell me what to do.",
            "I haven't done anything wrong!",
            "I'll cooperate fully.",
            "This must be a mistake.",
        ]
        
        response_base = fear_responses[turn % len(fear_responses)]
        
        if missing_questions:
            question = missing_questions[turn % len(missing_questions)]
            return f"{response_base} {question}"
        else:
            return f"{response_base} What should I do next?"
    
    def _handle_lottery_scam(self, text: str, session: SessionState) -> str:
        """Handle lottery/prize scams - Intel-aware responses"""
        turn = session.turn_count
        intel = session.extracted_intelligence
        
        # Check what intel we already have
        has_upi = len(intel.upiIds) > 0
        has_phone = len(intel.phoneNumbers) > 0
        has_bank = len(intel.bankAccounts) > 0
        has_link = len(intel.phishingLinks) > 0
        
        # Build questions for missing intel
        missing_questions = []
        if not has_phone:
            missing_questions.append("What is your official contact number?")
            missing_questions.append("Can you give me a number to call back?")
        if not has_upi:
            missing_questions.append("What is the UPI ID for the processing fee?")
            missing_questions.append("Where should I send the fee? What UPI?")
        if not has_bank:
            missing_questions.append("What is the bank account for the fee?")
            missing_questions.append("Can you give me the account details?")
        if not has_link:
            missing_questions.append("What is your email to send my documents?")
            missing_questions.append("Can you email me the prize details?")
        
        # Excitement responses (vary by turn)
        excitement_responses = [
            "Wow, I really won something?",
            "This is amazing news!",
            "I never win anything!",
            "How exciting!",
            "I can't believe it!",
        ]
        
        response_base = excitement_responses[turn % len(excitement_responses)]
        
        if missing_questions:
            question = missing_questions[turn % len(missing_questions)]
            return f"{response_base} {question}"
        else:
            return f"{response_base} What do I do next?"
    
    def _handle_job_scam(self, text: str, session: SessionState) -> str:
        """Handle job/investment scams - Intel-aware responses"""
        turn = session.turn_count
        intel = session.extracted_intelligence
        
        # Check what intel we already have
        has_upi = len(intel.upiIds) > 0
        has_phone = len(intel.phoneNumbers) > 0
        has_bank = len(intel.bankAccounts) > 0
        has_link = len(intel.phishingLinks) > 0
        
        # Build questions for missing intel
        missing_questions = []
        if not has_phone:
            missing_questions.append("What is the HR contact number?")
            missing_questions.append("Can you give me a number to call?")
        if not has_upi:
            missing_questions.append("What is the UPI for the registration fee?")
            missing_questions.append("Where should I pay? What UPI?")
        if not has_bank:
            missing_questions.append("What is the bank account for the fee?")
            missing_questions.append("Can you give me account details?")
        if not has_link:
            missing_questions.append("What is the company email ID?")
            missing_questions.append("Can you send details to my email?")
        
        # Interest responses (vary by turn)
        interest_responses = [
            "I'm very interested in this opportunity!",
            "Work from home sounds perfect for me!",
            "How much can I earn?",
            "This sounds like a great job!",
            "I really need this income.",
        ]
        
        response_base = interest_responses[turn % len(interest_responses)]
        
        if missing_questions:
            question = missing_questions[turn % len(missing_questions)]
            return f"{response_base} {question}"
        else:
            return f"{response_base} What are the next steps?"
    
    def _handle_link_scam(self, text: str, session: SessionState) -> str:
        """Handle phishing link scams - Intel-aware responses"""
        turn = session.turn_count
        intel = session.extracted_intelligence
        
        # Check what intel we already have
        has_upi = len(intel.upiIds) > 0
        has_phone = len(intel.phoneNumbers) > 0
        has_bank = len(intel.bankAccounts) > 0
        has_link = len(intel.phishingLinks) > 0
        
        # Build questions for missing intel
        missing_questions = []
        if not has_phone:
            missing_questions.append("Can you tell me over phone? What is your number?")
            missing_questions.append("My browser is not working. Can you call me?")
        if not has_upi:
            missing_questions.append("What is the UPI ID mentioned in the link?")
            missing_questions.append("If I need to pay, what UPI should I use?")
        if not has_bank:
            missing_questions.append("What account number should I enter?")
            missing_questions.append("Can you tell me the bank details?")
        if not has_link:
            missing_questions.append("Can you email me the link instead?")
            missing_questions.append("What is your email ID?")
        
        # Technical excuse responses (vary by turn)
        tech_excuses = [
            "The link is not opening on my phone.",
            "My internet is very slow.",
            "The page shows an error.",
            "My browser is blocking this.",
            "I clicked but nothing happened.",
        ]
        
        response_base = tech_excuses[turn % len(tech_excuses)]
        
        if missing_questions:
            question = missing_questions[turn % len(missing_questions)]
            return f"{response_base} {question}"
        else:
            return f"{response_base} Can you guide me step by step?"
    
    def _handle_kyc_scam(self, text: str, session: SessionState) -> str:
        """Handle KYC/verification fraud - Intel-aware responses"""
        turn = session.turn_count
        intel = session.extracted_intelligence
        
        # Check what intel we already have
        has_upi = len(intel.upiIds) > 0
        has_phone = len(intel.phoneNumbers) > 0
        has_bank = len(intel.bankAccounts) > 0
        has_link = len(intel.phishingLinks) > 0
        
        # Build questions for missing intel
        missing_questions = []
        if not has_phone:
            missing_questions.append("What is your callback number?")
            missing_questions.append("Can you give me a number to verify?")
        if not has_upi:
            missing_questions.append("What is the UPI ID for the fee?")
            missing_questions.append("If there's a fee, what UPI should I use?")
        if not has_bank:
            missing_questions.append("Which account number are you referring to?")
            missing_questions.append("Can you confirm the account details?")
        if not has_link:
            missing_questions.append("What is your email for documents?")
            missing_questions.append("Can you email me the KYC form?")
        
        # Confusion responses (vary by turn)
        confusion_responses = [
            "I'm confused about this KYC process.",
            "I thought I already completed KYC.",
            "My account will be blocked?",
            "I didn't receive any message about this.",
            "Which account are you referring to?",
        ]
        
        response_base = confusion_responses[turn % len(confusion_responses)]
        
        if missing_questions:
            question = missing_questions[turn % len(missing_questions)]
            return f"{response_base} {question}"
        else:
            return f"{response_base} What should I do next?"
    
    def _handle_generic_scam(self, text: str, session: SessionState) -> str:
        """Handle generic/unclassified scams - Intel-aware responses"""
        turn = session.turn_count
        intel = session.extracted_intelligence
        
        # Check what intel we already have
        has_upi = len(intel.upiIds) > 0
        has_phone = len(intel.phoneNumbers) > 0
        has_bank = len(intel.bankAccounts) > 0
        has_link = len(intel.phishingLinks) > 0
        
        # Build questions for missing intel
        missing_questions = []
        if not has_phone:
            missing_questions.append("What is the best number to reach you?")
            missing_questions.append("Can you give me your phone number?")
        if not has_upi:
            missing_questions.append("What is your UPI ID?")
            missing_questions.append("If I need to pay, what UPI?")
        if not has_bank:
            missing_questions.append("What is your bank account number?")
            missing_questions.append("Can you give account details?")
        if not has_link:
            missing_questions.append("What is your email address?")
            missing_questions.append("Can you email me the details?")
        
        # Generic engagement responses (vary by turn)
        generic_responses = [
            "I see, can you explain more?",
            "I'm interested, tell me more.",
            "What do I need to do?",
            "This sounds important.",
            "I want to understand better.",
        ]
        
        response_base = generic_responses[turn % len(generic_responses)]
        
        if missing_questions:
            question = missing_questions[turn % len(missing_questions)]
            return f"{response_base} {question}"
        else:
            return f"{response_base} What are the next steps?"
    
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
