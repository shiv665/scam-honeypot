"""
Groq LLM Handler for Scam Honeypot System
Uses Groq's fast inference API with Llama 3.1 for intelligent responses
"""
import os
from typing import List, Optional
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")


class GroqHandler:
    """
    Handles LLM-based response generation using Groq's fast API.
    Groq provides very fast inference with Llama 3.1 models.
    """
    
    def __init__(self):
        self.client = None
        self.model = GROQ_MODEL
        self._initialized = False
        self._initialize()
    
    def _initialize(self):
        """Initialize the Groq client"""
        if not GROQ_API_KEY:
            print("⚠️ GROQ_API_KEY not set - using rule-based responses")
            return
        
        try:
            self.client = Groq(api_key=GROQ_API_KEY)
            self._initialized = True
            print(f"✅ Groq LLM initialized with model: {self.model}")
        except Exception as e:
            print(f"⚠️ Failed to initialize Groq: {e}")
            self._initialized = False
    
    def is_available(self) -> bool:
        """Check if Groq is properly configured and available"""
        return self._initialized and self.client is not None
    
    def generate_response(self, 
                          scammer_message: str,
                          conversation_history: List,
                          detection_result,
                          session) -> Optional[str]:
        """
        Generate a human-like response to engage the scammer.
        
        Args:
            scammer_message: The latest message from the scammer
            conversation_history: Previous messages in the conversation
            detection_result: Scam detection analysis
            session: Current session state
            
        Returns:
            Generated response string or None if generation fails
        """
        if not self.is_available():
            return None
        
        try:
            # Build the system prompt for the honeypot agent
            system_prompt = self._build_system_prompt(detection_result, session)
            
            # Build conversation messages
            messages = self._build_messages(
                system_prompt, 
                scammer_message, 
                conversation_history
            )
            
            # Generate response using Groq
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=150,
                temperature=0.8,
                top_p=0.9,
            )
            
            reply = response.choices[0].message.content.strip()
            
            # Clean up the response
            reply = self._clean_response(reply)
            
            return reply
            
        except Exception as e:
            print(f"Groq generation error: {e}")
            return None
    
    def _build_system_prompt(self, detection_result, session) -> str:
        """Build the system prompt for the agent - intel-aware to avoid repetition"""
        
        scam_type = detection_result.scam_type if detection_result else "unknown"
        turn_count = session.turn_count if session else 0
        intel = session.extracted_intelligence if session else None
        
        # Check what intel we already have
        has_phone = intel and len(intel.phoneNumbers) > 0
        has_upi = intel and len(intel.upiIds) > 0
        has_bank = intel and len(intel.bankAccounts) > 0
        has_link = intel and len(intel.phishingLinks) > 0
        
        # Build missing intel list
        still_need = []
        if not has_phone:
            still_need.append("PHONE NUMBER or CALLBACK NUMBER")
        if not has_upi:
            still_need.append("UPI ID")
        if not has_bank:
            still_need.append("BANK ACCOUNT NUMBER")
        if not has_link:
            still_need.append("WEBSITE LINK or EMAIL ID")
        
        # Build collected intel list
        collected = []
        if has_phone:
            collected.append(f"Phone: {intel.phoneNumbers[0]}")
        if has_upi:
            collected.append(f"UPI: {intel.upiIds[0]}")
        if has_bank:
            collected.append(f"Bank: {intel.bankAccounts[0]}")
        if has_link:
            collected.append(f"Link/Email: {intel.phishingLinks[0]}")
        
        base_prompt = """You are a regular Indian person (age 35-55) who received this call/message. 
You're NOT a bot - you're a real human having a natural conversation.

ABSOLUTE RULES - FOLLOW STRICTLY:
1. NEVER repeat the same question or similar phrasing - CRITICAL! Read conversation history!
2. NEVER ask for something you already have (see COLLECTED INTEL below)
3. Keep responses to 1-2 short sentences MAX
4. NEVER reveal you suspect it's a scam
5. Each response MUST be completely different from ALL previous responses

"""
        # Add collected intel info
        if collected:
            base_prompt += f"\nCOLLECTED INTEL (DO NOT ASK FOR THESE AGAIN): {', '.join(collected)}\n"
        
        # Add what we still need
        if still_need:
            base_prompt += f"\nSTILL NEED TO COLLECT: {', '.join(still_need)}\n"
            base_prompt += "ASK FOR ONE OF THESE in your response!\n"
        else:
            base_prompt += "\nALL INTEL COLLECTED! Just keep engaging naturally. Ask about office address, documents, or next steps.\n"
        
        # Add variety instructions based on turn
        variety_options = [
            ("office address", "What is your office address? I'll visit in person."),
            ("supervisor", "Can I speak with your supervisor or manager?"),
            ("employee ID", "What is your employee ID number?"),
            ("documents", "What documents should I bring?"),
            ("branch", "Which branch are you calling from?"),
            ("proof", "Can you send me some proof or official notice?"),
            ("callback", "What number can I call you back on?"),
            ("email", "What is your official email ID?"),
            ("website", "What is the official website link?"),
            ("WhatsApp", "Give me your WhatsApp number, I'll message you."),
        ]
        
        # Pick 3 different options based on turn to suggest
        options_to_suggest = []
        for i in range(3):
            idx = (turn_count + i) % len(variety_options)
            options_to_suggest.append(variety_options[idx][1])
        
        base_prompt += f"\nVARIETY OPTIONS (pick ONE, not the same as last turn):\n"
        for opt in options_to_suggest:
            base_prompt += f"- {opt}\n"
        
        # Add scam-specific guidance (without specific phrases to repeat)
        scam_context = ""
        if scam_type == "phishing":
            scam_context = "\n\nSCAM TYPE: OTP/PIN request. Deflect by asking for alternative verification. DO NOT keep asking about OTP."
        elif scam_type == "impersonation_threat":
            scam_context = "\n\nSCAM TYPE: Legal threat. Ask for case details, court name, or FIR copy."
        elif scam_type == "lottery_scam":
            scam_context = "\n\nSCAM TYPE: Prize scam. Ask for company website or official verification."
        elif scam_type == "payment_fraud":
            scam_context = "\n\nSCAM TYPE: Payment. Ask for official payment portal or bank verification."
        
        return base_prompt + scam_context
    
    def _build_messages(self, system_prompt: str, 
                        scammer_message: str,
                        conversation_history: List) -> List[dict]:
        """Build the messages array for the API call"""
        
        messages = [{"role": "system", "content": system_prompt}]
        
        # Add conversation history (last 6 messages max)
        recent_history = conversation_history[-6:] if len(conversation_history) > 6 else conversation_history
        
        for msg in recent_history:
            role = "assistant" if msg.sender.value == "user" else "user"
            content = msg.text if hasattr(msg, 'text') else str(msg)
            messages.append({"role": role, "content": content})
        
        # Add current scammer message
        messages.append({"role": "user", "content": scammer_message})
        
        return messages
    
    def _clean_response(self, response: str) -> str:
        """Clean and validate the generated response"""
        # Remove any role-play markers
        response = response.replace("*", "").strip()
        
        # Remove quotes if the whole response is quoted
        if response.startswith('"') and response.endswith('"'):
            response = response[1:-1]
        
        # Ensure response isn't too long
        if len(response) > 200:
            # Find a natural break point
            sentences = response.split('.')
            if len(sentences) > 1:
                response = sentences[0] + '.'
        
        # Ensure it doesn't reveal detection
        suspicious_phrases = [
            "i know this is a scam",
            "you are a scammer",
            "this is fraud",
            "i'm calling the police",
            "reported you"
        ]
        
        for phrase in suspicious_phrases:
            if phrase in response.lower():
                return "I don't understand. Can you explain again?"
        
        return response


# Singleton instance
groq_handler = GroqHandler()
