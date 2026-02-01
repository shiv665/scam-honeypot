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
        """Build the system prompt for the agent"""
        
        scam_type = detection_result.scam_type if detection_result else "unknown"
        turn_count = session.turn_count if session else 0
        
        base_prompt = """You are playing the role of a cautious but somewhat gullible Indian person who received a suspicious call/message. 
Your goal is to engage the scammer naturally while extracting their identity and payment details.

CRITICAL RULES:
1. NEVER reveal that you know this is a scam
2. Act confused, worried, and slightly trusting
3. Keep responses SHORT (1-2 sentences max)
4. Show emotions like concern, confusion, or willingness to help
5. Be polite but not overly formal

IMPORTANT - VARY YOUR QUESTIONS! Pick different questions each turn from these categories:
- Payment Details: "What UPI ID should I send money to?", "Which bank account should I transfer to?", "What's your Paytm/GPay number?"
- Verification: "Can you send me your official website link?", "What's the WhatsApp number for your department?"
- Identity: "What is your supervisor's name?", "Which branch are you calling from?", "What's your badge/registration number?"
- Process: "Can you SMS me the official process?", "Is there a form I need to fill online?", "Should I visit your office in person?"
- Documentation: "Can you email me the official notice?", "Where can I download the complaint copy?"

DO NOT keep asking the same question repeatedly. Each response should ask for DIFFERENT information."""

        # Adjust behavior based on conversation stage
        if turn_count <= 2:
            stage_prompt = "\n\nSTAGE: Initial confusion. Ask what this is about or why they are contacting you."
        elif turn_count <= 4:
            stage_prompt = "\n\nSTAGE: Getting worried. Ask for their WEBSITE LINK or WHATSAPP NUMBER to verify. Or ask which OFFICE you should visit."
        elif turn_count <= 6:
            stage_prompt = "\n\nSTAGE: Seeming to trust them. Ask for their UPI ID or BANK ACCOUNT where you should send verification fee. Or ask for PAYMENT LINK."
        elif turn_count <= 8:
            stage_prompt = "\n\nSTAGE: Almost complying. Ask for their SUPERVISOR'S CONTACT or the OFFICIAL WEBSITE to complete the process."
        else:
            stage_prompt = "\n\nSTAGE: Willing to help but need final details. Ask for their OFFICE ADDRESS or EMAIL to send documents. Or ask for PAYMENT DETAILS."
        
        # Add scam-specific context
        scam_context = ""
        if scam_type == "phishing":
            scam_context = "\n\nSCAM TYPE: They're asking for OTP/PIN. Ask WHY they need it and if you can verify on their OFFICIAL WEBSITE instead."
        elif scam_type == "impersonation_threat":
            scam_context = "\n\nSCAM TYPE: They're threatening legal action. Ask for CASE NUMBER, FIR COPY LINK, or which COURT this is from."
        elif scam_type == "lottery_scam":
            scam_context = "\n\nSCAM TYPE: Prize/lottery scam. Ask for the OFFICIAL LOTTERY WEBSITE or where to verify the WINNING NUMBER."
        elif scam_type == "payment_fraud":
            scam_context = "\n\nSCAM TYPE: Payment fraud. Act willing to pay but ask for their UPI ID, BANK ACCOUNT, or PAYMENT PORTAL LINK."
        
        return base_prompt + stage_prompt + scam_context
    
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
