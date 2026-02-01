"""
Main Honeypot Handler
Orchestrates scam detection, agent engagement, and intelligence extraction
"""
import json
from typing import Dict, Any
from models import (
    IncomingRequest, Message, AgentResponse, 
    SessionState, ExtractedIntelligence
)
from scam_detector import scam_detector
from intelligence_extractor import intelligence_extractor
from agent import conversation_agent
from guvi_callback import guvi_callback


class HoneypotHandler:
    """
    Main handler that orchestrates the honeypot system.
    Coordinates between scam detection, agent responses, and intelligence extraction.
    """
    
    def __init__(self):
        self.detector = scam_detector
        self.extractor = intelligence_extractor
        self.agent = conversation_agent
    
    def process_message(self, request: IncomingRequest) -> AgentResponse:
        """
        Process an incoming message and generate an appropriate response.
        
        This is the main entry point for the honeypot system.
        
        Args:
            request: The incoming message request
            
        Returns:
            AgentResponse with the reply message
        """
        # Get or create session state
        session = self.agent.get_or_create_session(request.sessionId)
        
        # Analyze the message for scam indicators
        detection_result = self.detector.analyze(
            request.message,
            request.conversationHistory
        )
        
        # Extract intelligence from all messages
        all_messages = request.conversationHistory + [request.message]
        intelligence = self.extractor.extract(all_messages)
        
        # Update session state (this increments turn_count)
        # Pass first_message for persona selection on turn 0
        session = self.agent.update_session(
            request.sessionId,
            detection_result,
            intelligence,
            first_message=request.message.text  # For dynamic persona selection
        )
        
        # Track total messages as 2x turn_count (scammer msg + agent response per turn)
        session.total_messages = session.turn_count * 2
        
        # Save updated session to MongoDB
        if self.agent.db and self.agent.db.is_connected():
            self.agent.db.save_session(session.model_dump())
        
        # Generate contextual response
        reply = self.agent.generate_response(
            request.message,
            request.conversationHistory,
            detection_result,
            session
        )
        
        # Save conversation turn to MongoDB
        self.agent.save_conversation_turn(
            request.sessionId,
            request.message,
            reply
        )
        
        # Create and return response
        return AgentResponse(
            status="success",
            reply=reply
        )
    
    def process_raw_json(self, json_data: Dict[str, Any]) -> str:
        """
        Process raw JSON input and return JSON response string.
        
        Args:
            json_data: Raw JSON dictionary
            
        Returns:
            JSON string response
        """
        try:
            # Parse the incoming request
            request = IncomingRequest(**json_data)
            
            # Process and get response
            response = self.process_message(request)
            
            # Return as JSON string
            return response.model_dump_json()
        
        except Exception as e:
            # Return error response
            error_response = {
                "status": "error",
                "reply": "I'm sorry, I didn't understand that. Could you please repeat?"
            }
            return json.dumps(error_response)
    
    def get_session_intelligence(self, session_id: str) -> ExtractedIntelligence:
        """
        Get the extracted intelligence for a session.
        
        Args:
            session_id: The session identifier
            
        Returns:
            ExtractedIntelligence with all extracted data
        """
        session = self.agent.get_or_create_session(session_id)
        return session.extracted_intelligence
    
    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """
        Get a summary of the session for reporting.
        
        Args:
            session_id: The session identifier
            
        Returns:
            Dictionary with session summary
        """
        session = self.agent.get_or_create_session(session_id)
        
        # Generate agentNotes preview using stored tactics
        agent_notes = guvi_callback.generate_agent_notes(session, session.tactics_observed)
        
        return {
            "session_id": session_id,
            "scam_detected": session.scam_detected,
            "scam_type": session.detection_result.scam_type if session.detection_result else None,
            "confidence": session.detection_result.confidence if session.detection_result else 0,
            "risk_level": session.detection_result.risk_level if session.detection_result else "unknown",
            "persona": session.persona,  # Dynamic persona selected based on first message
            "tactics_observed": session.tactics_observed,  # Scam tactics identified
            "agent_notes": agent_notes,  # Preview of agentNotes for callback
            "turn_count": session.turn_count,
            "total_messages": session.total_messages,
            "callback_sent": session.callback_sent,
            "extracted_intelligence": {
                "bankAccounts": session.extracted_intelligence.bankAccounts,
                "upiIds": session.extracted_intelligence.upiIds,
                "phoneNumbers": session.extracted_intelligence.phoneNumbers,
                "phishingLinks": session.extracted_intelligence.phishingLinks,
                "suspiciousKeywords": session.extracted_intelligence.suspiciousKeywords,
            }
        }


# Singleton instance
honeypot_handler = HoneypotHandler()


def process_message(json_input: str) -> str:
    """
    Simple function interface for processing messages.
    
    Args:
        json_input: JSON string with the message data
        
    Returns:
        JSON string response
    """
    try:
        data = json.loads(json_input)
        return honeypot_handler.process_raw_json(data)
    except json.JSONDecodeError:
        return json.dumps({
            "status": "error",
            "reply": "I'm having trouble understanding. Can you please repeat?"
        })
