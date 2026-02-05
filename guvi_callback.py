"""
GUVI Callback Handler
Sends final result to GUVI evaluation endpoint
"""
import aiohttp
import asyncio
from typing import Optional
from models import ExtractedIntelligence, GuviCallbackPayload, SessionState


GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"


class GuviCallbackHandler:
    """
    Handles sending final results to GUVI evaluation endpoint.
    This is mandatory for scoring.
    """
    
    def __init__(self):
        self.callback_url = GUVI_CALLBACK_URL
    
    async def send_callback(self, 
                            session_id: str,
                            scam_detected: bool,
                            total_messages: int,
                            intelligence: ExtractedIntelligence,
                            agent_notes: str) -> bool:
        """
        Send final result to GUVI evaluation endpoint.
        
        Args:
            session_id: Unique session identifier
            scam_detected: Whether scam was detected
            total_messages: Total messages exchanged
            intelligence: Extracted intelligence
            agent_notes: Summary of scammer behavior
            
        Returns:
            True if callback was successful
        """
        payload = GuviCallbackPayload(
            sessionId=session_id,
            scamDetected=scam_detected,
            totalMessagesExchanged=total_messages,
            extractedIntelligence=intelligence,
            agentNotes=agent_notes
        )
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.callback_url,
                    json=payload.model_dump(),
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        print(f"✅ GUVI callback successful for session: {session_id}")
                        return True
                    else:
                        print(f"⚠️ GUVI callback failed: {response.status}")
                        return False
        except Exception as e:
            print(f"❌ GUVI callback error: {e}")
            return False
    
    def send_callback_sync(self,
                           session_id: str,
                           scam_detected: bool,
                           total_messages: int,
                           intelligence: ExtractedIntelligence,
                           agent_notes: str) -> bool:
        """Synchronous version of send_callback"""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(
            self.send_callback(session_id, scam_detected, total_messages, intelligence, agent_notes)
        )
    
    def generate_agent_notes(self, session: SessionState, tactics: list) -> str:
        """
        Generate agent notes summarizing scammer behavior.
        Matches GUVI expected format like: "Scammer used urgency tactics and payment redirection"
        
        Args:
            session: Current session state
            tactics: List of observed tactics
            
        Returns:
            Summary string for agentNotes field
        """
        notes_parts = []
        
        # Map tactics to human-readable descriptions
        tactic_descriptions = {
            "urgency": "urgency tactics",
            "fear": "fear/threat tactics",
            "impersonation": "impersonation",
            "reward": "fake reward/prize claims",
            "pressure": "high-pressure tactics",
            "investment": "investment fraud tactics",
            "payment_request": "payment redirection"
        }
        
        # Describe tactics used
        if tactics:
            readable_tactics = [tactic_descriptions.get(t, t) for t in tactics]
            if len(readable_tactics) == 1:
                notes_parts.append(f"Scammer used {readable_tactics[0]}")
            else:
                notes_parts.append(f"Scammer used {', '.join(readable_tactics[:-1])} and {readable_tactics[-1]}")
        
        # Add intelligence-based observations
        intel = session.extracted_intelligence
        intel_actions = []
        
        if intel.upiIds:
            intel_actions.append("payment redirection via UPI")
        if intel.bankAccounts:
            intel_actions.append("bank account collection")
        if intel.phoneNumbers:
            intel_actions.append("phone number extraction")
        if intel.phishingLinks:
            intel_actions.append("phishing link distribution")
        
        if intel_actions:
            if notes_parts:
                notes_parts[0] += f" with {intel_actions[0]}"
                if len(intel_actions) > 1:
                    notes_parts.append(f"Also attempted: {', '.join(intel_actions[1:])}")
            else:
                notes_parts.append(f"Scammer attempted {', '.join(intel_actions)}")
        
        # Add scam type if available
        if session.detection_result and session.detection_result.scam_type:
            notes_parts.append(f"Identified as {session.detection_result.scam_type} scam")
        
        # Fallback
        if not notes_parts:
            notes_parts.append("Scammer engagement completed")
        
        return ". ".join(notes_parts)
    
    def should_trigger_callback(self, session: SessionState, min_turns: int = 3) -> bool:
        """
        Determine if callback should be triggered.
        
        Callback is triggered when:
        - Scam is detected
        - Turn count is EXACTLY 3, 6, or 10
        - OR all intel collected (phone, UPI, links, bank accounts)
        
        Args:
            session: Current session state
            min_turns: Minimum turns before first callback (default 3)
            
        Returns:
            True if callback should be sent
        """
        if not session.scam_detected:
            return False
        
        # Check if ALL key intelligence types are extracted (phone, UPI, links)
        intel = session.extracted_intelligence
        has_all_intel = (
            len(intel.bankAccounts) > 0 and
            len(intel.phoneNumbers) > 0 and
            len(intel.upiIds) > 0 and
            len(intel.phishingLinks) > 0
        )
        
        # Log what intel we have
        intel_summary = []
        if intel.phoneNumbers: intel_summary.append(f"phones:{len(intel.phoneNumbers)}")
        if intel.upiIds: intel_summary.append(f"upis:{len(intel.upiIds)}")
        if intel.phishingLinks: intel_summary.append(f"links:{len(intel.phishingLinks)}")
        if intel.bankAccounts: intel_summary.append(f"banks:{len(intel.bankAccounts)}")
        print(f"📊 Intel status: {', '.join(intel_summary) if intel_summary else 'none yet'} | Turn {session.turn_count}")
        
        # Callback triggers at SPECIFIC turns: 3, 6, 10
        callback_turns = [3, 6, 10]
        is_callback_turn = session.turn_count in callback_turns
        
        # Track last callback turn to avoid duplicate callbacks at same turn
        last_callback_turn = getattr(session, 'last_callback_turn', 0)
        
        # Trigger callback at specific turns (3, 6, 10)
        if is_callback_turn and session.turn_count > last_callback_turn:
            print(f"📤 Triggering callback at turn {session.turn_count}")
            return True
        
        # Also trigger if all intel collected and haven't sent callback with all intel yet
        if has_all_intel and not session.callback_had_all_intel:
            print(f"📤 Triggering callback - all intel collected!")
            return True
        
        return False


# Singleton instance
guvi_callback = GuviCallbackHandler()
