"""
FastAPI Application for Scam Honeypot System
REST API with authentication matching GUVI requirements
"""
from fastapi import FastAPI, HTTPException, Header, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
from contextlib import asynccontextmanager

from models import IncomingRequest, AgentResponse
from honeypot import honeypot_handler
from guvi_callback import guvi_callback
from config import API_HOST, API_PORT, API_KEY, MIN_ENGAGEMENT_TURNS


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for the FastAPI app"""
    print("🚀 Scam Honeypot System Starting...")
    print(f"📡 Listening on http://{API_HOST}:{API_PORT}")
    print(f"🔐 API Key authentication enabled")
    yield
    print("🛑 Scam Honeypot System Shutting Down...")


app = FastAPI(
    title="Scam Honeypot System",
    description="Autonomous AI Agent for scam detection and intelligence extraction",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


async def verify_api_key(x_api_key: Optional[str] = Header(None)):
    """Verify API key from request header"""
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Please provide x-api-key header."
        )
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=403,
            detail="Invalid API key"
        )
    return x_api_key


@app.get("/")
async def root():
    """Health check endpoint (no auth required)"""
    return {
        "status": "online",
        "service": "Scam Honeypot System",
        "version": "1.0.0"
    }


@app.get("/health")
async def health_check():
    """Detailed health check (no auth required)"""
    return {
        "status": "healthy",
        "components": {
            "detector": "operational",
            "agent": "operational",
            "extractor": "operational",
            "callback": "operational"
        }
    }


async def send_guvi_callback_if_ready(session_id: str):
    """Background task to send GUVI callback when ready"""
    session = honeypot_handler.agent.get_or_create_session(session_id)
    
    if guvi_callback.should_trigger_callback(session, MIN_ENGAGEMENT_TURNS):
        # Use tactics already observed and stored in session
        tactics = session.tactics_observed
        
        # Generate agent notes using stored tactics
        agent_notes = guvi_callback.generate_agent_notes(session, tactics)
        
        # Check if we have all intel for this callback
        intel = session.extracted_intelligence
        has_all_intel = (
            len(intel.bankAccounts) > 0 and
            len(intel.upiIds) > 0 and
            len(intel.phoneNumbers) > 0 and
            len(intel.phishingLinks) > 0
        )
        
        # Send callback
        success = await guvi_callback.send_callback(
            session_id=session.session_id,
            scam_detected=session.scam_detected,
            total_messages=session.total_messages,
            intelligence=session.extracted_intelligence,
            agent_notes=agent_notes
        )
        
        if success:
            session.callback_sent = True
            session.callback_had_all_intel = has_all_intel  # Track if this callback had all intel
            # Save to MongoDB to persist callback_sent status
            honeypot_handler.agent.session_states[session_id] = session
            if honeypot_handler.agent.db and honeypot_handler.agent.db.is_connected():
                honeypot_handler.agent.db.save_session(session.model_dump())


@app.post("/process", response_model=AgentResponse)
async def process_message(
    request: IncomingRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """
    Main endpoint for processing incoming messages.
    
    Requires: x-api-key header
    
    Analyzes the message for scam intent, engages with realistic responses,
    and extracts actionable intelligence.
    
    Returns: {"status": "success", "reply": "..."}
    """
    try:
        # Get session ID from either sessionId or session_id field
        session_id = request.get_session_id()
        
        response = honeypot_handler.process_message(request)
        
        # Schedule GUVI callback check in background
        background_tasks.add_task(send_guvi_callback_if_ready, session_id)
        
        return response
    except Exception as e:
        print(f"Error processing message: {e}")
        return AgentResponse(
            status="success",
            reply="I'm sorry, I didn't catch that. Could you please repeat?"
        )


@app.post("/analyze")
async def analyze_message(
    request: IncomingRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Analyze a message for scam indicators without engaging.
    Returns detailed detection results (for debugging).
    """
    try:
        from scam_detector import scam_detector
        result = scam_detector.analyze(request.message, request.conversationHistory)
        return result.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/session/{session_id}/intelligence")
async def get_intelligence(
    session_id: str,
    api_key: str = Depends(verify_api_key)
):
    """Get extracted intelligence for a session."""
    try:
        intelligence = honeypot_handler.get_session_intelligence(session_id)
        return intelligence.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/session/{session_id}/summary")
async def get_session_summary(
    session_id: str,
    api_key: str = Depends(verify_api_key)
):
    """Get complete session summary with detection results and intelligence."""
    try:
        summary = honeypot_handler.get_session_summary(session_id)
        return summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/session/{session_id}/history")
async def get_conversation_history(
    session_id: str,
    api_key: str = Depends(verify_api_key)
):
    """
    Get full conversation history from MongoDB.
    Returns all messages in chronological order.
    """
    try:
        history = honeypot_handler.agent.get_full_history(session_id)
        return {
            "session_id": session_id,
            "message_count": len(history),
            "messages": history
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats")
async def get_statistics(api_key: str = Depends(verify_api_key)):
    """Get overall statistics from MongoDB."""
    try:
        from database import db_handler
        if db_handler.is_connected():
            return db_handler.get_statistics()
        else:
            return {"error": "MongoDB not connected", "storage": "in-memory"}
    except Exception as e:
        return {"error": str(e)}


@app.post("/session/{session_id}/trigger-callback")
async def trigger_callback(
    session_id: str,
    api_key: str = Depends(verify_api_key)
):
    """
    Manually trigger GUVI callback for a session.
    Use this if automatic callback hasn't fired.
    """
    try:
        session = honeypot_handler.agent.get_or_create_session(session_id)
        
        if session.callback_sent:
            return {"status": "already_sent", "message": "Callback already sent for this session"}
        
        # Use tactics already observed and stored in session
        tactics = session.tactics_observed
        
        agent_notes = guvi_callback.generate_agent_notes(session, tactics)
        
        success = await guvi_callback.send_callback(
            session_id=session.session_id,
            scam_detected=session.scam_detected,
            total_messages=session.total_messages,
            intelligence=session.extracted_intelligence,
            agent_notes=agent_notes
        )
        
        if success:
            session.callback_sent = True
            return {"status": "success", "message": "Callback sent successfully"}
        else:
            return {"status": "failed", "message": "Failed to send callback"}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=API_HOST, port=API_PORT)
