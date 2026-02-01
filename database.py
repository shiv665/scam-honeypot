"""
MongoDB Database Handler for Scam Honeypot System
Stores full conversation history and session data
"""
import os
from datetime import datetime
from typing import Optional, List, Dict, Any
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from dotenv import load_dotenv

load_dotenv()

# MongoDB Configuration
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "scam_honeypot")


class DatabaseHandler:
    """
    MongoDB handler for persistent storage of conversations and sessions.
    Supports full conversation history storage for multiple concurrent users.
    """
    
    def __init__(self):
        self.client: Optional[MongoClient] = None
        self.db = None
        self.connected = False
        self._connect()
    
    def _connect(self):
        """Establish MongoDB connection"""
        try:
            self.client = MongoClient(
                MONGODB_URI,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000
            )
            # Test connection
            self.client.admin.command('ping')
            self.db = self.client[MONGODB_DB_NAME]
            self.connected = True
            print(f"✅ MongoDB connected: {MONGODB_DB_NAME}")
            
            # Create indexes for better query performance
            self._create_indexes()
            
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            print(f"⚠️ MongoDB not available: {e}")
            print("📝 Using in-memory storage as fallback")
            self.connected = False
        except Exception as e:
            print(f"⚠️ MongoDB connection error: {e}")
            self.connected = False
    
    def _create_indexes(self):
        """Create indexes for efficient queries"""
        if self.db is not None:
            # Index on session_id for fast session lookups
            self.db.sessions.create_index("session_id", unique=True)
            self.db.conversations.create_index("session_id")
            self.db.conversations.create_index([("session_id", 1), ("timestamp", 1)])
    
    def is_connected(self) -> bool:
        """Check if MongoDB is connected"""
        return self.connected and self.db is not None
    
    # ==================== SESSION OPERATIONS ====================
    
    def save_session(self, session_data: Dict[str, Any]) -> bool:
        """
        Save or update session state in MongoDB
        
        Args:
            session_data: Session state dictionary
            
        Returns:
            True if saved successfully
        """
        if not self.is_connected():
            return False
        
        try:
            session_id = session_data.get("session_id")
            session_data["updated_at"] = datetime.now()
            
            # Convert any nested objects to dicts
            if "detection_result" in session_data and session_data["detection_result"]:
                if hasattr(session_data["detection_result"], "model_dump"):
                    session_data["detection_result"] = session_data["detection_result"].model_dump()
            
            if "extracted_intelligence" in session_data:
                if hasattr(session_data["extracted_intelligence"], "model_dump"):
                    session_data["extracted_intelligence"] = session_data["extracted_intelligence"].model_dump()
            
            self.db.sessions.update_one(
                {"session_id": session_id},
                {"$set": session_data},
                upsert=True
            )
            return True
        except Exception as e:
            print(f"Error saving session: {e}")
            return False
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve session state from MongoDB
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            Session data dict or None
        """
        if not self.is_connected():
            return None
        
        try:
            session = self.db.sessions.find_one({"session_id": session_id})
            if session:
                # Remove MongoDB's _id field
                session.pop("_id", None)
            return session
        except Exception as e:
            print(f"Error getting session: {e}")
            return None
    
    def delete_session(self, session_id: str) -> bool:
        """Delete a session and its conversation history"""
        if not self.is_connected():
            return False
        
        try:
            self.db.sessions.delete_one({"session_id": session_id})
            self.db.conversations.delete_many({"session_id": session_id})
            return True
        except Exception as e:
            print(f"Error deleting session: {e}")
            return False
    
    # ==================== CONVERSATION OPERATIONS ====================
    
    def save_message(self, session_id: str, message: Dict[str, Any], 
                     sender_role: str = "scammer") -> bool:
        """
        Save a single message to conversation history
        
        Args:
            session_id: Session identifier
            message: Message data (sender, text, timestamp)
            sender_role: 'scammer' or 'agent'
            
        Returns:
            True if saved successfully
        """
        if not self.is_connected():
            return False
        
        try:
            doc = {
                "session_id": session_id,
                "sender": message.get("sender", sender_role),
                "text": message.get("text", ""),
                "timestamp": message.get("timestamp", datetime.now()),
                "created_at": datetime.now()
            }
            self.db.conversations.insert_one(doc)
            return True
        except Exception as e:
            print(f"Error saving message: {e}")
            return False
    
    def save_conversation_turn(self, session_id: str, 
                                scammer_message: Dict[str, Any],
                                agent_reply: str) -> bool:
        """
        Save a complete conversation turn (scammer message + agent reply)
        
        Args:
            session_id: Session identifier
            scammer_message: Incoming scammer message
            agent_reply: Agent's response
            
        Returns:
            True if saved successfully
        """
        if not self.is_connected():
            return False
        
        try:
            now = datetime.now()
            
            # Save scammer's message
            self.db.conversations.insert_one({
                "session_id": session_id,
                "sender": "scammer",
                "text": scammer_message.get("text", ""),
                "timestamp": scammer_message.get("timestamp", now),
                "created_at": now
            })
            
            # Save agent's reply
            self.db.conversations.insert_one({
                "session_id": session_id,
                "sender": "agent",
                "text": agent_reply,
                "timestamp": now,
                "created_at": now
            })
            
            return True
        except Exception as e:
            print(f"Error saving conversation turn: {e}")
            return False
    
    def get_conversation_history(self, session_id: str, 
                                  limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve full conversation history for a session
        
        Args:
            session_id: Session identifier
            limit: Maximum messages to retrieve
            
        Returns:
            List of messages in chronological order
        """
        if not self.is_connected():
            return []
        
        try:
            cursor = self.db.conversations.find(
                {"session_id": session_id}
            ).sort("timestamp", 1).limit(limit)
            
            messages = []
            for doc in cursor:
                doc.pop("_id", None)
                doc.pop("created_at", None)
                messages.append(doc)
            
            return messages
        except Exception as e:
            print(f"Error getting conversation history: {e}")
            return []
    
    def get_message_count(self, session_id: str) -> int:
        """Get total number of messages in a session"""
        if not self.is_connected():
            return 0
        
        try:
            return self.db.conversations.count_documents({"session_id": session_id})
        except Exception as e:
            print(f"Error counting messages: {e}")
            return 0
    
    # ==================== ANALYTICS & REPORTING ====================
    
    def get_all_sessions(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all sessions with summary info"""
        if not self.is_connected():
            return []
        
        try:
            cursor = self.db.sessions.find().sort("updated_at", -1).limit(limit)
            sessions = []
            for doc in cursor:
                doc.pop("_id", None)
                sessions.append(doc)
            return sessions
        except Exception as e:
            print(f"Error getting sessions: {e}")
            return []
    
    def get_scam_sessions(self) -> List[Dict[str, Any]]:
        """Get all sessions where scam was detected"""
        if not self.is_connected():
            return []
        
        try:
            cursor = self.db.sessions.find({"scam_detected": True})
            sessions = []
            for doc in cursor:
                doc.pop("_id", None)
                sessions.append(doc)
            return sessions
        except Exception as e:
            print(f"Error getting scam sessions: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics"""
        if not self.is_connected():
            return {"error": "Database not connected"}
        
        try:
            total_sessions = self.db.sessions.count_documents({})
            scam_sessions = self.db.sessions.count_documents({"scam_detected": True})
            total_messages = self.db.conversations.count_documents({})
            callbacks_sent = self.db.sessions.count_documents({"callback_sent": True})
            
            return {
                "total_sessions": total_sessions,
                "scam_sessions": scam_sessions,
                "total_messages": total_messages,
                "callbacks_sent": callbacks_sent,
                "scam_detection_rate": round(scam_sessions / max(total_sessions, 1) * 100, 2)
            }
        except Exception as e:
            return {"error": str(e)}
    
    def close(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            print("🔌 MongoDB connection closed")


# Singleton instance
db_handler = DatabaseHandler()
