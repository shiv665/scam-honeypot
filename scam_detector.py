"""
Scam Detection Module
Analyzes messages to detect scam/fraudulent intent
"""
import re
from typing import List, Tuple
from models import Message, ScamDetectionResult, ScamIndicator
from config import SCAM_KEYWORDS, SUSPICIOUS_URL_PATTERNS, SCAM_CONFIDENCE_THRESHOLD


class ScamDetector:
    """
    Detects scam intent in messages using pattern matching,
    keyword analysis, and behavioral indicators.
    """
    
    def __init__(self):
        self.scam_keywords = SCAM_KEYWORDS
        self.url_patterns = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_URL_PATTERNS]
        self.confidence_threshold = SCAM_CONFIDENCE_THRESHOLD
    
    def analyze(self, message: Message, conversation_history: List[Message] = None) -> ScamDetectionResult:
        """
        Analyze a message for scam indicators.
        
        Args:
            message: The message to analyze
            conversation_history: Previous messages for context
            
        Returns:
            ScamDetectionResult with detection details
        """
        indicators = []
        total_confidence = 0.0
        
        text = message.text.lower()
        
        # Check for scam keywords
        keyword_indicators, keyword_confidence = self._detect_keywords(text)
        indicators.extend(keyword_indicators)
        total_confidence += keyword_confidence
        
        # Check for suspicious URLs
        url_indicators, url_confidence = self._detect_suspicious_urls(message.text)
        indicators.extend(url_indicators)
        total_confidence += url_confidence
        
        # Check for financial data requests
        financial_indicators, financial_confidence = self._detect_financial_requests(text)
        indicators.extend(financial_indicators)
        total_confidence += financial_confidence
        
        # Check for urgency patterns
        urgency_indicators, urgency_confidence = self._detect_urgency(text)
        indicators.extend(urgency_indicators)
        total_confidence += urgency_confidence
        
        # Check for threat patterns
        threat_indicators, threat_confidence = self._detect_threats(text)
        indicators.extend(threat_indicators)
        total_confidence += threat_confidence
        
        # Analyze conversation context if available
        if conversation_history:
            context_indicators, context_confidence = self._analyze_context(conversation_history)
            indicators.extend(context_indicators)
            total_confidence += context_confidence
        
        # Normalize confidence (cap at 1.0)
        final_confidence = min(total_confidence, 1.0)
        
        # Determine scam type and risk level
        scam_type = self._determine_scam_type(indicators)
        risk_level = self._determine_risk_level(final_confidence)
        
        return ScamDetectionResult(
            is_scam=final_confidence >= self.confidence_threshold,
            confidence=round(final_confidence, 2),
            indicators=indicators,
            scam_type=scam_type,
            risk_level=risk_level
        )
    
    def _detect_keywords(self, text: str) -> Tuple[List[ScamIndicator], float]:
        """Detect scam keywords in text"""
        indicators = []
        confidence = 0.0
        
        for keyword, weight in self.scam_keywords.items():
            if keyword in text:
                indicators.append(ScamIndicator(
                    indicator_type="keyword",
                    value=keyword,
                    confidence=weight,
                    context=f"Found scam keyword: '{keyword}'"
                ))
                confidence += weight
        
        return indicators, min(confidence, 0.6)  # Cap keyword contribution
    
    def _detect_suspicious_urls(self, text: str) -> Tuple[List[ScamIndicator], float]:
        """Detect suspicious URLs and links"""
        indicators = []
        confidence = 0.0
        
        # Find all URLs in text
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+|'
            r'www\.(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        
        urls = url_pattern.findall(text)
        
        for url in urls:
            for pattern in self.url_patterns:
                if pattern.search(url):
                    indicators.append(ScamIndicator(
                        indicator_type="suspicious_url",
                        value=url,
                        confidence=0.5,
                        context="URL matches suspicious pattern"
                    ))
                    confidence += 0.3
                    break
            else:
                # Any URL in unsolicited message is mildly suspicious
                indicators.append(ScamIndicator(
                    indicator_type="url",
                    value=url,
                    confidence=0.2,
                    context="External URL detected"
                ))
                confidence += 0.1
        
        return indicators, min(confidence, 0.5)
    
    def _detect_financial_requests(self, text: str) -> Tuple[List[ScamIndicator], float]:
        """Detect requests for financial information"""
        indicators = []
        confidence = 0.0
        
        patterns = {
            r'\b\d{9,18}\b': ("account_number", 0.4, "Possible bank account number"),
            r'\b[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\b(?=.*upi|.*pay)': ("upi_request", 0.5, "UPI ID request detected"),
            r'\botp\b|\bone.?time.?password\b': ("otp_request", 0.6, "OTP request detected"),
            r'\bcvv\b|\bcard.?verification\b': ("cvv_request", 0.7, "CVV request detected"),
            r'\bpin\b.*\b(enter|share|send)\b|\b(enter|share|send)\b.*\bpin\b': ("pin_request", 0.6, "PIN request detected"),
            r'\b(share|send|give).*\b(details|number|info)\b': ("info_request", 0.3, "Information request detected"),
        }
        
        for pattern, (indicator_type, weight, context) in patterns.items():
            if re.search(pattern, text, re.IGNORECASE):
                indicators.append(ScamIndicator(
                    indicator_type=indicator_type,
                    value=pattern,
                    confidence=weight,
                    context=context
                ))
                confidence += weight
        
        return indicators, min(confidence, 0.7)
    
    def _detect_urgency(self, text: str) -> Tuple[List[ScamIndicator], float]:
        """Detect urgency and pressure tactics"""
        indicators = []
        confidence = 0.0
        
        urgency_phrases = [
            (r'\b(act|do it|respond)\s*(now|immediately|fast|quick)\b', 0.4),
            (r'\b(within|in)\s*\d+\s*(hour|minute|day)s?\b', 0.3),
            (r'\blast\s*(chance|warning|notice)\b', 0.4),
            (r'\b(expire|expiring|expired)\b', 0.3),
            (r'\b(urgent|urgently|emergency)\b', 0.4),
            (r'\bdon\'?t\s*(delay|wait|ignore)\b', 0.3),
        ]
        
        for pattern, weight in urgency_phrases:
            if re.search(pattern, text, re.IGNORECASE):
                indicators.append(ScamIndicator(
                    indicator_type="urgency",
                    value=pattern,
                    confidence=weight,
                    context="Urgency/pressure tactic detected"
                ))
                confidence += weight
        
        return indicators, min(confidence, 0.5)
    
    def _detect_threats(self, text: str) -> Tuple[List[ScamIndicator], float]:
        """Detect threat-based manipulation"""
        indicators = []
        confidence = 0.0
        
        threat_phrases = [
            (r'\b(arrest|arrested|jail|prison)\b', 0.5),
            (r'\b(legal|court|lawsuit|sue)\s*(action|case|notice)\b', 0.5),
            (r'\b(police|cbi|ed|cyber\s*cell)\b', 0.4),
            (r'\b(block|blocked|suspend|suspended|freeze|frozen)\b.*\b(account|card|number)\b', 0.5),
            (r'\b(penalty|fine|charge)\b.*\b(pay|amount|₹|\$)\b', 0.4),
            (r'\b(cancel|terminate|deactivate)\b', 0.3),
        ]
        
        for pattern, weight in threat_phrases:
            if re.search(pattern, text, re.IGNORECASE):
                indicators.append(ScamIndicator(
                    indicator_type="threat",
                    value=pattern,
                    confidence=weight,
                    context="Threat/fear tactic detected"
                ))
                confidence += weight
        
        return indicators, min(confidence, 0.6)
    
    def _analyze_context(self, history: List[Message]) -> Tuple[List[ScamIndicator], float]:
        """Analyze conversation context for scam patterns"""
        indicators = []
        confidence = 0.0
        
        # Check for escalating requests pattern
        request_count = 0
        for msg in history:
            if msg.sender == "scammer":
                text = msg.text.lower()
                if any(word in text for word in ["send", "share", "give", "provide", "transfer"]):
                    request_count += 1
        
        if request_count >= 2:
            indicators.append(ScamIndicator(
                indicator_type="pattern",
                value="escalating_requests",
                confidence=0.3,
                context=f"Multiple requests detected ({request_count} times)"
            ))
            confidence += 0.2
        
        return indicators, confidence
    
    def _determine_scam_type(self, indicators: List[ScamIndicator]) -> str:
        """Determine the type of scam based on indicators"""
        indicator_types = [i.indicator_type for i in indicators]
        
        if "otp_request" in indicator_types or "cvv_request" in indicator_types:
            return "phishing"
        elif "threat" in [i.indicator_type for i in indicators]:
            return "impersonation_threat"
        elif any("lottery" in i.value or "prize" in i.value or "winner" in i.value 
                 for i in indicators if i.indicator_type == "keyword"):
            return "lottery_scam"
        elif any("job" in i.value or "earning" in i.value 
                 for i in indicators if i.indicator_type == "keyword"):
            return "job_scam"
        elif "suspicious_url" in indicator_types:
            return "phishing_link"
        elif any("kyc" in i.value or "verify" in i.value 
                 for i in indicators if i.indicator_type == "keyword"):
            return "kyc_fraud"
        else:
            return "generic_scam"
    
    def _determine_risk_level(self, confidence: float) -> str:
        """Determine risk level based on confidence score"""
        if confidence >= 0.8:
            return "critical"
        elif confidence >= 0.6:
            return "high"
        elif confidence >= 0.4:
            return "medium"
        else:
            return "low"


# Singleton instance
scam_detector = ScamDetector()
