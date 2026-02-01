"""
Intelligence Extraction Module
Extracts actionable intelligence from scam conversations
Matches GUVI callback format
"""
import re
from typing import List, Set
from models import Message, ExtractedIntelligence


class IntelligenceExtractor:
    """
    Extracts actionable intelligence from conversations including:
    - Bank account numbers (bankAccounts)
    - UPI IDs (upiIds)
    - Phone numbers (phoneNumbers)
    - Phishing links (phishingLinks)
    - Suspicious keywords (suspiciousKeywords)
    """
    
    def __init__(self):
        # Regex patterns for extraction
        self.patterns = {
            "bank_account": [
                re.compile(r'\b\d{9,18}\b'),
                re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
            ],
            "upi_id": [
                re.compile(r'\b[a-zA-Z0-9._-]+@[a-zA-Z]{2,}\b'),
                re.compile(r'\b[a-zA-Z0-9._-]+@(ybl|paytm|okaxis|okhdfcbank|oksbi|upi|apl|axl|ibl|sbi|icici|hdfc)\b', re.IGNORECASE),
            ],
            "phone_number": [
                re.compile(r'\+91[\s-]?\d{10}\b'),
                re.compile(r'\b[6-9]\d{9}\b'),
                re.compile(r'\b\d{3}[\s-]?\d{3}[\s-]?\d{4}\b'),
            ],
            "url": [
                re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
                re.compile(r'www\.[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
                re.compile(r'\b[a-zA-Z0-9-]+\.(com|in|org|net|xyz|top|click|loan|co\.in|io)[/\w.-]*\b', re.IGNORECASE),
            ],
        }
        
        # Suspicious keywords to detect
        self.suspicious_keywords = [
            'urgent', 'immediately', 'verify now', 'account blocked', 'suspended',
            'otp', 'pin', 'cvv', 'password', 'bank', 'transfer', 'payment',
            'verify', 'kyc', 'blocked', 'suspended', 'arrest', 'police',
            'legal action', 'court', 'complaint', 'fine', 'penalty',
            'lottery', 'prize', 'winner', 'reward', 'cashback', 'refund',
            'click here', 'download', 'install', 'anydesk', 'teamviewer',
            'invest', 'profit', 'earning', 'scheme', 'offer', 'limited time',
            'last chance', 'expire', 'deadline', 'today only'
        ]
    
    def extract(self, messages: List[Message]) -> ExtractedIntelligence:
        """
        Extract intelligence from a list of messages.
        
        Args:
            messages: List of conversation messages
            
        Returns:
            ExtractedIntelligence with all extracted data
        """
        intelligence = ExtractedIntelligence()
        
        all_text = ""
        for message in messages:
            # Check sender value - handles both enum and string comparisons
            sender_value = message.sender.value if hasattr(message.sender, 'value') else str(message.sender)
            if sender_value == "scammer":
                text = message.text
                all_text += " " + text
                
                # Extract various data types
                intelligence.bankAccounts.extend(self._extract_bank_accounts(text))
                intelligence.upiIds.extend(self._extract_upi_ids(text))
                intelligence.phoneNumbers.extend(self._extract_phone_numbers(text))
                intelligence.phishingLinks.extend(self._extract_urls(text))
        
        # Remove duplicates while preserving order
        intelligence.bankAccounts = list(dict.fromkeys(intelligence.bankAccounts))
        intelligence.upiIds = list(dict.fromkeys(intelligence.upiIds))
        intelligence.phoneNumbers = list(dict.fromkeys(intelligence.phoneNumbers))
        intelligence.phishingLinks = list(dict.fromkeys(intelligence.phishingLinks))
        
        # Extract suspicious keywords
        intelligence.suspiciousKeywords = self._extract_keywords(all_text)
        
        return intelligence
    
    def extract_from_single_message(self, message: Message) -> ExtractedIntelligence:
        """Extract intelligence from a single message"""
        return self.extract([message])
    
    def _extract_bank_accounts(self, text: str) -> List[str]:
        """Extract potential bank account numbers"""
        accounts = set()
        for pattern in self.patterns["bank_account"]:
            matches = pattern.findall(text)
            for match in matches:
                clean_match = re.sub(r'[\s-]', '', match)
                if len(clean_match) >= 9 and len(clean_match) <= 18:
                    if not (len(clean_match) == 10 and clean_match[0] in '6789'):
                        accounts.add(clean_match)
        return list(accounts)
    
    def _extract_upi_ids(self, text: str) -> List[str]:
        """Extract UPI IDs"""
        upi_ids = set()
        for pattern in self.patterns["upi_id"]:
            matches = pattern.findall(text)
            for match in matches:
                if isinstance(match, tuple):
                    match = '@'.join(match) if len(match) > 1 else match[0]
                if '@' in str(match) and not str(match).endswith('.com'):
                    upi_ids.add(str(match).lower())
        return list(upi_ids)
    
    def _extract_phone_numbers(self, text: str) -> List[str]:
        """Extract phone numbers"""
        numbers = set()
        for pattern in self.patterns["phone_number"]:
            matches = pattern.findall(text)
            for match in matches:
                clean_number = re.sub(r'[\s-]', '', match)
                if len(clean_number) >= 10:
                    # Format with +91 prefix
                    if not clean_number.startswith('+'):
                        clean_number = '+91' + clean_number[-10:]
                    numbers.add(clean_number)
        return list(numbers)
    
    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs and phishing links"""
        urls = set()
        for pattern in self.patterns["url"]:
            matches = pattern.findall(text)
            for match in matches:
                url = match.rstrip('.,;:!?')
                if len(url) > 5:
                    urls.add(url)
        return list(urls)
    
    def _extract_keywords(self, text: str) -> List[str]:
        """Extract suspicious keywords from text"""
        found_keywords = set()
        text_lower = text.lower()
        
        for keyword in self.suspicious_keywords:
            if keyword in text_lower:
                found_keywords.add(keyword)
        
        return list(found_keywords)
    
    def identify_tactics(self, text: str) -> List[str]:
        """Identify scam tactics used in conversation"""
        tactics = []
        text_lower = text.lower()
        
        tactic_patterns = {
            "urgency": r'\b(urgent|immediately|right now|within\s*\d+|expire|deadline|hurry)\b',
            "fear": r'\b(arrest|legal|police|court|block|suspend|freeze|penalty|action)\b',
            "impersonation": r'\b(bank|rbi|cbi|government|customer\s*care|amazon|flipkart|microsoft|support)\b',
            "reward": r'\b(won|winner|prize|lottery|cashback|reward|gift|congratulations)\b',
            "pressure": r'\b(last chance|final|today only|limited time|limited slots|now or never)\b',
            "investment": r'\b(invest|profit|earning|double|guaranteed|returns|scheme)\b',
            "payment_request": r'\b(transfer|send|pay|upi|account|otp|pin|cvv)\b',
        }
        
        for tactic, pattern in tactic_patterns.items():
            if re.search(pattern, text_lower, re.IGNORECASE):
                tactics.append(tactic)
        
        return tactics
    
    def merge_intelligence(self, intel1: ExtractedIntelligence, intel2: ExtractedIntelligence) -> ExtractedIntelligence:
        """Merge two intelligence objects"""
        return ExtractedIntelligence(
            bankAccounts=list(set(intel1.bankAccounts + intel2.bankAccounts)),
            upiIds=list(set(intel1.upiIds + intel2.upiIds)),
            phoneNumbers=list(set(intel1.phoneNumbers + intel2.phoneNumbers)),
            phishingLinks=list(set(intel1.phishingLinks + intel2.phishingLinks)),
            suspiciousKeywords=list(set(intel1.suspiciousKeywords + intel2.suspiciousKeywords)),
        )


# Singleton instance
intelligence_extractor = IntelligenceExtractor()
