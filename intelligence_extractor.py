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
                re.compile(r'\b\d{11,16}\b'),  # Primary: 11-16 digits (standard bank accounts)
                re.compile(r'\b\d{9,18}\b'),    # Broader: 9-18 digits catch-all
                re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),  # Card format
            ],
            "upi_id": [
                re.compile(r'\b([a-zA-Z0-9._-]+@(?:ybl|paytm|okaxis|okhdfcbank|oksbi|upi|apl|axl|ibl|sbi|icici|hdfc))\b', re.IGNORECASE),
                # Broadened catch-all: any handle@provider (2-256 chars @ 2-64 chars)
                re.compile(r'\b([a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64})\b(?!\.(?:com|in|org|net|co|edu|gov))', re.IGNORECASE),
            ],
            "phone_number": [
                re.compile(r'\+91[\s-]?\d{10}\b'),
                re.compile(r'(\+91[\-\s]?)?[6-9]\d{9}', re.IGNORECASE),
                re.compile(r'\b\d{3}[\s-]?\d{3}[\s-]?\d{4}\b'),
            ],
            "url": [
                re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
                re.compile(r'www\.[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
                re.compile(r'\b[a-zA-Z0-9-]+\.(com|in|org|net|xyz|top|click|loan|co\.in|io)[/\w.-]*\b', re.IGNORECASE),
            ],
            "email": [
                re.compile(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(?:com|in|org|net|co\.in|io))\b', re.IGNORECASE),
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
                bank_accts = self._extract_bank_accounts(text)
                upi_ids = self._extract_upi_ids(text)
                phone_nums = self._extract_phone_numbers(text)
                phish_links = self._extract_urls(text)
                emails = self._extract_emails(text)
                
                intelligence.bankAccounts.extend(bank_accts)
                intelligence.upiIds.extend(upi_ids)
                intelligence.phoneNumbers.extend(phone_nums)
                intelligence.phishingLinks.extend(phish_links)
                # Emails go into phishingLinks as per requirement
                intelligence.phishingLinks.extend(emails)
        
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
        text_lower = text.lower()
        
        # Patterns that indicate a number is NOT a bank account
        non_account_patterns = [
            r'employee\s*id[:\s]*',
            r'emp[:\s]*id[:\s]*',
            r'staff\s*id[:\s]*',
            r'id\s*(?:number|no)?[:\s]*',
            r'case\s*(?:number|no)?[:\s]*',
            r'reference\s*(?:number|no)?[:\s]*',
            r'complaint\s*(?:number|no)?[:\s]*',
            r'ticket\s*(?:number|no)?[:\s]*',
            r'order\s*(?:number|no)?[:\s]*',
        ]
        
        for pattern in self.patterns["bank_account"]:
            for match in pattern.finditer(text):
                clean_match = re.sub(r'[\s-]', '', match.group())
                if len(clean_match) >= 9 and len(clean_match) <= 18:
                    # Skip if it's a phone number (10 digits starting with 6-9)
                    if len(clean_match) == 10 and clean_match[0] in '6789':
                        continue
                    
                    # Check if this number appears after an employee ID or similar context
                    start_pos = match.start()
                    context_before = text_lower[max(0, start_pos - 30):start_pos]
                    
                    is_non_account = False
                    for non_pattern in non_account_patterns:
                        if re.search(non_pattern, context_before, re.IGNORECASE):
                            is_non_account = True
                            break
                    
                    if not is_non_account:
                        accounts.add(clean_match)
        
        return list(accounts)
    
    def _extract_upi_ids(self, text: str) -> List[str]:
        """Extract UPI IDs using broadened regex that catches non-standard formats"""
        upi_ids = set()
        # Known email domains to exclude from UPI detection
        email_domains = {
            'gmail', 'yahoo', 'hotmail', 'outlook', 'rediffmail', 'protonmail',
            'mail', 'email', 'live', 'aol', 'icloud', 'zoho', 'yandex',
        }
        for pattern in self.patterns["upi_id"]:
            matches = pattern.findall(text)
            for match in matches:
                if isinstance(match, tuple):
                    match = '@'.join(match) if len(match) > 1 else match[0]
                match_str = str(match).strip()
                if '@' not in match_str:
                    continue
                # Filter out standard email addresses (word@domain.com/.in/.org etc)
                if match_str.endswith('.com') or match_str.endswith('.in') or match_str.endswith('.org') or match_str.endswith('.net'):
                    continue
                # Filter out known email provider domains
                domain_part = match_str.split('@')[1].lower() if '@' in match_str else ''
                if domain_part in email_domains:
                    continue
                upi_ids.add(match_str.lower())
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
    
    def _extract_emails(self, text: str) -> List[str]:
        """Extract email addresses (added to phishing links)"""
        emails = set()
        for pattern in self.patterns["email"]:
            matches = pattern.findall(text)
            for match in matches:
                email = match.strip().lower()
                # Don't add UPI IDs that look like emails
                if not any(upi_suffix in email for upi_suffix in ['@ybl', '@paytm', '@okaxis', '@okhdfcbank', '@oksbi', '@upi', '@apl', '@axl', '@ibl', '@sbi', '@icici', '@hdfc', '@fakebank']):
                    emails.add(email)
        return list(emails)
    
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
