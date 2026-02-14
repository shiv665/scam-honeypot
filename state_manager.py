"""
Dynamic State Manager for Honeypot Agent

Tracks conversational state to prevent:
1. Topic Anchoring failures (keyword vs intent)
2. Circular Memory (asking same questions)
3. Response Variation (repetitive replies)
4. Direct Question Avoidance (not answering yes/no)
5. Tone Stagnation (stuck in one emotional mode)

The state manager maintains a living chronicle of:
- Extracted facts and their turn numbers
- Generated responses (with deduplication)
- Detected topics and intents
- Emotional progression
- Questions asked and answered
"""

import re
import random
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime
from enum import Enum


class EmotionalState(str, Enum):
    """Progression of emotional states matching human behavior"""
    HIGH_ANXIETY = "high_anxiety"          # Turns 1-3: cooperative, scared
    TECHNICAL_CONFUSION = "technical_confusion"  # Turns 4-7: things not working
    FRUSTRATION = "frustration"            # Turns 8-10: why is this hard?
    SUSPICION = "suspicion"                # Turns 11+: are you really from bank?


class ConversationTopic(str, Enum):
    """Detected conversation topics"""
    OTP = "otp"
    UPI = "upi"
    BANK_ACCOUNT = "bank_account"
    LINK = "link"
    PHONE = "phone"
    CASE_NUMBER = "case_number"
    THREAT = "threat"
    VERIFICATION = "verification"
    PAYMENT = "payment"
    UNKNOWN = "unknown"


class DynamicStateManager:
    """
    Manages conversation state to ensure dynamic, human-like responses.
    Prevents bot from sounding scripted or repetitive.
    """

    def __init__(self, session_id: str):
        self.session_id = session_id
        
        # Track extracted facts and when they were extracted
        self.extracted_facts: Dict[str, Tuple[str, int]] = {}  # fact -> (value, turn_number)
        
        # Track what we've asked for and received
        self.asked_for: Set[str] = set()  # {otp, upi, bank_account, phone, case_number, etc}
        self.received_fact_types: Set[str] = set()  # {upi, phone, account, link, etc}
        
        # Track generated responses to prevent repetition
        self.recent_responses: List[str] = []  # Last 6 full responses
        self.response_patterns: Set[str] = set()  # Normalized response beginnings
        self.max_recent_responses = 6
        
        # Track topics mentioned
        self.active_topics: Set[str] = set()  # Currently relevant topics
        self.previous_topics: Set[str] = set()  # Topics we've moved away from
        
        # Track questions and answers
        self.recent_questions: List[str] = []  # Questions we've asked
        self.scammer_answers_to_questions: Dict[str, str] = {}  # question -> answer
        
        # NEW: Track forbidden openers (prevent repetition of emotional phrases)
        self.used_openers: List[str] = []  # "I'm scared", "I'm anxious", etc
        self.forbidden_opener_phrases = ["i'm scared", "i'm anxious", "i'm worried", "help me sir", "oh no", "my god", "my god, this is too much"]
        
        # NEW: Track contradictions detected
        self.detected_contradictions: List[Dict] = []  # [{turn, contradiction, response}]
        
        # NEW: Track acknowledgment prefixes to prevent Echo Loop
        self.used_ack_phrases: List[str] = []  # ["I opened secure-sbi-login.com", ...]
        
        # NEW: Track which scammer-provided data has been validated/engaged with
        self.validated_facts: Set[str] = set()  # {"scammer.fraud@fakebank", "+919876543210", ...}
        
        # NEW: Track given data (for poisoning)
        self.poisoned_data_given: Dict[str, str] = {}  # {data_type: poisoned_value}
        
        # NEW: Track data echo counts to prevent repeating same data verbatim
        self.data_echo_counts: Dict[str, int] = {}  # {data_value: echo_count}
        self.max_data_echo = 1  # Only echo each piece of data fully ONCE
        
        # NEW: Track used physical excuses to prevent repetition
        self.used_physical_excuses: Set[str] = set()
        
        # Emotional progression
        self.current_emotion = EmotionalState.HIGH_ANXIETY
        self.emotion_history: List[Tuple[int, EmotionalState]] = [(0, EmotionalState.HIGH_ANXIETY)]
        
        # Turn tracking
        self.turn_count = 0
        self.last_update = datetime.now()

    # =========================
    # Core State Updates
    # =========================
    def update_turn(self, scammer_message: str, generated_response: str) -> None:
        """Update state after receiving scammer message and generating response"""
        self.turn_count += 1
        self.last_update = datetime.now()
        
        # Track the response
        self._track_response(generated_response)
        
        # Detect topics in scammer message
        detected_topics = self._detect_topics(scammer_message)
        self._update_active_topics(detected_topics)
        
        # Extract facts from scammer message
        facts = self._extract_facts_from_message(scammer_message)
        for fact_type, values in facts.items():
            for value in values:
                self.extracted_facts[value] = (fact_type, self.turn_count)
                self.received_fact_types.add(fact_type)
        
        # Update emotional state based on turn count
        self._progress_emotion()

    def _track_response(self, response: str) -> None:
        """Track response to prevent repetition"""
        self.recent_responses.append(response)
        if len(self.recent_responses) > self.max_recent_responses:
            self.recent_responses.pop(0)
        
        # Store normalized pattern (first ~50 chars) for quick dedup
        pattern = self._normalize_for_comparison(response[:80])
        self.response_patterns.add(pattern)

    def _detect_topics(self, message: str) -> Set[str]:
        """Detect conversation topics in message"""
        text = message.lower()
        topics = set()
        
        # Topic detection patterns
        if re.search(r"\botp\b|\bone.*time.*pass\b|\bcode\b", text):
            topics.add(ConversationTopic.OTP.value)
        if re.search(r"\bupi\b|\bverifyi.*amount\b", text):
            topics.add(ConversationTopic.UPI.value)
        if re.search(r"\baccount.*number\b|\bbank.*account\b|\b账户\b", text):
            topics.add(ConversationTopic.BANK_ACCOUNT.value)
        if re.search(r"https?://|\.com|website|link", text):
            topics.add(ConversationTopic.LINK.value)
        if re.search(r"\bphone\b|\bnumber\b|\bcall.*back\b", text):
            topics.add(ConversationTopic.PHONE.value)
        if re.search(r"\bcase.*number\b|\breference.*number\b|\bref\.\b", text):
            topics.add(ConversationTopic.CASE_NUMBER.value)
        if re.search(r"\bthreat\b|\bblock\b|\bfrozen\b|\barrest\b|\bpolice\b", text):
            topics.add(ConversationTopic.THREAT.value)
        if re.search(r"\bpay\b|\btransfer\b|\bfee\b|\bfine\b|\bamount\b", text):
            topics.add(ConversationTopic.PAYMENT.value)
        if re.search(r"\bverif\b|\bconfirm\b|\bidentif\b", text):
            topics.add(ConversationTopic.VERIFICATION.value)
        
        if not topics:
            topics.add(ConversationTopic.UNKNOWN.value)
        
        return topics

    def _update_active_topics(self, new_topics: Set[str]) -> None:
        """Update topic tracking"""
        # If scammer introduces new topic, track it
        if new_topics and ConversationTopic.UNKNOWN.value not in new_topics:
            self.previous_topics.update(self.active_topics - new_topics)
            self.active_topics = new_topics

    def _extract_facts_from_message(self, message: str) -> Dict[str, List[str]]:
        """Extract structured facts from message"""
        facts = {
            "upi": list(dict.fromkeys(
                re.findall(r"\b([a-zA-Z0-9._-]+@(?:ybl|paytm|okaxis|okhdfcbank|oksbi|upi|apl|axl|ibl|sbi|icici|hdfc))\b", message, re.IGNORECASE)
                # Catch-all: any word@word that isn't a standard email domain
                + re.findall(r"\b([a-zA-Z0-9._-]+@(?!(?:gmail|yahoo|hotmail|outlook|rediffmail|protonmail|mail|email|live|aol|icloud|zoho|yandex)\b)[a-zA-Z0-9_-]+)\b(?!\.(?:com|in|org|net|co|edu|gov))", message, re.IGNORECASE)
            )),
            "phone": re.findall(r"(\+91[\s-]?\d{10}|\b[6-9]\d{9}\b)", message),
            "bank_account": re.findall(r"\b\d{9,18}\b", message),
            "link": re.findall(r"(https?://[^\s<>\"]+|www\.[^\s<>\"]+)", message),
            "case_number": re.findall(r"\b(?:case|ref)[.:]?\s*([A-Z0-9\-/]+)\b", message, re.IGNORECASE),
        }
        # Filter out empty lists
        return {k: v for k, v in facts.items() if v}

    def _progress_emotion(self) -> None:
        """Progress emotional state based on turn count"""
        if self.turn_count <= 3:
            new_emotion = EmotionalState.HIGH_ANXIETY
        elif self.turn_count <= 7:
            new_emotion = EmotionalState.TECHNICAL_CONFUSION
        elif self.turn_count <= 10:
            new_emotion = EmotionalState.FRUSTRATION
        else:
            new_emotion = EmotionalState.SUSPICION
        
        if new_emotion != self.current_emotion:
            self.current_emotion = new_emotion
            self.emotion_history.append((self.turn_count, new_emotion))

    # =========================
    # Deduplication & Guardrails
    # =========================
    def should_avoid_response(self, candidate_response: str) -> bool:
        """Check if response is too similar to recent ones"""
        pattern = self._normalize_for_comparison(candidate_response[:80])
        
        # Exact pattern match = definitely skip
        if pattern in self.response_patterns:
            return True
        
        # Fuzzy match: check if candidate is very similar to recent responses
        for recent in self.recent_responses[-3:]:
            similarity = self._similarity_score(candidate_response, recent)
            if similarity > 0.75:  # 75% similar = skip
                return True
        
        return False

    def _normalize_for_comparison(self, text: str) -> str:
        """Normalize text for comparison"""
        # Remove pronouns, articles, common filler words
        normalized = re.sub(r"\b(i|me|my|the|a|an|is|are|was|were|been|be|have|has|do|does|did)\b", "", text.lower())
        normalized = re.sub(r"\s+", " ", normalized).strip()
        return normalized

    def _similarity_score(self, text1: str, text2: str) -> float:
        """Calculate simple similarity score between 0 and 1"""
        # Rough Jaccard similarity on words
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        if not words1 or not words2:
            return 0.0
        
        intersection = len(words1 & words2)
        union = len(words1 | words2)
        return intersection / union if union > 0 else 0.0

    def get_facts_already_provided(self) -> Dict[str, List[str]]:
        """Return facts already extracted from scammer"""
        result = {}
        for value, (fact_type, turn) in self.extracted_facts.items():
            if fact_type not in result:
                result[fact_type] = []
            result[fact_type].append(value)
        return result

    def get_missing_facts(self) -> List[str]:
        """Return list of facts we haven't collected yet"""
        needed = ["upi", "bank_account", "phone", "link", "case_number"]
        missing = [f for f in needed if f not in self.received_fact_types]
        return missing

    # =========================
    # Question Tracking
    # =========================
    def track_question_asked(self, question: str) -> None:
        """Record a question we asked"""
        self.recent_questions.append(question)
        if len(self.recent_questions) > 5:
            self.recent_questions.pop(0)

    def should_ask_for_fact(self, fact_type: str) -> bool:
        """Check if we should ask for a specific fact"""
        return fact_type not in self.received_fact_types

    def was_question_recently_asked(self, keyword: str) -> bool:
        """Check if we recently asked about a topic"""
        for question in self.recent_questions[-3:]:
            if keyword.lower() in question.lower():
                return True
        return False

    # =========================
    # Emotional Context
    # =========================
    def get_emotional_context(self) -> str:
        """Return emotional context for prompt engineering"""
        emotion = self.current_emotion
        
        if emotion == EmotionalState.HIGH_ANXIETY:
            return (
                "You are PANICKED and ANXIOUS. Answer quickly, comply readily, "
                "but show confusion about technical details. "
                "Use reactions like 'What do I do...', 'I can't lose my savings...', 'I'm trying, I'm trying...'. "
                "NEVER say 'Oh no' or 'My God, this is too much'. "
                "Use periods and commas, NOT exclamation marks. Sound breathless, not theatrical."
            )
        elif emotion == EmotionalState.TECHNICAL_CONFUSION:
            return (
                "You are CONFUSED and FRUSTRATED with technology. "
                "Say things like 'my app won't load', 'I don't understand this', "
                "'why is this happening?'. Still cooperative but showing strain."
            )
        elif emotion == EmotionalState.FRUSTRATION:
            return (
                "You are FRUSTRATED and IMPATIENT. "
                "Say 'Why is this taking so long?', 'This doesn't make sense', "
                "'Can you explain this better?'. Still comply but more questioning."
            )
        else:  # SUSPICION
            return (
                "You are SUSPICIOUS. Start asking 'Are you really from the bank?', "
                "'Why won't you give me the official number?', 'This seems weird'. "
                "Still engage but probe for contradictions."
            )

    # =========================
    # Topic Anchoring
    # =========================
    def acknowledge_active_topic(self, scammer_message: str) -> Optional[str]:
        """
        Generate a contextual acknowledgment of the current topic.
        Helps satisfy "Topic Anchoring" requirement.
        Returns a sentence framing for the response.
        """
        topics = self._detect_topics(scammer_message)
        if ConversationTopic.UNKNOWN.value in topics:
            return None
        
        # Pick the most specific topic
        topic = list(topics)[0] if topics else None
        
        if topic == ConversationTopic.OTP.value:
            return "I still don't see the OTP. "
        elif topic == ConversationTopic.UPI.value:
            return "About the UPI ID... "
        elif topic == ConversationTopic.BANK_ACCOUNT.value:
            return "Wait, about my account... "
        elif topic == ConversationTopic.LINK.value:
            return "That link you mentioned... "
        elif topic == ConversationTopic.PHONE.value:
            return "So that phone number... "
        elif topic == ConversationTopic.CASE_NUMBER.value:
            return "Can you repeat the case number...? "
        elif topic == ConversationTopic.THREAT.value:
            return "I'm really worried about this block. "
        elif topic == ConversationTopic.PAYMENT.value:
            return "About the payment you mentioned... "
        
        return None

    # =========================
    # ENHANCEMENT: Defect Fixes
    # =========================
    def check_forbidden_opener(self, response: str) -> bool:
        """Check if response starts with forbidden opener (emotion phrase)"""
        response_lower = response.lower()
        for phrase in self.forbidden_opener_phrases:
            if response_lower.startswith(phrase):
                count = sum(1 for r in self.recent_responses if r.lower().startswith(phrase))
                if count > 0:  # Already used once
                    return True
        return False

    def detect_contradiction(self, scammer_message: str) -> Optional[Dict]:
        """Detect logical contradictions in scammer's claims"""
        text = scammer_message.lower()
        
        # Bank vs Tax contradiction
        has_hdfc = "hdfc" in text
        has_income_tax = "income tax" in text or "it department" in text
        
        if has_hdfc and has_income_tax:
            return {
                "type": "bank_vs_tax",
                "doubt_response": "My brother-in-law works at HDFC and he said they don't do tax work. Are you sure you're at the right department?"
            }
        
        return None

    def get_bumbling_delay(self) -> str:
        """Return a physical delay excuse instead of asking for definitions"""
        delays = [
            "I dropped my card under the sofa, let me get a flashlight...",
            "My touch screen is acting up, let me wipe it...",
            "The phone line is crackling, hold on...",
            "My glasses are foggy, can't read the screen, one second...",
            "My hands are shaking, speak slower so I can type...",
            "The keyboard keys are sticking, wait...",
            "The lights went out, looking for a torch...",
            "My phone is overheating and closing apps...",
        ]
        return random.choice(delays)

    def get_poisoned_data(self, data_type: str) -> str:
        """Return intentionally poisoned data to force re-asks"""
        if data_type in self.poisoned_data_given:
            return self.poisoned_data_given[data_type]
        
        poisoned = {
            "card": str(random.randint(100000000000000, 999999999999999)),
            "cvv": "000",
            "account": str(random.randint(100000000, 999999999)),
            "otp": str(random.randint(1000000, 9999999)),
        }
        
        value = poisoned.get(data_type, "")
        if value:
            self.poisoned_data_given[data_type] = value
        return value

    def get_varied_ack_prefix(self, fact_type: str, fact_value: str) -> str:
        """Return a varied acknowledgment prefix for a scammer fact, preventing Echo Loop.
        
        Instead of always saying 'I opened secure-sbi-login.com,' vary the phrasing each turn.
        """
        
        link_prefixes = [
            f"I tried opening {fact_value}, but",
            f"That {fact_value} site is",
            f"About that website you sent,",
            f"I went to {fact_value} and",
            f"The page at {fact_value}",
            f"So I clicked your link and",
        ]
        
        phone_prefixes = [
            f"I noted the number {fact_value[-4:]},",
            f"About that number ending {fact_value[-4:]},",
            f"I tried calling {fact_value[-4:]} but",
            f"That number you gave,",
            f"So the number ending {fact_value[-4:]},",
        ]
        
        upi_prefixes = [
            f"I typed {fact_value} but",
            f"About that UPI {fact_value},",
            f"I'm entering {fact_value} and",
            f"That ID {fact_value}",
            f"So {fact_value} is showing",
            f"Wait, is it exactly {fact_value}?",
        ]
        
        account_prefixes = [
            f"About account {fact_value[-4:]},",
            f"I wrote down ...{fact_value[-4:]},",
            f"That account ending {fact_value[-4:]},",
            f"Wait, the account {fact_value},",
        ]
        
        prefix_map = {
            "link": link_prefixes,
            "phone": phone_prefixes,
            "upi": upi_prefixes,
            "bank_account": account_prefixes,
        }
        
        candidates = prefix_map.get(fact_type, [f"About {fact_value},"])
        
        # Filter out already-used prefixes
        unused = [p for p in candidates if p not in self.used_ack_phrases]
        if not unused:
            # All used up — reset and pick any
            unused = candidates
        
        chosen = random.choice(unused)
        self.used_ack_phrases.append(chosen)
        return chosen

    def get_fact_validation_question(self, fact_type: str, fact_value: str) -> Optional[str]:
        """Generate a validation question for a scammer-provided fact.
        
        Instead of ignoring data (Semantic Ignoring), ask clarifying questions
        that keep the scammer talking AND validate the intel.
        """
        
        if fact_value in self.validated_facts:
            return None  # Already validated this one
        
        self.validated_facts.add(fact_value)
        
        upi_questions = [
            f"Is {fact_value} spelled with a dot or a dash? I want to type it correctly.",
            f"Wait, {fact_value} — is that the same as my bank UPI? I have a @ybl one.",
            f"I'm typing {fact_value} but my app shows 'user not found'. Can you spell it again slowly?",
            f"So {fact_value} — do I send money to this or is this for receiving? I'm confused.",
            f"Is {fact_value} your personal ID or the bank's official verification ID?",
        ]
        
        phone_questions = [
            f"Is {fact_value} a landline or mobile? It's showing busy on my side.",
            f"I tried {fact_value} but it says 'number not reachable'. Is there an extension?",
            f"Can you confirm — {fact_value} — is this your direct line or the helpdesk?",
        ]
        
        link_questions = [
            f"That link is showing a certificate error. Is it http or https?",
            f"The page loaded but it's asking for my mother's maiden name. Is that normal?",
            f"It opened but there's no SBI logo on the page. Are you sure this is official?",
        ]
        
        account_questions = [
            f"You said {fact_value} — that doesn't match my passbook. Can you read back what you have for me?",
            f"Wait, {fact_value} has too many digits. My account is shorter. Which bank is this?",
            f"I entered {fact_value} but it says 'invalid account'. Can you confirm the last 4 digits?",
        ]
        
        question_map = {
            "upi": upi_questions,
            "phone": phone_questions,
            "link": link_questions,
            "bank_account": account_questions,
        }
        
        candidates = question_map.get(fact_type, [])
        if not candidates:
            return None
        
        return random.choice(candidates)

    # =========================
    # ENHANCEMENT: Anti-Echo (Data Repetition Prevention)
    # =========================
    def should_echo_data(self, data_value: str) -> bool:
        """Check if a data point should be echoed fully (max 1 full mention).
        After first mention, use partial references only."""
        clean = re.sub(r'[\s\-+]', '', data_value)
        count = self.data_echo_counts.get(clean, 0)
        return count < self.max_data_echo

    def record_data_echo(self, data_value: str) -> None:
        """Record that a data point was echoed in a response"""
        clean = re.sub(r'[\s\-+]', '', data_value)
        self.data_echo_counts[clean] = self.data_echo_counts.get(clean, 0) + 1

    def get_data_reference(self, data_value: str) -> str:
        """Get an abbreviated reference for data after first mention.
        First time: full value. After: last 4 digits only."""
        clean = re.sub(r'[\s\-+]', '', data_value)
        count = self.data_echo_counts.get(clean, 0)
        if count == 0:
            return data_value  # First mention: use full value
        # Subsequent mentions: use partial reference
        if len(clean) >= 8:
            return f"...{clean[-4:]}"
        elif len(clean) >= 4:
            return f"ending {clean[-4:]}"
        return data_value

    def detect_data_echo_in_response(self, response: str) -> List[str]:
        """Find full data values repeated in a response that shouldn't be."""
        echoed = []
        for value, count in self.data_echo_counts.items():
            if count >= self.max_data_echo and len(value) >= 8:
                if value in re.sub(r'[\s\-+]', '', response):
                    echoed.append(value)
        return echoed

    # =========================
    # ENHANCEMENT: Physical Friction Diversity
    # =========================
    def get_unique_physical_excuse(self) -> str:
        """Return a physical excuse that hasn't been used yet in this session.
        Pool of 20+ diverse excuses. Never repeats until all are exhausted."""
        all_excuses = [
            "I dropped my phone in the kitchen sink, let me dry it off...",
            "My screen is flickering, I can't see the numbers clearly...",
            "The power just went out, I'm looking for the torch...",
            "My reading glasses broke yesterday, I'm squinting at the screen...",
            "I spilled tea on the keyboard, the keys are sticky now...",
            "My grandchild grabbed the phone, one moment...",
            "The phone fell between the sofa cushions, hold on...",
            "My internet just disconnected, I'm restarting the router...",
            "The battery is at 2 percent, running to get the charger...",
            "My fingers are trembling, I keep pressing the wrong buttons...",
            "The screen cracked again, I can barely tap on anything...",
            "My neighbor is ringing the doorbell, one second...",
            "The dog knocked the phone off the table, sorry...",
            "I'm getting a headache from staring at this tiny screen...",
            "My touchscreen is frozen, let me restart the phone...",
            "The phone is overheating and the screen went black...",
            "I accidentally pressed the wrong button and the app closed...",
            "The ceiling fan wire touched my phone charger and it sparked...",
            "I'm in the kitchen and there's too much noise, moving to another room...",
            "My hand is cramping from holding the phone, give me a moment...",
        ]
        unused = [e for e in all_excuses if e not in self.used_physical_excuses]
        if not unused:
            self.used_physical_excuses.clear()
            unused = all_excuses
        chosen = random.choice(unused)
        self.used_physical_excuses.add(chosen)
        return chosen

    # =========================
    # ENHANCEMENT: Strategic Intel Baiting
    # =========================
    def get_strategic_bait(self) -> Optional[str]:
        """Generate strategic bait to push scammer into providing missing intel.
        Uses false information to force corrections and reveal infrastructure."""
        missing = self.get_missing_facts()
        if not missing:
            return None
        
        baits = {
            "upi": [
                "Wait, the OTP I see says 'BANK-123', is that the right code?",
                "I see a message from HDFC-SECURE, but my account is SBI. Is that correct?",
                "My nephew says I should pay through Google Pay. Do you have a UPI ID I can use?",
                "Can I just do the verification through UPI? What ID should I enter?",
                "I was about to transfer, but which UPI handle do I send to? My app is asking.",
                "My son set up PhonePe for me. Can I use that? What UPI ID do I enter?",
            ],
            "link": [
                "Can you send me an official website link so I can verify? I don't trust phone calls alone.",
                "My son told me to always check the official website first. What is the URL?",
                "Can you email me the notice? I need something in writing.",
                "Is there a portal I can log into and check myself?",
            ],
            "phone": [
                "Can you give me a callback number? I want to call from my landline.",
                "What is the direct number for your department? I need to note it down.",
                "My son wants to call you back and verify. What number should he dial?",
            ],
            "bank_account": [
                "If I need to make any payment, which account should I transfer to?",
                "Can you confirm the account number? I want to cross-check with my passbook.",
                "I'll go to the bank branch tomorrow. What account number should I mention?",
            ],
        }
        
        # Prioritize UPI since it's most commonly missed
        priority = ["upi", "link", "bank_account", "phone"]
        for fact_type in priority:
            if fact_type in missing and fact_type in baits:
                return random.choice(baits[fact_type])
        
        return None

    def get_false_info_bait(self) -> Optional[str]:
        """Generate false information to see if scammer corrects it.
        Forces scammer to stay engaged and reveal technical details."""
        false_info_baits = [
            "Wait, the OTP I see is 'BANK-123', is that the one?",
            "I see a code but it's only 4 digits — 8291. Is that right or should it be 6?",
            "The message says 'Dear HDFC customer' but I have SBI. Is this correct?",
            "I got a notification from 'RBI-ALERT' but you said this is the bank. Which one is it?",
            "The link opens a page with 'ICICI' logo but you mentioned SBI earlier. Is this right?",
            "I'm seeing a reference number 'TXN-00000' on my screen. Does that match your records?",
        ]
        return random.choice(false_info_baits)

    def get_sentiment_shift(self) -> str:
        """After turn 7, shift from scared to annoyed"""
        if self.turn_count > 7:
            annoyances = [
                "I'm trying my best, stop shouting at me!",
                "Why is this taking so long? Getting tired of this.",
                "I'm doing everything! Stop being aggressive!",
                "Explain this calmly, you're stressing me out!",
                "I appreciate if you slow down. I'm TRYING, okay?",
            ]
            return random.choice(annoyances)
        return ""

    # =========================
    # Reporting
    # =========================
    def get_state_summary(self) -> Dict:
        """Return summary of current conversation state"""
        return {
            "turn_count": self.turn_count,
            "current_emotion": self.current_emotion.value,
            "active_topics": list(self.active_topics),
            "extracted_facts": {k: [v[0] for v in vals] if isinstance(vals, list) else vals 
                              for k, vals in self._group_facts().items()},
            "missing_facts": self.get_missing_facts(),
            "recent_responses_count": len(self.recent_responses),
            "questions_asked": len(self.recent_questions),
        }

    def _group_facts(self) -> Dict[str, List[str]]:
        """Group facts by type"""
        grouped = {}
        for value, (fact_type, _) in self.extracted_facts.items():
            if fact_type not in grouped:
                grouped[fact_type] = []
            grouped[fact_type].append(value)
        return grouped

    def get_context_for_llm(self) -> str:
        """
        Generate a detailed context string for the LLM system prompt.
        This ensures the LLM has full awareness of conversation state.
        """
        facts = self.get_facts_already_provided()
        missing = self.get_missing_facts()
        
        context_lines = [
            f"Turn: {self.turn_count}",
            f"Emotional Level: {self.current_emotion.value.replace('_', ' ').title()}",
            f"Active Topics: {', '.join(self.active_topics) if self.active_topics else 'None yet'}",
        ]
        
        if facts:
            context_lines.append("Facts Already Extracted:")
            for fact_type, values in facts.items():
                context_lines.append(f"  - {fact_type}: {', '.join(values)}")
        
        if missing:
            context_lines.append(f"Still Need: {', '.join(missing)}")
        
        if self.recent_responses:
            context_lines.append(f"AVOID REPEATING (last {len(self.recent_responses)} responses used): {', '.join([r[:60]+'...' if len(r)>60 else r for r in self.recent_responses])}")
        
        return "\n".join(context_lines)
