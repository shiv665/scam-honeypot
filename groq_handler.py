"""
Groq LLM Handler for Scam Honeypot System

Goals:
- Use AI for both scam detection and response generation
- Avoid repetitive, scripted replies
- Prevent topic drift (e.g. asking for UPI/money before the scammer introduces payment)
- Acknowledge and react to scammer-provided "facts" (links, phone numbers, account numbers)
- Match scammer urgency with human-like panic without revealing detection
"""

import json
import re
import random
from typing import Any, Dict, List, Optional

from groq import Groq

from config import GROQ_API_KEY, GROQ_MODEL
from models import ScamDetectionResult, ScamIndicator
from state_manager import DynamicStateManager


class GroqHandler:
    def __init__(self):
        self.client = None
        self.model = GROQ_MODEL
        self._initialized = False
        self.state_managers: Dict[str, DynamicStateManager] = {}  # Per-session state managers
        self._initialize()

    def _initialize(self):
        if not GROQ_API_KEY:
            print("Groq API key not set - using rule-based responses")
            return
        try:
            self.client = Groq(api_key=GROQ_API_KEY)
            self._initialized = True
            print(f"Groq initialized with model: {self.model}")
        except Exception as e:
            print(f"Failed to initialize Groq: {e}")
            self._initialized = False

    def is_available(self) -> bool:
        return self._initialized and self.client is not None

    def _get_or_create_state_manager(self, session_id: str) -> DynamicStateManager:
        """Get or create a state manager for the session"""
        if session_id not in self.state_managers:
            self.state_managers[session_id] = DynamicStateManager(session_id)
        return self.state_managers[session_id]

    # =========================
    # Detection
    # =========================
    def detect_scam(self, scammer_message: str, conversation_history: List) -> Optional[ScamDetectionResult]:
        if not self.is_available():
            return None
        try:
            history_payload = self._format_history(conversation_history, limit=10)
            prompt = (
                "Classify whether the latest incoming message is likely a scam.\n"
                "Return only valid JSON with this schema:\n"
                "{"
                "\"is_scam\": boolean, "
                "\"confidence\": number_between_0_and_1, "
                "\"scam_type\": \"phishing|impersonation_threat|lottery_scam|job_scam|phishing_link|kyc_fraud|generic_scam|benign\", "
                "\"risk_level\": \"low|medium|high|critical\", "
                "\"indicators\": ["
                "{\"indicator_type\": string, \"value\": string, \"confidence\": number_between_0_and_1, \"context\": string}"
                "]"
                "}\n\n"
                f"Latest message:\n{scammer_message}\n\n"
                f"Conversation history:\n{json.dumps(history_payload, ensure_ascii=True)}"
            )

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a fraud detection analyst for Indian scam messages. "
                            "Be strict with JSON and do not include markdown."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
                max_tokens=550,
            )

            content = (response.choices[0].message.content or "").strip()
            if not content:
                return None
            raw = self._safe_json_loads(content)
            if not isinstance(raw, dict):
                return None
            return self._normalize_detection_result(raw)
        except Exception as e:
            print(f"Groq detection error: {e}")
            return None

    # =========================
    # Response generation
    # =========================
    def generate_response(
        self,
        scammer_message: str,
        conversation_history: List,
        detection_result,
        session,
    ) -> Optional[str]:
        if not self.is_available():
            return None

        try:
            # Get state manager for this session
            session_id = getattr(session, 'session_id', 'unknown')
            state_mgr = self._get_or_create_state_manager(session_id)
            
            # Extract what the scammer is trying to do and what they already revealed.
            scammer_facts = self._extract_scammer_facts(scammer_message, conversation_history)
            
            # NEW: Detect contradictions in scammer's claims
            contradiction = state_mgr.detect_contradiction(scammer_message)
            if contradiction:
                # Log detected contradiction
                state_mgr.detected_contradictions.append({
                    "turn": state_mgr.turn_count,
                    "type": contradiction.get("type"),
                })
            
            strategy = self._choose_strategy(
                scammer_message=scammer_message,
                conversation_history=conversation_history,
                scammer_facts=scammer_facts,
                detection_result=detection_result,
                session=session,
            )

            # Build enhanced system prompt with emotional context
            system_prompt = self._build_system_prompt(
                session=session,
                detection_result=detection_result,
                scammer_facts=scammer_facts,
                strategy=strategy,
                state_mgr=state_mgr,  # Pass state manager
                contradiction=contradiction,  # Pass detected contradiction
            )

            messages = self._build_messages(system_prompt, scammer_message, conversation_history)
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=140,
                temperature=0.9,
                top_p=0.95,
            )

            reply = (response.choices[0].message.content or "").strip()
            reply = self._clean_response(reply)

            # Check if this reply would be a repetition
            if state_mgr.should_avoid_response(reply):
                # Generate a fallback response
                print(f"[GROQ-GUARDRAIL] Repetition detected, generating alternative")
                sf = self._extract_scammer_facts(scammer_message, conversation_history)
                prev_bot_texts = self._get_prev_bot_texts(conversation_history, limit=6)
                reply = self._fallback_non_payment_reply(sf, prev_bot_texts, conversation_history, state_mgr=state_mgr)

            # Hard guardrails against the common failures you listed.
            reply = self._apply_post_guardrails(
                reply=reply,
                scammer_message=scammer_message,
                conversation_history=conversation_history,
                scammer_facts=scammer_facts,
                strategy=strategy,
                state_mgr=state_mgr,
            )
            
            # Update state manager with this turn
            state_mgr.update_turn(scammer_message, reply)
            
            print(f"[GROQ] Response: {reply[:80]}{'...' if len(reply) > 80 else ''}")
            return reply
        except Exception as e:
            print(f"Groq generation error: {e}")
            # Avoid falling back to the repetitive rule-based agent responses.
            try:
                sf = self._extract_scammer_facts(scammer_message, conversation_history)
                prev_bot_texts = self._get_prev_bot_texts(conversation_history, limit=6)
                fallback = self._fallback_non_payment_reply(sf, prev_bot_texts, conversation_history, state_mgr=state_mgr)
                
                # Run post-guardrails on fallback too (structural monotony, etc.)
                fallback = self._apply_post_guardrails(
                    reply=fallback,
                    scammer_message=scammer_message,
                    conversation_history=conversation_history,
                    scammer_facts=sf,
                    strategy=locals().get('strategy', {}),
                    state_mgr=state_mgr,
                )
                
                # CRITICAL: Update state manager so it remembers this fallback response
                state_mgr.update_turn(scammer_message, fallback)
                
                print(f"[GROQ-FALLBACK] Groq errored, using internal fallback: {fallback[:80]}{'...' if len(fallback) > 80 else ''}")
                return fallback
            except Exception as fallback_err:
                print(f"[GROQ-FALLBACK] Groq errored and internal fallback also failed: {fallback_err}")
                return None

    # =========================
    # Prompt building
    # =========================
    def _build_system_prompt(
        self,
        session,
        detection_result,
        scammer_facts: Dict[str, Any],
        strategy: Dict[str, Any],
        state_mgr: Optional[DynamicStateManager] = None,
        contradiction: Optional[Dict] = None,
    ) -> str:
        scam_type = detection_result.scam_type if detection_result else "unknown"
        turn_count = session.turn_count if session else 0
        intel = session.extracted_intelligence if session else None

        recent_bot_replies: List[str] = []
        if session and getattr(session, "conversation_history", None):
            recent_bot_replies = [
                str(turn.bot_reply).strip()
                for turn in session.conversation_history[-6:]
                if getattr(turn, "bot_reply", None)
            ]

        collected = []
        if intel:
            if intel.phoneNumbers:
                collected.append(f"Phone: {intel.phoneNumbers[0]}")
            if intel.upiIds:
                collected.append(f"UPI: {intel.upiIds[0]}")
            if intel.bankAccounts:
                collected.append(f"BankAcct: {intel.bankAccounts[0]}")
            if intel.phishingLinks:
                collected.append(f"Link/Email: {intel.phishingLinks[0]}")

        # Topic lock: only ask for money/UPI if scammer has introduced payment/UPI/fine/fee.
        allow_payment_questions = bool(strategy.get("allow_payment_questions", False))

        base = [
            "You are a real Indian person (age 35-55) replying naturally to a scammer.",
            "You must waste the scammer's time and extract details, WITHOUT ever revealing suspicion.",
            "",
            "Hard rules:",
            "1) Write 1-2 short sentences only.",
            "2) Never repeat or paraphrase your last 6 replies (see RECENT REPLIES).",
            "3) React to what the scammer just said: acknowledge their link/number/account if present.",
            "4) Match their urgency with human emotion (panic/confusion/frustration) but stay cooperative.",
            "5) Do NOT introduce new subplots (no talk of payments/UPI/fees) unless the scammer mentioned money/UPI/fine/fee.",
            "6) Do not ask for OTP again and again; deflect and ask for alternative verification or written proof.",
        ]

        # Add emotional context from state manager
        if state_mgr:
            base.append("")
            base.append("EMOTIONAL STATE:")
            base.append(f"- Progression level: {state_mgr.current_emotion.value.replace('_', ' ').title()}")
            base.append(f"- {state_mgr.get_emotional_context()}")
            
            # NEW: Add sentiment shift guidance
            sentiment = state_mgr.get_sentiment_shift()
            if sentiment:
                base.append(f"- SENTIMENT SHIFT (Turn {turn_count}, >7): {sentiment}")
            
            # Add state context
            base.append("")
            base.append("CONVERSATION STATE:")
            base.append(f"- Turn: {turn_count}")
            base.append(f"- Fact Categories Obtained: {', '.join(state_mgr.received_fact_types) if state_mgr.received_fact_types else 'None yet'}")
            base.append(f"- Missing Fact Types: {', '.join(state_mgr.get_missing_facts())}")
            
            # NEW: Anti-Echo Rule — prevent repeating data verbatim
            base.append("")
            base.append("ANTI-ECHO RULE (CRITICAL):")
            base.append("- NEVER repeat a phone number, account number, or UPI ID in full after the first mention.")
            base.append("- After first mention, refer to data by LAST 4 DIGITS ONLY: 'that number ending 3210', 'my account ending 3456'.")
            base.append("- A real person does NOT say their full account number 5 times. It sounds robotic.")
            base.append("- If you already mentioned +919876543210, say 'that number ending 3210' next time.")
            base.append("- If you already mentioned 1234567890123456, say 'my account ending 3456' next time.")
            if state_mgr.data_echo_counts:
                echoed_items = [f"{v} (mentioned {c}x)" for v, c in state_mgr.data_echo_counts.items() if c >= 1]
                if echoed_items:
                    base.append(f"- Already mentioned fully: {', '.join(echoed_items[:5])} — use partial refs only.")
            
            # NEW: Logical Barrier (Process Confusion) — replaces Physical Friction
            base.append("")
            base.append("LOGICAL BARRIER (PROCESS CONFUSION STALLS):")
            base.append("- PROHIBITED: Physical catastrophes (spilled tea, cracked screen, power cut, dropped phone).")
            base.append("  These are contradictory when you're still typing fluent replies.")
            base.append("- REQUIRED: Use 'Process Confusion' — stall by asking micro-questions about their UI/instructions:")
            base.append("  Example: 'Where exactly on the page is the button?', 'I see two fields, which one is for OTP?'")
            base.append("  Example: 'The app is asking for a VPA — is that the same as the ID you gave?'")
            stall_suggestion = state_mgr.get_process_confusion_stall()
            base.append(f"- Suggested stall: '{stall_suggestion}'")
            if state_mgr.used_process_confusions:
                base.append(f"- Already used (DO NOT repeat): {', '.join(list(state_mgr.used_process_confusions)[:5])}")
            
            # NEW: Mirror & Verify Rule
            base.append("")
            base.append("MIRROR & VERIFY RULE (MANDATORY):")
            base.append("- When scammer provides a data point (UPI, Link, Phone, Account):")
            base.append("  Your NEXT response MUST repeat that data back with slight doubt.")
            base.append("  Example: 'You said the ID is scammer@fakebank, right? It's showing Rahul Enterprises.'")
            base.append("  Example: 'That number +919876543210, right? It says not reachable.'")
            base.append("- This validates intel AND forces scammer to stay engaged.")
            if state_mgr.mirrored_data_points:
                base.append(f"- Already mirrored: {', '.join(list(state_mgr.mirrored_data_points)[:5])}")
            
            # NEW: Response Diversity — Anti-Monotony
            base.append("")
            base.append("RESPONSE DIVERSITY (CRITICAL):")
            base.append("- NEVER follow the same STRUCTURAL PATTERN in consecutive turns.")
            base.append("- BAD EXAMPLE (same structure 3x): 'What if I make a mistake…account locked?' / 'What if I send wrong OTP…account blocked?' / 'What if I accidentally…locked instantly?'")
            base.append("- These are structurally IDENTICAL even though words differ. A real person changes approach.")
            base.append("- VARY your response type each turn: one turn ask a UI question, next turn express doubt, next turn try to comply slowly.")
            base.append("- If you asked 'what if X happens?' last turn, do NOT ask 'what if Y happens?' this turn.")
            if state_mgr.recent_skeletons:
                last_skeleton = state_mgr.recent_skeletons[-1]
                if last_skeleton:
                    base.append(f"- Last response features: {', '.join(sorted(last_skeleton))}")
                    base.append(f"- THIS response MUST NOT match these features. Use a DIFFERENT approach.")
            if state_mgr.consecutive_monotone_count > 0:
                base.append(f"- WARNING: {state_mgr.consecutive_monotone_count} consecutive monotone responses detected! CHANGE APPROACH NOW.")

            # NEW: State Persistence — Tactic Rotation
            base.append("")
            base.append("STATE PERSISTENCE (TACTIC ROTATION):")
            base.append("- You maintain a Used_Tactics list. NEVER repeat the same stalling tactic.")
            base.append(f"- Last tactic category: {state_mgr.last_tactic_category or 'None'}")
            next_cat = state_mgr.get_next_tactic_category()
            base.append(f"- NEXT turn MUST use category: {next_cat.upper()}")
            base.append("- Categories: CONFUSION (UI questions), SKEPTICAL (doubt scammer), SLOW_COMPLIANCE (realistic delays)")
            base.append("- FORBIDDEN: Same category twice in a row.")
            next_tactic = state_mgr.get_next_tactic()
            base.append(f"- Suggested {next_cat} tactic: '{next_tactic['text']}'")
            if state_mgr.used_tactics:
                recent_tactics = state_mgr.used_tactics[-3:]
                base.append(f"- Recent tactics used: {', '.join([t['category'] + ': ' + t['text'][:40] for t in recent_tactics])}")
            
            # NEW: Strategic Intel Baiting
            missing = state_mgr.get_missing_facts()
            if missing:
                base.append("")
                base.append("STRATEGIC INTEL BAITING (HIGH PRIORITY):")
                base.append(f"- You are MISSING these intel types: {', '.join(missing)}")
                base.append("- You MUST actively push the scammer to provide missing intel.")
                base.append("- Use FALSE INFORMATION to force corrections:")
                bait = state_mgr.get_strategic_bait()
                if bait:
                    base.append(f"  Example bait: '{bait}'")
                false_info = state_mgr.get_false_info_bait()
                if false_info:
                    base.append(f"  False info bait: '{false_info}'")
                base.append("- Mention wrong bank name, wrong OTP format, or ask 'Can I pay via UPI?' to fish for UPI ID.")
                base.append("- If scammer mentions money, ALWAYS ask 'which UPI ID?' or 'which account number?'")
        else:
            base.append("")
            base.append(f"Turn: {turn_count}")
        
        base.append(f"Scam type (for guidance only): {scam_type}")

        # NEW: Add detected contradiction
        if contradiction:
            base.append("")
            base.append("CONTRADICTION DETECTED:")
            base.append(f"- Type: {contradiction.get('type')}")
            base.append(f"- Response: {contradiction.get('doubt_response')}")

        if collected:
            base.append("")
            base.append(f"COLLECTED INTEL (do not ask again): {', '.join(collected)}")

        base.append("")
        base.append("SCAMMER FACTS OBSERVED (acknowledge at least one if present):")
        if scammer_facts.get("phone_numbers"):
            base.append(f"- Phone numbers: {', '.join(scammer_facts['phone_numbers'][:2])}")
        if scammer_facts.get("links"):
            base.append(f"- Links: {', '.join(scammer_facts['links'][:2])}")
        if scammer_facts.get("bank_accounts"):
            base.append(f"- Account numbers: {', '.join(scammer_facts['bank_accounts'][:2])}")
        if scammer_facts.get("upi_ids"):
            base.append(f"- UPI IDs: {', '.join(scammer_facts['upi_ids'][:2])}")

        base.append("")
        base.append("YOU MUST DO THIS NEXT MOVE:")
        selected_move = str(strategy.get("selected_move", "")).strip()
        if selected_move:
            base.append(f"- {selected_move}")
        else:
            base.append("- Stay cooperative but panicked; ask for the official customer care number and official bank website to verify.")

        if not allow_payment_questions:
            base.append("")
            base.append("PAYMENT/UPI GUARDRAIL: The scammer did NOT introduce payment yet. Do not ask for UPI/fees/verification amount.")

        if recent_bot_replies:
            base.append("")
            base.append("RECENT REPLIES (do NOT repeat or rephrase):")
            for r in recent_bot_replies:
                base.append(f"- {' '.join(r.split())[:170]}")

        return "\n".join(base).strip()

    def _build_messages(self, system_prompt: str, scammer_message: str, conversation_history: List) -> List[dict]:
        messages = [{"role": "system", "content": system_prompt}]

        # Provide more context to reduce repetition.
        recent = conversation_history[-10:] if len(conversation_history) > 10 else conversation_history
        for msg in recent:
            sender_value = getattr(msg.sender, "value", str(getattr(msg, "sender", "")))
            role = "assistant" if sender_value == "user" else "user"
            content = str(getattr(msg, "text", "")).strip() or str(msg)
            messages.append({"role": role, "content": content})

        messages.append({"role": "user", "content": scammer_message})
        return messages

    # =========================
    # Strategy
    # =========================
    def _choose_strategy(
        self,
        scammer_message: str,
        conversation_history: List,
        scammer_facts: Dict[str, Any],
        detection_result,
        session,
    ) -> Dict[str, Any]:
        text = (scammer_message or "").lower()
        scam_type = (getattr(detection_result, "scam_type", None) or "").lower()

        allow_payment = bool(
            re.search(r"\b(upi|pay|payment|transfer|fee|fine|amount|rs\.?|inr|rupees?)\b", text, re.IGNORECASE)
            or scammer_facts.get("upi_ids")
        )

        prev_bot_texts = self._get_prev_bot_texts(conversation_history, limit=6)
        last_bot = prev_bot_texts[-1] if prev_bot_texts else ""

        # If we previously drifted into payment topics but scammer hasn't, correct the flow.
        needs_correction = (not allow_payment) and bool(
            re.search(r"\b(upi|pay|payment|transfer|fee|amount)\b", last_bot, re.IGNORECASE)
        )

        has_link = bool(scammer_facts.get("links"))
        has_phone = bool(scammer_facts.get("phone_numbers"))
        has_acct = bool(scammer_facts.get("bank_accounts"))
        has_upi = bool(scammer_facts.get("upi_ids")) or bool(re.search(r"\bupi\b", text, re.IGNORECASE))
        asked_case_last = bool(re.search(r"\b(case|reference)\b", last_bot, re.IGNORECASE))
        scammer_answered_case = bool(re.search(r"\b(case|reference|ref)\b", text, re.IGNORECASE))

        # Build a set of "next moves" that keeps the scammer working.
        moves: List[str] = []

        # Always increase emotional realism.
        moves.append("Show panic/confusion about the block and ask a very specific clarifying question.")

        if has_link:
            moves.append("Say the link is showing an error or you can't log in; ask for the official bank website domain or an email with the notice.")
            moves.append("Ask which exact page option to click and what the 'case/reference' number is on their side.")

        if has_phone:
            moves.append("Say you're calling but it says busy/switched off; ask if there is another landline or extension number.")
            moves.append("Ask their name, designation, and branch/department and tell them you're noting it down.")

        if has_acct:
            moves.append("Read back the account number and say it doesn't match yours; ask them to confirm the last 4 digits of YOUR account on file.")
            moves.append("Say you tried entering it and it says 'invalid'; ask them to repeat slowly with spacing.")

        if has_upi:
            moves.append("Sound confused about the UPI change and ask what 'UPI verification' means since you were told about OTP/account block.")
            moves.append("Say you're typing the UPI ID but it says 'user not found'; ask them to repeat the exact UPI handle.")

        if asked_case_last and not scammer_answered_case:
            moves.append("Say you still need the case/reference number before proceeding and ask them to share it.")

        # OTP-focused deflection: keep them stuck but cooperative.
        moves.append("Say you didn't receive OTP; ask them to resend and tell what exact SMS sender name will appear.")
        moves.append("Ask for a written notice/FIR/case ID and the official email address to send documents.")

        # Only once payment is introduced, move to payment intel.
        if allow_payment:
            moves.append("Ask which UPI ID / account details to pay to and what the beneficiary name is.")

        # STRATEGIC BAITING: Push for missing intel types
        session_id = getattr(session, 'session_id', 'unknown')
        state_mgr = self._get_or_create_state_manager(session_id)
        missing_facts = state_mgr.get_missing_facts()
        
        if "upi" in missing_facts:
            moves.append("Bait for UPI: Say 'My nephew uses Google Pay, can I verify through UPI? What UPI ID?' or 'Can I pay through PhonePe? What ID should I use?'")
            moves.append("Offer false info: 'The OTP says BANK-123, is that it?' to force scammer to clarify, then ask 'Can I just send through UPI instead?'")
        
        if "link" in missing_facts:
            moves.append("Push for link/email: 'Can you send me an official website link to verify? I don't trust phone calls alone.' or 'My son says check official website first, what is the URL?'")
        
        if "bank_account" in missing_facts and allow_payment:
            moves.append("Push for bank account: 'If I need to transfer, what account number to? I need to go to the bank branch.'")

        # Scam-type hints.
        if scam_type == "impersonation_threat":
            moves.append("Ask which police station/court/case number and request a copy of the notice.")
        elif scam_type in ("phishing", "kyc_fraud"):
            moves.append("Ask for the official customer care number and official bank website to verify, because OTP isn't coming.")

        # De-duplicate
        unique_moves: List[str] = []
        for m in moves:
            if m not in unique_moves:
                unique_moves.append(m)

        selected_move = self._pick_next_move(
            unique_moves=unique_moves,
            scammer_facts=scammer_facts,
            prev_bot_texts=prev_bot_texts,
            needs_correction=needs_correction,
        )

        return {
            "allow_payment_questions": allow_payment,
            "moves": unique_moves,
            "selected_move": selected_move,
            "needs_correction": needs_correction,
        }

    # =========================
    # Fact extraction helpers
    # =========================
    def _extract_scammer_facts(self, scammer_message: str, conversation_history: List) -> Dict[str, Any]:
        # Only consider scammer text when extracting "scammer facts".
        # This prevents the bot from hallucinating artifacts (like links) that the scammer never sent.
        recent = conversation_history[-12:] if len(conversation_history) > 12 else conversation_history
        scammer_texts: List[str] = []
        for m in recent:
            sender = getattr(m, "sender", None)
            sender_value = getattr(sender, "value", str(sender)).lower()
            if sender_value == "scammer":
                scammer_texts.append(str(getattr(m, "text", "")).strip())
        scammer_texts.append(str(scammer_message or "").strip())
        combined = " ".join([t for t in scammer_texts if t])

        links = re.findall(r"(https?://[^\s<>\"]+|www\.[^\s<>\"]+)", combined, flags=re.IGNORECASE)
        # Light normalization
        links = [l.rstrip(".,;:!?") for l in links]

        upi_ids = re.findall(r"\b([a-zA-Z0-9._-]+@(?:ybl|paytm|okaxis|okhdfcbank|oksbi|upi|apl|axl|ibl|sbi|icici|hdfc))\b", combined, flags=re.IGNORECASE)
        # Catch-all: word@word that isn't a known email domain
        upi_ids += re.findall(r"\b([a-zA-Z0-9._-]+@(?!(?:gmail|yahoo|hotmail|outlook|rediffmail|protonmail|mail|email|live|aol|icloud|zoho|yandex)\b)[a-zA-Z0-9_-]+)\b(?!\.(?:com|in|org|net|co|edu|gov))", combined, flags=re.IGNORECASE)
        upi_ids = [u.lower() for u in upi_ids]

        phone_numbers = re.findall(r"(\+91[\s-]?\d{10}|\b[6-9]\d{9}\b)", combined)
        phone_numbers = [self._normalize_phone(p) for p in phone_numbers]

        # Bank accounts: 9-18 digits, avoid phone-like 10-digit starting 6-9
        bank_accounts = []
        for match in re.findall(r"\b\d{9,18}\b", combined):
            if len(match) == 10 and match[0] in "6789":
                continue
            bank_accounts.append(match)

        return {
            "links": list(dict.fromkeys(links)),
            "upi_ids": list(dict.fromkeys(upi_ids)),
            "phone_numbers": list(dict.fromkeys([p for p in phone_numbers if p])),
            "bank_accounts": list(dict.fromkeys(bank_accounts)),
        }

    def _normalize_phone(self, raw: str) -> str:
        digits = re.sub(r"[^\d+]", "", raw or "")
        if digits.startswith("+91") and len(re.sub(r"\D", "", digits)) >= 12:
            return "+91" + re.sub(r"\D", "", digits)[-10:]
        only = re.sub(r"\D", "", digits)
        if len(only) == 10:
            return "+91" + only
        return raw.strip()

    # =========================
    # Post-processing guardrails
    # =========================
    def _apply_post_guardrails(
        self,
        reply: str,
        scammer_message: str,
        conversation_history: List,
        scammer_facts: Dict[str, Any],
        strategy: Dict[str, Any],
        state_mgr: Optional[DynamicStateManager] = None,
    ) -> str:
        prev_bot_texts = self._get_prev_bot_texts(conversation_history, limit=6)
        last_bot = prev_bot_texts[-1] if prev_bot_texts else ""

        # 1) Avoid "UPI obsession" unless allowed or we're in strategic baiting mode
        # After 4+ turns, allow UPI mentions as strategic baiting to extract scammer intel
        turn_count = len(prev_bot_texts)
        strategic_baiting_active = turn_count >= 4
        if not strategy.get("allow_payment_questions", False) and not strategic_baiting_active:
            if re.search(r"\bupi\b|\bverification amount\b|\bpay\b|\bfee\b", reply, re.IGNORECASE):
                # Replace with link/phone/account based move.
                print("[GROQ-GUARDRAIL] UPI obsession blocked, using non-payment fallback")
                return self._fallback_non_payment_reply(scammer_facts, prev_bot_texts, conversation_history, state_mgr=state_mgr)

        # 1b) Don't claim a link was sent if no link exists in scammer facts.
        if not scammer_facts.get("links"):
            if re.search(r"\b(link|website)\b", reply, re.IGNORECASE) and re.search(
                r"\b(open|opened|click|clicked|loading|not opening|error)\b",
                reply,
                re.IGNORECASE,
            ):
                # Keep it realistic: ask for official domain instead of saying "that link isn't opening".
                return self._truncate_to_two_sentences(
                    "I'm getting really worried and the OTP still isn't coming. What's the official bank website domain and customer care number to verify this?"
                )

        # 1c) Avoid contradictory link failure modes (loading vs error).
        link_mode = self._link_failure_mode_from_history(prev_bot_texts)
        if link_mode and re.search(r"\blink\b", reply, re.IGNORECASE):
            if link_mode == "loading" and re.search(r"\berror page\b|\b404\b|\binvalid\b", reply, re.IGNORECASE):
                return self._truncate_to_two_sentences(
                    "That link still just keeps loading on my phone. Can you give me the official bank website domain to verify this?"
                )
            if link_mode == "error" and re.search(r"\bloading\b|\bnot opening\b", reply, re.IGNORECASE):
                return self._truncate_to_two_sentences(
                    "The link keeps showing an error page. Can you send the official bank website and a reference/case number?"
                )

        # 1d) If we asked for a case/reference number last time and scammer ignored, persist.
        # BUT: If scammer introduced a NEW topic (payment/transfer/UPI), engage with THAT instead.
        #      This prevents Logic Reset where bot ignores a ₹1 transfer to ask for case number.
        # LIMIT: Only persist for max 2 consecutive turns. After that, move on to
        #         strategic baiting / different engagement to avoid infinite loop.
        scammer_introduced_new_topic = bool(
            re.search(r"\b(upi|pay|payment|transfer|fee|fine|amount|rs\.?|inr|rupees?|\₹)\b", scammer_message, re.IGNORECASE)
            or re.search(r"\b([a-zA-Z0-9._-]+@[a-zA-Z0-9_-]+)\b", scammer_message)
        )
        if re.search(r"\b(case|reference)\b", last_bot, re.IGNORECASE):
            if not re.search(r"\b(case|reference|ref)\b", scammer_message, re.IGNORECASE) and not scammer_introduced_new_topic:
                # Count how many recent bot turns already asked for case/reference
                case_persist_count = sum(
                    1 for p in prev_bot_texts[-4:]
                    if re.search(r"\bcase.{0,10}reference|reference.{0,10}number\b", p, re.IGNORECASE)
                )
                if case_persist_count < 2:
                    return self._truncate_to_two_sentences(
                        "I still need the case/reference number to proceed. Please share that first so I can verify."
                    )
                # After 2 persists, fall through to let strategic baiting / other guardrails take over

        # 2) Avoid repeating previous replies (quick heuristic)
        low = reply.lower()
        if any(self._similar(low, p) for p in prev_bot_texts):
            print("[GROQ-GUARDRAIL] Repetition detected in post-guardrail, using fallback")
            return self._fallback_non_payment_reply(scammer_facts, prev_bot_texts, conversation_history, state_mgr=state_mgr)

        # 3) Ensure we acknowledge scammer facts when present (one of link/phone/account/upi)
        if self._has_any_fact(scammer_facts) and not self._mentions_any_fact(reply, scammer_facts):
            # Add a short acknowledgement prefix (still 1-2 sentences overall)
            prefix = self._ack_prefix(scammer_facts, state_mgr)
            stitched = f"{prefix} {reply}".strip()
            return self._truncate_to_two_sentences(stitched)

        # 4) SEMANTIC IGNORING FIX: If scammer just provided NEW data, validate it
        #    instead of ignoring. Ask a clarifying question about the data.
        #    ENHANCED: Mirror & Verify — repeat data back with doubt first.
        if state_mgr:
            new_facts = state_mgr._extract_facts_from_message(scammer_message)
            for fact_type, values in new_facts.items():
                for val in values:
                    # FIX BLOCK 2: Mirror & Verify — repeat data back with doubt
                    mirror_response = state_mgr.mirror_and_verify(fact_type, val)
                    if mirror_response and not self._mentions_any_fact(reply, scammer_facts):
                        return self._truncate_to_two_sentences(mirror_response)
                    # Fallback to validation question
                    question = state_mgr.get_fact_validation_question(fact_type, val)
                    if question and not self._mentions_any_fact(reply, scammer_facts):
                        return self._truncate_to_two_sentences(question)

        # 5) ANTI-ECHO: Strip full data values that have already been echoed
        if state_mgr:
            reply = self._strip_data_echoes(reply, state_mgr)

        # 6) STRATEGIC BAITING: If reply doesn't push for missing intel, append bait
        if state_mgr:
            missing = state_mgr.get_missing_facts()
            if missing and len(reply) < 150:
                # Check if reply already pushes for missing intel
                pushes_for_missing = False
                low = reply.lower()
                if "upi" in missing and re.search(r'\bupi\b|\bgoogle pay\b|\bphonepe\b', low):
                    pushes_for_missing = True
                if "link" in missing and re.search(r'\bwebsite\b|\burl\b|\blink\b|\bemail\b', low):
                    pushes_for_missing = True
                if "bank_account" in missing and re.search(r'\baccount\b.*\bnumber\b', low):
                    pushes_for_missing = True
                # After turn 5, force baiting every turn; before that, 70% chance
                turn_count = state_mgr.turn_count if state_mgr else 0
                bait_probability = 1.0 if turn_count >= 5 else 0.7
                if not pushes_for_missing and random.random() < bait_probability:
                    bait = state_mgr.get_strategic_bait()
                    if bait:
                        reply = self._truncate_to_two_sentences(reply + " " + bait)

        # 7) PHYSICAL CATASTROPHE GUARD: Strip unrealistic excuses that contradict fluent typing
        #    Replace with process confusion stalls from the Logical Barrier system.
        if state_mgr:
            catastrophe_patterns = [
                r'\b(spill(?:ed)?\s+tea|cracked\s+screen|power\s+(?:cut|went\s+out)|dropped\s+(?:my\s+)?phone)\b',
                r'\b(phone\s+fell|screen\s+(?:is\s+)?flickering|kitchen\s+sink|glasses?\s+broke)\b',
                r'\b(ceiling\s+fan\s+wire|charger\s+sparked|dog\s+knocked|overheating)\b',
                r'\b(battery\s+(?:at|is)\s+\d+\s*percent|running\s+to\s+get\s+charger)\b',
            ]
            has_catastrophe = any(re.search(p, reply, re.IGNORECASE) for p in catastrophe_patterns)
            if has_catastrophe:
                print("[GROQ-GUARDRAIL] Physical catastrophe detected, replacing with process confusion")
                stall = state_mgr.get_process_confusion_stall()
                reply = self._truncate_to_two_sentences(stall)

        # 8) EXCUSE REPETITION GUARD: Catch repeated tech excuses (e.g., 'not loading' used twice)
        if state_mgr:
            excuse_phrases = ['not loading', 'not opening', 'app is not', 'messaging app', 'screen is frozen', 'phone is frozen']
            prev_bot_texts_for_excuse = self._get_prev_bot_texts(conversation_history, limit=6)
            for phrase in excuse_phrases:
                if phrase in reply.lower():
                    # Check if this phrase was used before
                    prev_uses = sum(1 for p in prev_bot_texts_for_excuse if phrase in p)
                    if prev_uses > 0:
                        print(f"[GROQ-GUARDRAIL] Repeated excuse '{phrase}' detected, replacing with process confusion")
                        stall = state_mgr.get_process_confusion_stall()
                        reply = self._truncate_to_two_sentences(stall)
                        break

        # 9) STRUCTURAL MONOTONY BREAKER: Detect when consecutive responses follow the
        #    same structural pattern (e.g., "panic + data_ref + what_if + fear_lock") even
        #    though exact words differ. Forces a completely different response type.
        if state_mgr:
            if state_mgr.is_structurally_repetitive(reply):
                print(f"[GROQ-GUARDRAIL] Structural monotony detected (same pattern 3+ turns), forcing diversity break")
                diversity_reply = state_mgr.get_diversity_replacement()
                if diversity_reply:
                    reply = self._truncate_to_two_sentences(diversity_reply)

        # Record the structural skeleton of the final response for future comparison
        if state_mgr:
            state_mgr.record_response_skeleton(reply)

        return reply

    def _fallback_non_payment_reply(
        self,
        scammer_facts: Dict[str, Any],
        prev_bot_texts: List[str],
        conversation_history: List,
        state_mgr: Optional[DynamicStateManager] = None,
    ) -> str:
        """
        Non-payment fallback that stays realistic and avoids repetition.
        Uses state_mgr.used_fallback_responses to guarantee no exact repeats.
        """
        candidates: List[str] = []
        link_mode = self._link_failure_mode_from_history(prev_bot_texts)

        if scammer_facts.get("links"):
            if link_mode == "loading":
                candidates.extend(
                    [
                        "That link still isn't opening on my phone, it just keeps loading. What's the official bank website domain to verify this?",
                        "It's stuck on loading and won't open. Can you send the official website and a reference/case number?",
                    ]
                )
            elif link_mode == "error":
                candidates.extend(
                    [
                        "I clicked the link but it keeps showing an error page. Can you send the official website and a reference/case number?",
                        "It's showing an error/invalid page. What's the official bank website domain to verify this?",
                    ]
                )
            else:
                candidates.extend(
                    [
                        "That link isn't opening on my phone, it just keeps loading. What's the official bank website domain to verify this?",
                        "I clicked the link but it shows an error page. Can you send the official website and a reference/case number?",
                        "The site is asking for OTP but nothing came yet. What's the official customer care number from the bank website?",
                    ]
                )

        if scammer_facts.get("phone_numbers"):
            candidates.extend(
                [
                    "I'm calling the number you gave but it's busy. Is there another landline or extension number I can try?",
                    "I tried calling but it says switched off. Which branch/department are you from and what's your office number?",
                    "Call isn't going through from my side. Can you message me the official customer care number and your name/designation?",
                ]
            )

        if scammer_facts.get("bank_accounts"):
            acct = scammer_facts["bank_accounts"][0]
            acct_partial = acct[-4:] if len(acct) > 4 else acct
            candidates.extend(
                [
                    f"You mentioned the account ending {acct_partial}, but that doesn't match mine. Can you confirm the last 4 digits you have on record for me?",
                    f"Wait, repeat the account number ending {acct_partial} slowly, I'm writing it down. Which bank/branch is this linked to?",
                    f"I entered the number ending {acct_partial} and it says invalid. Can you tell me the bank name and your employee ID so I can verify?",
                ]
            )

        if scammer_facts.get("upi_ids"):
            upi = scammer_facts["upi_ids"][0]
            candidates.extend(
                [
                    f"I'm typing {upi} into my app but it says 'user not found'. Can you repeat the exact UPI handle?",
                    f"I'm confused — earlier you said account block/OTP, now UPI. What does UPI verification mean exactly?",
                ]
            )

        if not candidates:
            candidates = [
                "I'm really scared but no OTP is coming. Can you resend it and tell me what exact SMS sender name will show?",
                "I'm trying again but nothing is coming. Are you sure you have my correct registered number on your screen?",
                "This is stressing me out. Can you give me the official helpline number so I can verify this block?",
                "Wait, I see a button but it's greyed out. What do I do now? Which field should I click first?",
                "The page is asking for 'IFSC code' and 'MICR code.' Which one do you need from me?",
                "There's a dropdown showing 10 banks. Which one do I select? It doesn't have the one you mentioned.",
            ]

        # STRATEGIC BAITING: Always mix in UPI/link/account bait candidates
        # These push the scammer to provide missing intel types.
        strategic_baits = [
            "Can I just do this verification through UPI instead? What UPI ID should I use?",
            "My son set up PhonePe for me. If I need to pay, what UPI ID do I enter?",
            "Can you send me a link or email so I can verify this on the official website?",
            "I don't understand all this OTP business. Can I just transfer the amount through Google Pay? What is your UPI?",
            "My daughter says I should only do this on the official bank website. Can you share the URL?",
            "Wait, I saw something on my screen that says 'BANK-REF-4829'. Is that the reference number?",
        ]
        # Add baits that aren't too similar to what we already have
        for bait in strategic_baits:
            if not any(self._similar(bait.lower(), c.lower()) for c in candidates):
                candidates.append(bait)

        # Get previously used fallback responses from state manager (hard dedup)
        used_fallbacks = set()
        if state_mgr and hasattr(state_mgr, 'used_fallback_responses'):
            used_fallbacks = state_mgr.used_fallback_responses

        # TIER 1: Prefer candidates not similar to prev_bot_texts AND not previously used as fallback
        tier1 = [c for c in candidates
                 if c not in used_fallbacks
                 and not any(self._similar(c.lower(), p) for p in prev_bot_texts)]
        if tier1:
            chosen = random.choice(tier1)
            if state_mgr and hasattr(state_mgr, 'used_fallback_responses'):
                state_mgr.used_fallback_responses.add(chosen)
            return self._truncate_to_two_sentences(chosen)

        # TIER 2: Candidates not previously used (even if somewhat similar to history)
        tier2 = [c for c in candidates if c not in used_fallbacks]
        if tier2:
            chosen = random.choice(tier2)
            if state_mgr and hasattr(state_mgr, 'used_fallback_responses'):
                state_mgr.used_fallback_responses.add(chosen)
            return self._truncate_to_two_sentences(chosen)

        # TIER 3: All candidates exhausted — use process confusion stall (always unique)
        if state_mgr:
            stall = state_mgr.get_process_confusion_stall()
            if stall:
                state_mgr.used_fallback_responses.add(stall)
                return self._truncate_to_two_sentences(stall)

        # Last resort: random pick (all candidates were used, no state_mgr)
        chosen = random.choice(candidates)
        return self._truncate_to_two_sentences(chosen)

    def _has_any_fact(self, facts: Dict[str, Any]) -> bool:
        return bool(facts.get("links") or facts.get("phone_numbers") or facts.get("bank_accounts") or facts.get("upi_ids"))

    def _mentions_any_fact(self, reply: str, facts: Dict[str, Any]) -> bool:
        low = reply.lower()
        for link in facts.get("links", [])[:2]:
            domain = self._extract_domain(link)
            if (domain and domain in low) or link.lower() in low:
                return True
        for phone in facts.get("phone_numbers", [])[:2]:
            if re.sub(r"\D", "", phone) and re.sub(r"\D", "", phone) in re.sub(r"\D", "", reply):
                return True
        for acct in facts.get("bank_accounts", [])[:2]:
            if acct in low:
                return True
        for upi in facts.get("upi_ids", [])[:2]:
            if upi in low:
                return True
        return False

    def _ack_prefix(self, facts: Dict[str, Any], state_mgr: Optional[DynamicStateManager] = None) -> str:
        """Generate varied acknowledgment prefix — prevents Echo Loop."""
        if state_mgr:
            # Use state manager's varied prefix system to prevent repetition
            if facts.get("links"):
                domain = self._extract_domain(facts["links"][0])
                return state_mgr.get_varied_ack_prefix("link", domain)
            if facts.get("upi_ids"):
                return state_mgr.get_varied_ack_prefix("upi", facts["upi_ids"][0])
            if facts.get("phone_numbers"):
                return state_mgr.get_varied_ack_prefix("phone", facts["phone_numbers"][0])
            if facts.get("bank_accounts"):
                return state_mgr.get_varied_ack_prefix("bank_account", facts["bank_accounts"][0])
        else:
            # Fallback without state manager
            if facts.get("links"):
                domain = self._extract_domain(facts["links"][0])
                return f"I tried opening {domain},"
            if facts.get("phone_numbers"):
                digits = re.sub(r"\D", "", facts["phone_numbers"][0])
                tail = digits[-4:] if len(digits) >= 4 else digits
                return f"I noted the number ending {tail},"
            if facts.get("bank_accounts"):
                acct = str(facts["bank_accounts"][0])
                tail = acct[-4:] if len(acct) >= 4 else acct
                return f"Okay, I wrote down that account number ending {tail},"
            if facts.get("upi_ids"):
                return f"Okay, I wrote down {facts['upi_ids'][0]},"
        return "Okay,"

    def _truncate_to_two_sentences(self, text: str) -> str:
        parts = re.split(r"(?<=[.!?])\s+", text.strip())
        if len(parts) <= 2:
            return text.strip()
        return " ".join(parts[:2]).strip()

    def _strip_data_echoes(self, reply: str, state_mgr: DynamicStateManager) -> str:
        """Replace full data values with partial references after first echo.
        Prevents the bot from repeating '1234567890123456' or '+919876543210' every turn."""
        modified = reply
        # Check all data points that have been echoed at least once
        for data_val, count in list(state_mgr.data_echo_counts.items()):
            if count >= state_mgr.max_data_echo and len(data_val) >= 8:
                # Check if this value (or formatted versions) appears in the reply
                # Try raw digits
                if data_val in re.sub(r'[\s\-+]', '', modified):
                    partial = state_mgr.get_data_reference(data_val)
                    # Replace various formatted versions of the number
                    # Phone: +91-9876543210, +919876543210, 9876543210
                    # Account: 1234567890123456
                    patterns_to_try = [
                        re.escape(data_val),
                        # With +91 prefix
                        r'\+91[\s-]?' + re.escape(data_val[-10:]) if len(data_val) >= 10 else None,
                        # With spaces/dashes
                        r'[\s-]?'.join(re.escape(c) for c in data_val) if len(data_val) <= 16 else None,
                    ]
                    for pat in patterns_to_try:
                        if pat:
                            modified = re.sub(pat, partial, modified)

        # Track any full data values that remain in this response
        for fact_type, values in state_mgr._extract_facts_from_message(reply).items():
            for val in values:
                clean_val = re.sub(r'[\s\-+]', '', val)
                if len(clean_val) >= 8:
                    state_mgr.record_data_echo(clean_val)

        return modified

    def _similar(self, a: str, b: str) -> bool:
        # cheap similarity: shared long substring or very high overlap
        if not a or not b:
            return False
        if a == b:
            return True
        a2 = " ".join(a.split())
        b2 = " ".join(b.split())
        if len(a2) > 20 and a2 in b2:
            return True
        if len(b2) > 20 and b2 in a2:
            return True
        # token overlap — lowered from 0.85 to 0.70 to catch near-duplicate responses
        ta = set(a2.split())
        tb = set(b2.split())
        if not ta or not tb:
            return False
        overlap = len(ta & tb) / max(len(ta), 1)
        return overlap >= 0.70

    # =========================
    # Shared utilities
    # =========================
    def _clean_response(self, response: str) -> str:
        response = (response or "").replace("*", "").strip()
        if not response:
            return "Can you explain again? I'm really getting scared my account will get blocked."
        if response.startswith('"') and response.endswith('"'):
            response = response[1:-1]
        response = self._truncate_to_two_sentences(response)
        if len(response) > 220:
            response = response[:220].rstrip()
        # Avoid revealing detection
        forbidden = [
            "i know this is a scam",
            "you are a scammer",
            "this is fraud",
            "reported you",
            "i'm calling the police",
        ]
        if any(p in response.lower() for p in forbidden):
            print("[GROQ-SANITIZED] Blocked forbidden phrase, replacing response")
            return "I don't understand, but I'm really worried. Can you tell me the official customer care number to verify?"

        # Strip "oh no" and "my god this is too much" variants — unnatural phrasing
        import re as _re
        cleaned = _re.sub(r'\b[Oo]h\s+no\b[,!.;:\s]*', '', response, flags=_re.IGNORECASE).strip()
        cleaned = _re.sub(r'\b[Mm]y\s+[Gg]od[,!.;:\s]*(?:this is too much[,!.;:\s]*)?', '', cleaned, flags=_re.IGNORECASE).strip()
        # Strip leading punctuation left over
        cleaned = _re.sub(r'^[,!.;:\s]+', '', cleaned).strip()
        # Replace exclamation marks with periods for natural tone
        cleaned = cleaned.replace('!', '.')
        # Collapse double periods
        while '..' in cleaned:
            cleaned = cleaned.replace('..', '.')
        if len(cleaned) > 15:
            if cleaned != response:
                print(f"[GROQ-SANITIZED] Stripped 'Oh no' from response")
            response = cleaned
        else:
            # "Oh no" was the bulk of the response — replace entirely
            print("[GROQ-SANITIZED] 'Oh no' was bulk of response, replacing entirely")
            return "I don't understand, but I'm really worried. Can you tell me the official customer care number to verify?"

        return response

    def _get_prev_bot_texts(self, conversation_history: List, limit: int = 6) -> List[str]:
        """Extract recent honeypot replies from conversation history (sender == 'user')."""
        prev: List[str] = []
        recent = conversation_history[-(limit * 2) :] if len(conversation_history) > (limit * 2) else conversation_history
        for m in recent:
            sender = getattr(m, "sender", None)
            sender_value = getattr(sender, "value", str(sender))
            if sender_value == "user":
                t = str(getattr(m, "text", "")).strip().lower()
                if t:
                    prev.append(t)
        return prev[-limit:]

    def _pick_next_move(
        self,
        unique_moves: List[str],
        scammer_facts: Dict[str, Any],
        prev_bot_texts: List[str],
        needs_correction: bool,
    ) -> str:
        """
        Pick a single next-move to keep the model on-track (avoids drift/repetition).
        """
        if needs_correction:
            return (
                "Briefly correct yourself (you're panicking) and focus back on the block; "
                "say OTP isn't coming and ask for the official customer care number + official bank website."
            )

        wants_link_move = bool(scammer_facts.get("links")) and not any("link" in t or "website" in t for t in prev_bot_texts)
        wants_phone_move = bool(scammer_facts.get("phone_numbers")) and not any("call" in t or "number" in t for t in prev_bot_texts)
        wants_acct_move = bool(scammer_facts.get("bank_accounts")) and not any("account" in t or "digits" in t for t in prev_bot_texts)
        wants_upi_move = bool(scammer_facts.get("upi_ids")) and not any("upi" in t for t in prev_bot_texts)

        if wants_link_move:
            for m in unique_moves:
                if m.lower().startswith("say the link"):
                    return m
        if wants_phone_move:
            for m in unique_moves:
                if m.lower().startswith("say you're calling"):
                    return m
        if wants_acct_move:
            for m in unique_moves:
                if m.lower().startswith("read back the account"):
                    return m
        if wants_upi_move:
            for m in unique_moves:
                if "upi" in m.lower():
                    return m

        for m in unique_moves:
            if not any(self._similar(m.lower(), p) for p in prev_bot_texts):
                return m

        return unique_moves[0] if unique_moves else ""

    def _link_failure_mode_from_history(self, prev_bot_texts: List[str]) -> Optional[str]:
        """
        Track the last link failure mode to avoid contradictory claims.
        Returns "loading", "error", or None.
        """
        for t in reversed(prev_bot_texts or []):
            low = t.lower()
            if "link" in low or "website" in low:
                if re.search(r"\bloading\b|\bnot opening\b|\bkeeps loading\b", low):
                    return "loading"
                if re.search(r"\berror\b|\b404\b|\binvalid\b", low):
                    return "error"
        return None

    def _extract_domain(self, url: str) -> str:
        u = (url or "").strip().lower()
        u = re.sub(r"^https?://", "", u)
        return u.split("/")[0]

    def _format_history(self, conversation_history: List, limit: int = 8) -> List[Dict[str, str]]:
        formatted: List[Dict[str, str]] = []
        recent = conversation_history[-limit:] if len(conversation_history) > limit else conversation_history
        for msg in recent:
            sender_value = getattr(msg.sender, "value", str(getattr(msg, "sender", "")))
            text = str(getattr(msg, "text", "")).strip()
            if not text:
                continue
            formatted.append({"sender": sender_value, "text": text})
        return formatted

    def _safe_json_loads(self, content: str) -> Optional[Dict[str, Any]]:
        """Best-effort JSON parsing for LLM output."""
        if not content:
            return None
        try:
            return json.loads(content)
        except Exception:
            start = content.find("{")
            end = content.rfind("}")
            if start == -1 or end == -1 or end <= start:
                return None
            snippet = content[start : end + 1]
            try:
                return json.loads(snippet)
            except Exception:
                return None

    def _normalize_detection_result(self, raw: Dict[str, Any]) -> ScamDetectionResult:
        allowed_scam_types = {
            "phishing",
            "impersonation_threat",
            "lottery_scam",
            "job_scam",
            "phishing_link",
            "kyc_fraud",
            "generic_scam",
            "benign",
        }
        allowed_risk = {"low", "medium", "high", "critical"}

        is_scam = bool(raw.get("is_scam", False))
        confidence = self._clamp(raw.get("confidence", 0.0))
        scam_type_raw = str(raw.get("scam_type", "")).strip().lower()
        risk_raw = str(raw.get("risk_level", "")).strip().lower()

        if scam_type_raw not in allowed_scam_types:
            scam_type_raw = "generic_scam" if is_scam else "benign"

        if scam_type_raw == "benign":
            is_scam = False
            scam_type = None
            confidence = min(confidence, 0.39)
        else:
            scam_type = scam_type_raw
            if is_scam and confidence < 0.4:
                confidence = 0.4

        risk_level = risk_raw if risk_raw in allowed_risk else self._derive_risk(confidence, is_scam)

        indicators: List[ScamIndicator] = []
        raw_inds = raw.get("indicators", [])
        if isinstance(raw_inds, list):
            for item in raw_inds[:8]:
                if not isinstance(item, dict):
                    continue
                indicators.append(
                    ScamIndicator(
                        indicator_type=str(item.get("indicator_type", "llm_signal")).strip() or "llm_signal",
                        value=str(item.get("value", "signal")).strip() or "signal",
                        confidence=self._clamp(item.get("confidence", confidence)),
                        context=str(item.get("context", "")).strip() or None,
                    )
                )
        if is_scam and not indicators:
            indicators.append(
                ScamIndicator(
                    indicator_type="llm_signal",
                    value="scam_pattern_detected",
                    confidence=confidence,
                    context="AI classified this as likely scam content",
                )
            )

        return ScamDetectionResult(
            is_scam=is_scam,
            confidence=round(confidence, 2),
            indicators=indicators,
            scam_type=scam_type,
            risk_level=risk_level,
        )

    def _clamp(self, value: Any) -> float:
        try:
            num = float(value)
        except (TypeError, ValueError):
            num = 0.0
        return max(0.0, min(1.0, num))

    def _derive_risk(self, confidence: float, is_scam: bool) -> str:
        if not is_scam:
            return "low"
        if confidence >= 0.8:
            return "critical"
        if confidence >= 0.6:
            return "high"
        if confidence >= 0.4:
            return "medium"
        return "low"


groq_handler = GroqHandler()


