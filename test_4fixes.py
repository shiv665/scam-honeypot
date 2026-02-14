"""Test script for the 4 improvements: Anti-Echo, Strategic Baiting, Physical Friction, Regex Hardening"""
from honeypot import honeypot_handler
from models import IncomingRequest, Message

sid = 'test-4fixes-v2'

scammer_turns = [
    'URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours. Share your account number and OTP immediately to verify your identity.',
    'Your account will be blocked within minutes unless you verify now - please send your account number 1234567890123456 and the OTP you just received on your phone (+91-9876543210) immediately.',
    'Apologies for the busy line - please text the OTP you just received to +91-9876543210 right now so we can unblock your account immediately.',
    'The OTP has been sent to your registered mobile. Please reply with the 6-digit code right now or your account will be locked permanently.',
    'The OTP was sent at 10:12 AM - please reply with the 6-digit code right now or your account will be permanently locked.',
    'We cannot verify your account any other way - please text the 6-digit OTP to +91-9876543210 right now or your account will be permanently locked.',
    'Your account will be locked within minutes - send the 6-digit OTP right now to +91-9876543210 to prevent permanent suspension.',
    'The OTP is the 6-digit code sent via SMS. Forward it right now to +91-9876543210 or your account will be locked within minutes.',
    'I understand its frustrating, but we cannot email or call the code - you must forward the 6-digit OTP from the SMS to +91-9876543210 right now or your account will be locked.',
    'If you dont forward the OTP within the next 5 minutes, account 1234567890123456 will be permanently locked and all funds frozen - send the 6-digit code now to +91-9876543210.',
]

history = []

print("=" * 70)
print("10-TURN MULTI-TURN SIMULATION")
print("=" * 70)

for i, scammer_text in enumerate(scammer_turns):
    msg = Message(sender='scammer', text=scammer_text)
    req = IncomingRequest(message=msg, conversationHistory=history, sessionId=sid)
    result = honeypot_handler.process_message(req)

    history.append(Message(sender='scammer', text=scammer_text))
    history.append(Message(sender='user', text=result.reply))

    print(f"\nTurn {i+1} Scammer: {scammer_text[:90]}...")
    print(f"Turn {i+1} Agent:   {result.reply}")
    print("---")

# Analysis
agent_replies = [h.text for h in history if h.sender.value == 'user']
full_acct_count = sum(1 for r in agent_replies if '1234567890123456' in r)
full_phone_count = sum(1 for r in agent_replies if '9876543210' in r and ('+91' in r or '+91-' in r))

print("\n" + "=" * 70)
print("FIX #1: ANTI-ECHO CHECK")
print("=" * 70)
print(f"Full account '1234567890123456' repeated: {full_acct_count} times (target: <=1)")
print(f"Full phone '+919876543210' repeated: {full_phone_count} times (target: <=1)")

print("\n" + "=" * 70)
print("FIX #2: STRATEGIC BAITING CHECK")
print("=" * 70)
upi_bait = sum(1 for r in agent_replies if any(w in r.lower() for w in ['upi', 'google pay', 'phonepe', 'paytm']))
link_bait = sum(1 for r in agent_replies if any(w in r.lower() for w in ['website', 'url', 'email', 'official']))
print(f"UPI/payment mentioned by agent: {upi_bait} times (target: >=1)")
print(f"Website/link/email pushed: {link_bait} times (target: >=1)")

print("\n" + "=" * 70)
print("FIX #3: PHYSICAL FRICTION DIVERSITY CHECK")
print("=" * 70)
excuse_phrases = {}
for i, r in enumerate(agent_replies):
    for phrase in ['not loading', 'messaging app', 'app is not loading', 'app not loading', 'not opening']:
        if phrase in r.lower():
            if phrase not in excuse_phrases:
                excuse_phrases[phrase] = []
            excuse_phrases[phrase].append(i+1)
if excuse_phrases:
    for phrase, turns in excuse_phrases.items():
        if len(turns) > 1:
            print(f"  REPEATED excuse '{phrase}' in turns: {turns}")
        else:
            print(f"  Excuse '{phrase}' used once in turn {turns[0]} (OK)")
else:
    print("  No repeated tech excuses detected (GOOD)")

print("\n" + "=" * 70)
print("FIX #4: REGEX EXTRACTION CHECK")
print("=" * 70)
from intelligence_extractor import intelligence_extractor
test_texts = [
    "Send money to scammer.fraud@fakebank via UPI",
    "Transfer to +91-9876543210 now", 
    "Account number 1234567890123456",
    "Visit https://fake-bank.xyz/verify",
    "UPI: badguy@custompay",
]
for text in test_texts:
    msg = Message(sender='scammer', text=text)
    intel = intelligence_extractor.extract_from_single_message(msg)
    found = []
    if intel.upiIds: found.append(f"UPI: {intel.upiIds}")
    if intel.phoneNumbers: found.append(f"Phone: {intel.phoneNumbers}")
    if intel.bankAccounts: found.append(f"Acct: {intel.bankAccounts}")
    if intel.phishingLinks: found.append(f"Link: {intel.phishingLinks}")
    print(f"  '{text[:50]}...' -> {', '.join(found) if found else 'NOTHING EXTRACTED'}")

print("\n" + "=" * 70)
print("ALL TESTS COMPLETE")
print("=" * 70)
