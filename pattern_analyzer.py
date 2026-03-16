import re
from enum import Enum


class ScamType(Enum):
    """Scam type categories"""
    KRA_IMPERSONATION = 'kra_impersonation', 'KRA Impersonation'
    MPESA_FRAUD       = 'mpesa_fraud',       'M-Pesa Fraud'
    BANK_IMPERSONATION= 'bank_impersonation','Bank Impersonation'
    LOTTERY_PRIZE     = 'lottery_prize',     'Lottery/Prize Scam'
    EMERGENCY_SCAM    = 'emergency_scam',    'Emergency Scam'
    LOAN_SCAM         = 'loan_scam',         'Loan Scam'
    INVESTMENT_SCAM   = 'investment_scam',   'Investment Scam'
    ROMANCE_SCAM      = 'romance_scam',      'Romance Scam'
    PHISHING          = 'phishing',          'Phishing'
    OTHER             = 'other',             'Other'

    def __new__(cls, value, label):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.label = label
        return obj


# Priority-ordered rules: first match wins.
# Each rule is (set_of_flags_that_trigger_this_type, ScamType)
# ALL listed flags must be present for the rule to match,
# OR any single flag if the set has only one entry.
_SCAM_TYPE_RULES = [
    # Single-flag triggers (most specific first)
    ({"impersonates_KRA"},                                  ScamType.KRA_IMPERSONATION),
    ({"impersonates_bank"},                                 ScamType.BANK_IMPERSONATION),
    ({"lottery_no_entry"},                                  ScamType.LOTTERY_PRIZE),
    ({"unsolicited_prize_notification"},                    ScamType.LOTTERY_PRIZE),
    ({"fake_reversal_trick"},                               ScamType.MPESA_FRAUD),
    ({"exploits_family_emergency"},                         ScamType.EMERGENCY_SCAM),
    ({"advance_fee_fraud"},                                 ScamType.LOAN_SCAM),
    ({"job_offer_with_fee"},                                ScamType.LOAN_SCAM),
    ({"offers_unrealistic_reward"},                         ScamType.INVESTMENT_SCAM),
    # Phishing covers any credential/identity harvest
    ({"requests_OTP"},                                      ScamType.PHISHING),
    ({"requests_PIN_or_password"},                          ScamType.PHISHING),
    ({"credential_phishing"},                               ScamType.PHISHING),
    ({"requests_account_details"},                          ScamType.PHISHING),
    # M-Pesa fraud: telecom impersonation + money transfer
    ({"impersonates_telecom", "requests_money_transfer"},   ScamType.MPESA_FRAUD),
    # Authority + payment demand without a more specific category
    ({"impersonates_authority", "demands_immediate_payment"}, ScamType.OTHER),
    # Police impersonation (distinct from KRA)
    ({"impersonates_police"},                               ScamType.OTHER),
]


def classify_scam_type(matched_flags: list) -> str | None:
    """
    Given a list of matched pattern flags, return the most relevant
    ScamType label string, or None if no scam is detected.
    """
    flag_set = set(matched_flags)
    if not flag_set:
        return None
    for required_flags, scam_type in _SCAM_TYPE_RULES:
        if required_flags.issubset(flag_set):
            return scam_type.label
    # Fallback: something was flagged but didn't match a specific category
    return ScamType.OTHER.label

# Pattern flags mapped to Kenyan-specific keywords and phrases
# Each entry: (list of regex patterns, weight 1-3)
# Weight 3 = critical indicator, 2 = strong, 1 = moderate

PATTERN_RULES = {
    "impersonates_KRA": (
        [r'\bKRA\b', r'kenya revenue authority', r'\bitax\b', r'tax compliance',
         r'itax', r'kra pin', r'tax discrepanc', r'unfiled returns', r'kra compliance',
         r'kra enforcement', r'unpaid taxes', r'tax penalty', r'tax audit'],
        2
    ),
    "impersonates_police": (
        [r'\bDCI\b', r'directorate of criminal', r'\bpolice\b', r'\bofficer\b',
         r'\binspector\b', r'\bsergeant\b', r'police station', r'criminal investigation',
         r'police officer', r'law enforcement'],
        2
    ),
    "impersonates_bank": (
        [r'equity bank', r'\bKCB\b', r'\bNCBA\b', r'co-operative bank', r'co operative bank',
         r'\bstanbic\b', r'\babsa\b', r'standard chartered', r'family bank',
         r'bank compliance', r'bank officer', r'bank security'],
        2
    ),
    "impersonates_telecom": (
        [r'\bsafaricom\b', r'\bairtel\b', r'\btelkom\b', r'm-pesa agent', r'mpesa agent',
         r'telecom officer', r'network compliance'],
        1
    ),
    "impersonates_authority": (
        [r'government officer', r'ministry of', r'county government', r'\bntsa\b',
         r'\bnhif\b', r'\bnssf\b', r'immigration officer', r'judiciary', r'court officer',
         r'kenya power', r'\bkplc\b', r'nairobi water', r'public health officer',
         r'national government'],
        2
    ),
    "demands_immediate_payment": (
        [r'pay now', r'pay immediately', r'send money', r'send.*m-?pesa', r'm-?pesa.*send',
         r'pay.*today', r'make payment now', r'transfer.*now',
         r'pay the amount', r'settle.*now', r'settle.*today', r'lipa sasa',
         r'tuma pesa', r'lipa.*haraka'],
        3
    ),
    "threatens_arrest_or_legal": (
        [r'\barrest\b', r'\bwarrant\b', r'court case', r'\bDPP\b', r'director of public prosecution',
         r'\bprosecute\b', r'\bprison\b', r'\bjail\b', r'criminal offense', r'criminal offence',
         r'taken into custody', r'legal action', r'forward your file', r'kukamatwa',
         r'kufungwa', r'mahakama'],
        3
    ),
    "threatens_account_suspension": (
        [r'freeze.*account', r'block.*account', r'suspend.*account', r'close.*account',
         r'deactivate.*account', r'account.*frozen', r'account.*blocked',
         r'account.*suspended', r'kuzuia akaunti', r'kufunga akaunti'],
        2
    ),
    "creates_false_urgency": (
        [r'within \d+ (hour|minute|min)', r'by \d+(am|pm)', r'right now',
         r'immediately', r'urgent', r'today only', r'expires today',
         r'no extensions', r'last chance', r'final notice', r'deadline',
         r'haraka', r'sasa hivi', r'dakika chache'],
        2
    ),
    "requests_OTP": (
        [r'\bOTP\b', r'one.time password', r'one.time code', r'verification code',
         r'code sent to you', r'code we sent', r'enter the code', r'confirm.*code',
         r'namba.*uliyopewa', r'msimbo'],
        3
    ),
    "requests_PIN_or_password": (
        [r'\bPIN\b', r'\bpassword\b', r'secret code', r'security code',
         r'account password', r'mpesa pin', r'm-pesa pin', r'banking password',
         r'usiri', r'nambari ya siri'],
        3
    ),
    "requests_ID_number": (
        [r'ID number', r'national ID', r'identity number', r'\bpassport\b',
         r'kra pin number', r'id namba', r'namba ya kitambulisho',
         r'kitambulisho chako'],
        2
    ),
    "requests_account_details": (
        [r'account number', r'bank account', r'sort code', r'account details',
         r'banking details', r'namba ya akaunti'],
        2
    ),
    "credential_phishing": (
        [r'verify your account', r'confirm your details', r'update your details',
         r'login details', r'access your account', r'validate your account',
         r'account verification', r'confirm.*identity'],
        2
    ),
    "lottery_no_entry": (
        [r'you have won', r'you\'ve won', r'lucky winner', r'\blottery\b',
         r'\bjackpot\b', r'you are selected', r'selected as.*winner',
         r'prize.*claim', r'claim.*prize', r'umeshinda', r'mshindi'],
        3
    ),
    "advance_fee_fraud": (
        [r'processing fee', r'handling fee', r'registration fee', r'small fee',
         r'administrative fee', r'release.*fee', r'clearance fee',
         r'ada ya usindikaji', r'malipo ya usajili'],
        3
    ),
    "fake_reversal_trick": (
        [r'sent.*by mistake', r'wrong.*number', r'wrong account', r'please reverse',
         r'kindly reverse', r'accidentally.*sent', r'nilituma kwa makosa',
         r'nirudishie'],
        3
    ),
    "offers_unrealistic_reward": (
        [r'million(s)? shilling', r'\bmillions\b', r'huge amount', r'large sum',
         r'windfall', r'unclaimed fund', r'inheritance.*fund',
         r'you.*inherit'],
        2
    ),
    "instructs_secrecy": (
        [r"don't tell", r'do not tell', r'keep.*confidential', r'keep.*secret',
         r'between us', r'private matter', r'tell no one', r'usimwambie',
         r'siri yetu'],
        2
    ),
    "exploits_family_emergency": (
        [r'accident', r'hospital', r'\binjured\b', r'\bemergency\b',
         r'critical condition', r'urgent.*help', r'family.*emergency',
         r'ajali', r'hospitalini', r'dharura'],
        2
    ),
    "job_offer_with_fee": (
        [r'job offer', r'vacancy', r'employment.*fee', r'application fee',
         r'registration.*job', r'nafasi ya kazi', r'kazi.*malipo'],
        2
    ),
    "requests_money_transfer": (
        [r'm-?pesa', r'paybill.*\d{4,}', r'till.*\d{4,}', r'send.*\d{3,}.*shilling',
         r'send.*ksh', r'transfer.*ksh', r'tuma.*ksh', r'lipa.*ksh'],
        2
    ),
    "unsolicited_prize_notification": (
        [r'congratulations.*won', r'you have been selected', r'randomly selected',
         r'our records show.*won', r'pongezi.*umeshinda'],
        3
    ),
}

# Weights that are considered critical — any single match already indicates high risk
CRITICAL_FLAGS = {
    "requests_OTP", "requests_PIN_or_password", "fake_reversal_trick",
    "lottery_no_entry", "advance_fee_fraud", "unsolicited_prize_notification",
    "threatens_arrest_or_legal", "exploits_family_emergency",
}


class PatternAnalyzer:
    def __init__(self):
        # Pre-compile all regexes for performance
        self.compiled_rules = {}
        for flag, (patterns, weight) in PATTERN_RULES.items():
            compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
            self.compiled_rules[flag] = (compiled, weight)

    def analyze(self, text: str) -> dict:
        """
        Analyze text for scam patterns.
        Returns:
            pattern_score: 0-100 float
            matched_flags: list of matched pattern flag names
            is_scam_pattern: bool (True if pattern_score >= 40)
        """
        if not text or not text.strip():
            return {"pattern_score": 0.0, "matched_flags": [], "is_scam_pattern": False, "scam_type": None}

        matched_flags = []
        total_weight = 0
        has_critical = False

        for flag, (patterns, weight) in self.compiled_rules.items():
            for pattern in patterns:
                if pattern.search(text):
                    matched_flags.append(flag)
                    total_weight += weight
                    if flag in CRITICAL_FLAGS:
                        has_critical = True
                    break  # one match per flag is enough

        # Score calculation:
        # Use a reference of 20 weight units = "definitely a scam"
        # (e.g. 4 strong flags × weight 5, or mix of moderate+critical)
        # This keeps individual matched flags meaningful rather than diluting
        # across all 23 possible flags.
        REFERENCE_WEIGHT = 20.0
        base_score = (total_weight / REFERENCE_WEIGHT) * 100

        n = len(matched_flags)
        if n == 0:
            pattern_score = 0.0
        elif n == 1 and not has_critical:
            # Single weak match: low confidence, cap at 25%
            pattern_score = min(base_score * 1.0, 25.0)
        elif has_critical:
            # Any critical flag raises floor to 60%
            pattern_score = max(base_score * 1.5, 60.0)
        else:
            # Multiple non-critical matches: amplify moderately
            pattern_score = min(base_score * 1.5, 95.0)

        pattern_score = min(round(pattern_score, 1), 100.0)
        is_scam = pattern_score >= 40.0

        return {
            "pattern_score": pattern_score,
            "matched_flags": matched_flags,
            "is_scam_pattern": is_scam,
            "scam_type": classify_scam_type(matched_flags) if is_scam else None,
        }


# Singleton for import
_analyzer = None

def get_analyzer() -> PatternAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = PatternAnalyzer()
    return _analyzer


if __name__ == "__main__":
    analyzer = PatternAnalyzer()

    tests = [
        ("Hello, this is Officer James Mwangi from Kenya Revenue Authority. "
         "Your unpaid taxes of KSh 45,000 must be paid within 2 hours via M-Pesa "
         "or we will issue a warrant for your arrest.",
         "KRA arrest threat scam"),

        ("Congratulations! You have won KSh 500,000 in our lucky draw. "
         "To claim your prize, pay a processing fee of KSh 2,000 via paybill 123456.",
         "Lottery + fee scam"),

        ("Your M-Pesa OTP is 847291. Please do not share this code with anyone.",
         "Legitimate OTP message"),

        ("Hi, I sent money to your number by mistake. Please reverse KSh 3,000 back to me.",
         "Fake reversal scam"),

        ("Good morning! This is Equity Bank calling to confirm your appointment "
         "with our mortgage advisor on Friday at 2 PM.",
         "Legitimate bank call"),

        ("This is KRA enforcement. Your iTax account shows three years of unfiled returns. "
         "We are closing your business unless you pay KSh 85,000 right now. "
         "Send money to paybill 247247 and send us the transaction code.",
         "KRA enforcement scam"),

        ("Your Safaricom bill is ready. Please pay KSh 1,200 via M-Pesa paybill 100100.",
         "Legit bill payment"),
    ]

    print("=" * 70)
    print("PATTERN ANALYZER TEST")
    print("=" * 70)
    for text, desc in tests:
        result = analyzer.analyze(text)
        verdict = "SCAM" if result["is_scam_pattern"] else "LEGIT"
        print(f"\n[{verdict}] {desc}")
        print(f"  Score: {result['pattern_score']}%")
        if result["matched_flags"]:
            print(f"  Flags: {', '.join(result['matched_flags'])}")
        else:
            print(f"  Flags: none")
    print("\n" + "=" * 70)
