"""
Pattern engine — Is This Phishy v1.
50 compiled regex patterns across 10 scam categories.
"""
import re
from dataclasses import dataclass


@dataclass
class PatternHit:
    type: str
    detail: str
    score: int
    category: str  # scam category label


@dataclass
class CompiledPattern:
    name: str
    regex: re.Pattern
    reason: str
    score: int
    category: str


_RAW_PATTERNS: list[tuple[str, str, str, int, str]] = [
    # (name, regex, reason, score, category)

    # ── PHISHING ──────────────────────────────────────────────────────────────
    ("account_suspended",
     r'(?:your\s+)?account\s+(?:has\s+been\s+)?(?:suspended|locked|disabled|restricted|limited)',
     "Claims your account has been suspended — classic phishing trigger", 20, "phishing"),

    ("verify_account",
     r'(?:verify|confirm|validate)\s+(?:your\s+)?(?:account|identity|details|information)',
     "Asks you to verify account details — common phishing pattern", 18, "phishing"),

    ("click_to_verify",
     r'click\s+(?:here|below|the\s+link)\s+(?:to\s+)?(?:verify|confirm|activate|update|access)',
     "Instructs you to click a link to verify — phishing lure", 18, "phishing"),

    ("update_payment",
     r'update\s+(?:your\s+)?(?:payment|billing|credit\s+card|bank)\s+(?:details|information|method)',
     "Requests payment detail update — financial credential phishing", 22, "phishing"),

    ("login_required",
     r'(?:log\s*in|sign\s*in)\s+(?:immediately|now|urgently|to\s+avoid)',
     "Urgent login demand — designed to panic the recipient", 15, "phishing"),

    ("account_will_be_closed",
     r'(?:account|subscription|service)\s+(?:will\s+be\s+|is\s+about\s+to\s+be\s+)?(?:closed|terminated|cancelled|deleted)',
     "Threatens account closure — urgency-based phishing", 20, "phishing"),

    ("security_alert_fake",
     r'(?:security\s+alert|security\s+warning|unusual\s+(?:login|activity|sign.in)).{0,30}(?:verify|confirm|click|link)',
     "Fake security alert asking you to verify — credential phishing", 22, "phishing"),

    ("suspicious_link_text",
     r'(?:click|tap|open|visit)\s+(?:the\s+)?(?:link|url|site|website)\s+(?:below|above|here|now)',
     "Generic 'click the link' call to action — phishing delivery", 12, "phishing"),

    ("shortened_url",
     r'(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|rb\.gy|short\.io|tiny\.cc)/\S+',
     "Uses a URL shortener — hides the real destination", 15, "phishing"),

    # ── DELIVERY SCAMS ────────────────────────────────────────────────────────
    ("parcel_waiting",
     r'(?:parcel|package|delivery|shipment)\s+(?:is\s+)?(?:waiting|pending|on\s+hold|failed|undelivered)',
     "Claims you have a parcel waiting — delivery impersonation scam", 18, "delivery"),

    ("delivery_fee",
     r'(?:pay|payment\s+of)\s+(?:a\s+)?(?:small\s+)?(?:fee|charge|amount)\s+(?:to\s+)?(?:release|deliver|receive)',
     "Asks for a fee to release a delivery — parcel scam", 22, "delivery"),

    ("reschedule_delivery",
     r'reschedule\s+(?:your\s+)?(?:delivery|shipment)\s+(?:by\s+clicking|via|at)',
     "Prompts delivery rescheduling via a link — delivery scam", 15, "delivery"),

    # ── PRIZE / LOTTERY ───────────────────────────────────────────────────────
    ("you_have_won",
     r'(?:you\s+(?:have\s+)?(?:won|been\s+selected|been\s+chosen)|congratulations.{0,30}(?:winner|prize|reward))',
     "Claims you have won a prize — lottery/sweepstakes scam", 22, "prize"),

    ("claim_prize",
     r'claim\s+(?:your\s+)?(?:prize|reward|winnings|gift|voucher)',
     "Instructs you to claim a prize — unsolicited reward scam", 18, "prize"),

    ("selected_randomly",
     r'(?:randomly|specially)\s+selected\s+(?:from|as)',
     "Claims you were randomly selected — lottery scam", 15, "prize"),

    # ── FINANCIAL / TAX ───────────────────────────────────────────────────────
    ("tax_refund",
     r'(?:tax\s+refund|ato\s+refund|tax\s+return)\s+(?:of|worth|for)\s+[\$\d]',
     "Promises a tax refund — ATO impersonation scam", 22, "government"),

    ("investment_guaranteed",
     r'guaranteed\s+(?:\S+\s+){0,3}(?:returns?|profit|income|earnings?|investment)|'
     r'(?:returns?|profit|income|earnings?)\s+(?:are\s+)?guaranteed',
     "Promises guaranteed investment returns — investment scam hallmark", 20, "investment"),

    ("crypto_opportunity",
     r'(?:bitcoin|crypto|cryptocurrency)\s+(?:investment|opportunity|platform|trading)',
     "Promotes a crypto investment opportunity — high-risk scam", 18, "investment"),

    ("wire_transfer",
     r'(?:wire|transfer|send)\s+(?:money|funds|payment)\s+(?:to|via|using)',
     "Requests a money transfer — financial fraud", 20, "phishing"),

    ("overdue_payment",
     r'(?:overdue|outstanding)\s+(?:payment|debt|fine|fee|tax)',
     "Claims you have an overdue payment — debt/fine scam", 18, "government"),

    # ── GOVERNMENT IMPERSONATION ──────────────────────────────────────────────
    ("government_action",
     r'(?:centrelink|ato|mygov|mygovid|police|court|legal\s+action)\s+.{0,30}(?:action|notice|warrant|fine|penalty)',
     "Threatens government action — authority impersonation scam", 22, "government"),

    ("medicare_card_scam",
     r'(?:medicare|health\s+insurance)\s+.{0,30}(?:expires?|expired|renew|update|verify)',
     "Claims Medicare card needs renewal — government impersonation", 20, "government"),

    # ── URGENCY / PRESSURE ────────────────────────────────────────────────────
    ("urgent_action",
     r'urgent\s*(?:action|response|attention|notice|message)',
     "Uses 'urgent action required' language — pressure tactic", 15, "phishing"),

    ("expires_soon",
     r'(?:expires?|expiring)\s+(?:in\s+)?(?:\d+\s+hours?|\d+\s+minutes?|today|tonight|soon)',
     "Creates artificial time pressure — scam urgency tactic", 15, "phishing"),

    ("final_warning",
     r'(?:final|last)\s+(?:warning|notice|chance|reminder)\s+before',
     "Issues a 'final warning' — intimidation tactic", 18, "phishing"),

    # ── OTP / CREDENTIAL THEFT ────────────────────────────────────────────────
    ("otp_request",
     r'(?:otp|one.time\s+(?:password|code|pin)|verification\s+code)\s+.{0,20}(?:share|send|provide|enter)',
     "Asks you to share a one-time password — credential theft", 25, "phishing"),

    # ── REMOTE ACCESS / TECH SUPPORT ─────────────────────────────────────────
    ("remote_access",
     r'(?:download|install|run)\s+.{0,20}(?:teamviewer|anydesk|remote\s+desktop|remote\s+access)',
     "Asks you to install remote access software — tech support scam", 28, "tech_support"),

    ("tech_support",
     r'(?:microsoft|apple|telstra|nbn|optus)\s+.{0,30}(?:technician|support|department|team)\s+.{0,20}(?:detected|found|identified)',
     "Impersonates tech company support — tech support scam", 22, "tech_support"),

    # ── GIFT CARD SCAMS ───────────────────────────────────────────────────────
    ("gift_card_payment",
     r'(?:pay|purchase|buy)\s+.{0,20}(?:gift\s+card|itunes|google\s+play|steam\s+card)',
     "Requests payment via gift cards — gift card scam", 25, "phishing"),

    # ── ADVANCE FEE ───────────────────────────────────────────────────────────
    ("advance_fee",
     r'(?:advance\s+fee|processing\s+fee|administration\s+(?:fee|charge))\s+.{0,20}(?:release|transfer|receive)',
     "Asks for an advance fee to receive money — advance fee fraud", 25, "phishing"),

    # ── JOB SCAMS ─────────────────────────────────────────────────────────────
    ("job_easy_money",
     r'(?:work\s+from\s+home|work\s+anywhere|earn\s+from\s+home).{0,40}(?:\$\d+|\d+\s*(?:dollars?|AUD)|per\s+(?:day|hour|week))',
     "Promises easy money working from home — job scam", 25, "job"),

    ("job_no_experience",
     r'(?:no\s+experience|no\s+skills?|no\s+qualifications?)\s+(?:needed|required|necessary)',
     "Promises income with no experience required — job scam", 20, "job"),

    ("job_reply_to_start",
     r'(?:reply|text|message|dm|whatsapp)\s+.{0,15}(?:yes|start|join|interested)\s+(?:to|and)',
     "Asks you to reply a keyword to start — job/prize scam", 18, "job"),

    ("job_per_day_income",
     r'\$\s*\d{3,}\s*(?:per\s+day|\/day|a\s+day).{0,40}(?:work|earn|income|job)',
     "Promises specific high daily income — job scam", 22, "job"),

    ("job_part_time_income",
     r'(?:part.time|spare\s+time|side\s+hustle|extra\s+cash|extra\s+income).{0,30}(?:\$\d+|\d+\s*dollars?|earn)',
     "Promises side income in spare time — job scam pattern", 18, "job"),

    # ── INVESTMENT / CRYPTO SCAMS ─────────────────────────────────────────────
    ("investment_returns_pct",
     r'\d{2,4}\s*%\s+(?:returns?|profits?|gains?|(?:last\s+)?(?:month|week|day)|monthly|weekly|daily|per\s+(?:month|week|day))',
     "Promises specific high percentage returns — investment scam", 25, "investment"),

    ("crypto_bot_trading",
     r'(?:trading\s+bot|crypto\s+bot|automated\s+trading|ai\s+trading).{0,30}(?:profit|earn|returns?|\$\d+)',
     "Promotes crypto trading bot profits — investment scam", 22, "investment"),

    ("investment_dm_me",
     r'(?:dm\s+me|message\s+me|contact\s+me|whatsapp\s+me).{0,30}(?:invest|profit|earn|opportunity|returns?)',
     "Asks you to DM for investment details — social media investment scam", 28, "investment"),

    ("passive_income",
     r'(?:passive\s+income|financial\s+freedom|be\s+your\s+own\s+boss).{0,40}(?:invest|crypto|trading|\$\d+|opportunity)',
     "Promises passive income or financial freedom — investment scam", 18, "investment"),

    ("investment_limited_spots",
     r'(?:limited\s+spots?|limited\s+positions?|only\s+\d+\s+spots?).{0,30}(?:invest|earn|profit|join|opportunity)',
     "Creates urgency with limited spots — investment scam pressure tactic", 18, "investment"),

    # ── SEXTORTION / BLACKMAIL ────────────────────────────────────────────────
    ("sextortion_photos",
     r'(?:nude|naked|explicit|intimate)\s+(?:photos?|pictures?|videos?|images?|footage)\s+(?:of\s+you|you\s+sent)',
     "Claims to have intimate images — sextortion scam", 30, "blackmail"),

    ("sextortion_threat",
     r'(?:i\s+will\s+send|i\'ll\s+send|will\s+be\s+sent|will\s+share|will\s+expose).{0,30}(?:friends?|family|contacts?|everyone)',
     "Threatens to share compromising material — blackmail/sextortion", 28, "blackmail"),

    ("sextortion_pay_or",
     r'(?:pay|send|transfer)\s+.{0,20}(?:bitcoin|crypto|btc|monero).{0,30}(?:\bor\b|otherwise|else)',
     "Demands crypto payment under threat — sextortion scam", 28, "blackmail"),

    ("blackmail_recording",
     r'(?:webcam|camera|screen|device|computer).{0,20}(?:footage|recording|video|hacked|compromised|accessed)|(?:recorded|hacked|compromised|accessed).{0,20}(?:webcam|camera|screen|device|computer)',
     "Claims to have secretly recorded you — blackmail scam", 25, "blackmail"),

    # ── TOLL ROAD / TRAFFIC FINE (AU) ────────────────────────────────────────
    ("toll_road_scam",
     r'(?:linkt|e-toll|etoll|roam\.com\.au|mylinkt).{0,40}(?:unpaid|outstanding|overdue|fine|penalty|pay)',
     "Impersonates Australian toll road operator — toll scam", 25, "government"),

    ("traffic_fine_scam",
     r'(?:unpaid|outstanding)\s+(?:toll|fine|infringement|penalty)\s+.{0,20}(?:\$\d+|pay|due)',
     "Claims you have an unpaid traffic fine — fine scam", 22, "government"),


    # ── PACKAGE TRACKING PHISH ────────────────────────────────────────────────
    ("package_tracking_link",
     r'(?:track|tracking)\s+(?:your\s+)?(?:parcel|package|delivery|shipment)\s+.{0,20}(?:http|www|click|here)',
     "Fake package tracking link — common smishing vector", 18, "delivery"),

    # ── FAKE SURVEY / REWARD ──────────────────────────────────────────────────
    ("fake_survey_reward",
     r'(?:complete|fill\s+in|answer)\s+(?:a\s+)?(?:short\s+)?(?:survey|questionnaire).{0,30}(?:reward|voucher|gift|\$\d+|prize)',
     "Survey promising a reward — common lead-gen scam", 18, "prize"),

    # ── ROMANCE SCAM ─────────────────────────────────────────────────────────
    ("romance_found_number",
     r'(?:found\s+your\s+(?:number|profile|contact)|(?:came\s+across|stumbled\s+(?:on|upon))\s+your)',
     "Claims to have found your number randomly — romance scam opener", 15, "romance"),

    ("romance_investment_pivot",
     r'(?:i\s+can\s+teach\s+you|let\s+me\s+show\s+you|i\s+know\s+a\s+way).{0,40}(?:invest|crypto|earn|profit|trading)',
     "Pivots from friendly contact to investment pitch — pig butchering scam", 25, "romance"),
]


PATTERNS: list[CompiledPattern] = [
    CompiledPattern(
        name=name,
        regex=re.compile(pattern, re.IGNORECASE | re.DOTALL),
        reason=reason,
        score=score,
        category=category,
    )
    for name, pattern, reason, score, category in _RAW_PATTERNS
]


def evaluate_patterns(text: str) -> list[PatternHit]:
    return [
        PatternHit(type=p.name, detail=p.reason, score=p.score, category=p.category)
        for p in PATTERNS
        if p.regex.search(text)
    ]
