"""
Feature extraction layer — v3.

Changes from v2:
  - Added 'risk', 'at risk' to _URGENCY_WORDS (real threat language)
  - Added suspicious_domain field: brand name appears in URL hostname but
    it is NOT the official domain (lookalike domain detection)
  - Added is_local_au_number / is_foreign_number split (replaces is_international)
  - Exported AU_LOCAL_PHONE_RE for use in rules.py callback detection
"""
import re
from dataclasses import dataclass, field



# ── Homoglyph / Unicode normalisation ────────────────────────────────────────
# Maps common look-alike Unicode characters to their ASCII equivalents so that
# brand detection catches "PaypaΙ" (Greek iota), "amaz0n", "m!crosoft" etc.
_HOMOGLYPH_MAP: dict[str, str] = {
    'Ι': 'I', 'Ӏ': 'I', 'І': 'I',  # Cyrillic/Greek uppercase I
    'l': 'l',                                   # already ASCII l, covered
    '0': '0',                                   # digit zero  (already ASCII)
    'à': 'a', 'á': 'a', 'â': 'a', 'ã': 'a', 'ä': 'a',
    'è': 'e', 'é': 'e', 'ê': 'e', 'ë': 'e',
    'ì': 'i', 'í': 'i', 'î': 'i', 'ï': 'i',
    'ó': 'o', 'ô': 'o', 'õ': 'o', 'ö': 'o',
    'A': 'A',  # fullwidth A
    '1': '1',  # digit 1 (already ASCII, no-op but explicit)
}


def _normalize_homoglyphs(text: str) -> str:
    """Replace common look-alike Unicode characters with ASCII equivalents."""
    return ''.join(_HOMOGLYPH_MAP.get(c, c) for c in text)

# ── Compiled regexes ──────────────────────────────────────────────────────────

_URL_RE = re.compile(
    r'https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?',
    re.IGNORECASE,
)

# Australian local numbers (mobile 04xx, landline 02/03/07/08, 13xx, 1300, 1800)
AU_LOCAL_PHONE_RE = re.compile(
    r'(?<!\+)0[2-478](?:[ -]?\d){8}|'   # local mobile/landline
    r'\b13\d{4}\b|'                       # 13xx short codes
    r'\b1[38]00\s*\d{3}\s*\d{3}\b',      # 1300/1800 freecall
    re.IGNORECASE,
)

# International numbers that are NOT Australian (+61 is AU)
# Handles spaced/hyphenated formats like +44 20 7946 0958
_FOREIGN_PHONE_RE = re.compile(r'\+(?!61)\d[\d\s\-\(\)]{6,}')

# Any phone (for has_phone field — keeps existing behaviour)
_PHONE_RE = re.compile(
    r'(\+?61|0)[2-478](?:[ -]?\d){7,9}|'
    r'(\+?1)?[\s\-\.]?\(?\d{3}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{4}|'
    r'\+\d{7,15}',
    re.IGNORECASE,
)

_CURRENCY_RE = re.compile(
    r'[\$€£¥₹]\s*[\d,]+|[\d,]+\s*(?:AUD|USD|EUR|GBP)',
    re.IGNORECASE,
)

_SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.click', '.tk', '.ml', '.ga', '.cf',
    '.gq', '.pw', '.zip', '.loan', '.win',
}

# Brands and their canonical domains
_KNOWN_BRANDS: list[str] = [
    'commbank', 'commonwealth bank', 'nab', 'westpac', 'anz', 'macquarie',
    'auspost', 'australia post', 'ato', 'centrelink', 'mygov',
    'paypal', 'paypaι', 'pay pal', 'apple', 'microsoft', 'amazon', 'netflix',
    'telstra', 'optus', 'vodafone', 'ebay', 'google',
]

_BRAND_DOMAINS: dict[str, str] = {
    'commbank':          'commbank.com.au',
    'commonwealth bank': 'commbank.com.au',
    'nab':               'nab.com.au',
    'westpac':           'westpac.com.au',
    'anz':               'anz.com.au',
    'macquarie':         'macquarie.com.au',
    'auspost':           'auspost.com.au',
    'australia post':    'auspost.com.au',
    'ato':               'ato.gov.au',
    'centrelink':        'servicesaustralia.gov.au',
    'mygov':             'my.gov.au',
    'paypal':            'paypal.com',
    'paypaι':            'paypal.com',
    'pay pal':           'paypal.com',
    'apple':             'apple.com',
    'microsoft':         'microsoft.com',
    'amazon':            'amazon.com',
    'netflix':           'netflix.com',
    'telstra':           'telstra.com.au',
    'optus':             'optus.com.au',
    'ebay':              'ebay.com.au',
    'google':            'google.com',
}

# Urgency words ordered longest-first to support dedup logic in _find_urgency().
# Word-boundary regex matching prevents 'immediate' matching inside 'immediately'.
_URGENCY_WORDS_RAW: list[str] = [
    'urgent', 'immediate', 'immediately', 'asap', 'now', 'today only',
    'expires', 'limited time', 'act now', 'final notice', 'last chance',
    'warning', 'alert', 'critical', 'deadline', 'overdue',
    # v3: explicit threat/risk language
    'at risk', 'risk',
]

# Compiled word-boundary patterns — prevents substring double-counting
_URGENCY_PATTERNS: list[tuple[str, re.Pattern]] = [
    (w, re.compile(r'\b' + re.escape(w) + r'\b', re.IGNORECASE))
    for w in _URGENCY_WORDS_RAW
]


def _find_urgency(lower: str) -> list[str]:
    """
    Match urgency words with word boundaries and deduplicate substrings.
    Returns e.g. ['immediately', 'at risk'] NOT ['immediate', 'immediately', 'at risk', 'risk'].
    """
    matched = [w for w, pat in _URGENCY_PATTERNS if pat.search(lower)]
    # Remove any word that is a strict substring of a longer already-kept match
    result: list[str] = []
    for w in sorted(matched, key=len, reverse=True):
        if not any(w in kept for kept in result):
            result.append(w)
    return result

_SUSPICIOUS_KEYWORDS: list[str] = [
    'bank', 'account', 'verify', 'verification', 'suspend', 'suspended',
    'confirm', 'password', 'login', 'credential', 'secure', 'update',
    'auspost', 'australia post', 'ato', 'centrelink', 'mygov',
    'paypal', 'ebay', 'amazon', 'apple', 'microsoft', 'google',
    'bitcoin', 'crypto', 'investment', 'prize', 'winner', 'lottery',
    'refund', 'tax', 'irs', 'police', 'court', 'legal', 'warrant',
    'otp', 'one-time', 'pin', 'cvv', 'card number',
    'virus', 'malware', 'infected', 'detected', 'breach', 'hacked', 'compromised',
    'arrest', 'debt', 'overdue', 'proceedings', 'penalty',
]

# Action keywords — exported for rules.py
ACTION_KEYWORDS: list[str] = [
    'click', 'tap', 'verify', 'confirm', 'validate',
    'log in', 'sign in', 'pay now', 'update', 'enter your',
]

# URL shortener hostnames
_URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'rb.gy', 'short.io', 'tiny.cc', 'is.gd', 'buff.ly',
}

# Suspicious words inside URL paths/hostnames (tiered scoring in rules.py)
SUSPICIOUS_DOMAIN_WORDS = ['secure', 'login', 'verify', 'account', 'update', 'alert']

# Payment-related keywords (named feature for rules.py)
PAYMENT_KEYWORDS: list[str] = [
    'pay', 'payment', 'fee', 'charge', 'invoice', 'overdue',
    'credit card', 'debit', 'transfer', 'wire', 'bitcoin',
    'gift card', 'itunes', 'google play',
]

# Account threat keywords (named feature for rules.py)
ACCOUNT_THREAT_KEYWORDS: list[str] = [
    'suspended', 'locked', 'disabled', 'restricted', 'compromised',
    'unauthorised', 'unauthorized', 'unusual activity', 'breach',
    'hacked', 'blocked', 'closed', 'terminated', 'expired',
]

# OTP / verification code pattern
_OTP_PATTERN_RE = re.compile(
    r'(?:otp|one.time|verification|auth(?:entication)?|access)\s+(?:code|pin|password)|'
    r'\b\d{4,8}\b.{0,30}(?:code|otp|pin)|'
    r'(?:code|otp|pin).{0,20}\b\d{4,8}\b',
    re.IGNORECASE,
)


@dataclass
class Features:
    # ── Original fields (unchanged) ───────────────────────────────────────────
    urls: list[str] = field(default_factory=list)
    suspicious_tlds: list[str] = field(default_factory=list)
    phone_numbers: list[str] = field(default_factory=list)
    currency_mentions: list[str] = field(default_factory=list)
    urgency_keyword_count: int = 0
    urgency_keywords_found: list[str] = field(default_factory=list)
    suspicious_keyword_count: int = 0
    suspicious_keywords_found: list[str] = field(default_factory=list)
    message_length: int = 0
    word_count: int = 0
    has_url: bool = False
    has_phone: bool = False
    has_currency: bool = False
    all_caps_ratio: float = 0.0
    exclamation_count: int = 0

    # ── v2 fields ─────────────────────────────────────────────────────────────
    text_lower: str = ""
    brand_detected: str | None = None
    domain_mismatch: bool = False   # brand in message, URL ≠ official domain
    is_international: bool = False  # kept for backward compat; use is_foreign_number
    is_known_contact: bool = False

    # ── v3 fields ─────────────────────────────────────────────────────────────
    suspicious_domain: bool = False
    """Brand name appears inside the URL hostname but it is NOT the official
    domain (e.g. commbank-secure.com). Lower confidence than domain_mismatch
    but still a meaningful lookalike signal."""

    is_local_au_number: bool = False
    """True when the message contains a recognisably local Australian number
    (04xx mobile, 02/03/07/08 landline, 13xx, 1300, 1800)."""

    is_foreign_number: bool = False
    """True when the message contains an international number that is NOT
    Australian (+61). Foreign numbers in unsolicited messages are riskier."""

    has_url_shortener: bool = False
    """True when a known URL shortener (bit.ly, tinyurl, etc.) is detected."""

    has_otp_pattern: bool = False
    """True when the message matches OTP / verification code patterns.
    Used by otp_legitimate negative rule to reduce false positives."""

    has_payment_request: bool = False
    """True when the message contains payment-related language."""

    has_account_threat: bool = False
    """True when the message contains account suspension / compromise language."""

    suspicious_domain_word_count: int = 0
    """Count of suspicious words found inside URLs (secure, login, verify, etc.).
    Tiered: 1 word = moderate signal, 2+ words = stronger signal."""


def _extract_hostname(url: str) -> str:
    """Return just the hostname from a URL string."""
    cleaned = re.sub(r'^https?://', '', url.lower())
    return cleaned.split('/')[0]


def extract_features(text: str) -> Features:
    lower = text.lower()
    words = text.split()

    # URLs
    urls = _URL_RE.findall(text)
    suspicious_tlds = [
        url for url in urls
        if any(
            url.lower().endswith(tld) or f'{tld}/' in url.lower()
            for tld in _SUSPICIOUS_TLDS
        )
    ]

    # Phone numbers
    phones = _PHONE_RE.findall(text)
    phone_list = [p[0] if isinstance(p, tuple) else p for p in phones if any(p)]

    # Currency
    currencies = _CURRENCY_RE.findall(text)

    # Urgency (word-boundary matching with dedup)
    urgency_found = _find_urgency(lower)

    # Suspicious keywords
    suspicious_found = [kw for kw in _SUSPICIOUS_KEYWORDS if kw in lower]

    # Caps ratio
    letters = [c for c in text if c.isalpha()]
    caps_ratio = sum(1 for c in letters if c.isupper()) / len(letters) if letters else 0.0

    # Brand detection (longest match wins).
    # Also check homoglyph-normalised text to catch "PaypaΙ", "amaz0n", etc.
    _lower_norm = _normalize_homoglyphs(lower)
    brand_detected = next(
        (b for b in sorted(_KNOWN_BRANDS, key=len, reverse=True)
         if b in lower or b in _lower_norm),
        None,
    )

    # Domain mismatch: brand in message but URL goes elsewhere
    domain_mismatch = False
    if brand_detected and urls:
        expected = _BRAND_DOMAINS.get(brand_detected, '')
        if expected:
            domain_mismatch = not any(expected in u.lower() for u in urls)

    # Suspicious domain: brand name embedded inside the URL hostname itself
    # e.g. "commbank-secure.com" or "telstra-login.net"
    suspicious_domain = False
    if brand_detected and urls:
        expected = _BRAND_DOMAINS.get(brand_detected, '')
        brand_slug = brand_detected.replace(' ', '')  # "commonwealth bank" → "commonwealthbank"
        for url in urls:
            host = _extract_hostname(url)
            host_slug = host.replace('-', '').replace('.', '')
            # Brand name in hostname but NOT matching official domain
            if brand_slug in host_slug and (not expected or expected not in url.lower()):
                suspicious_domain = True
                break

    # Phone classification
    is_local_au   = bool(AU_LOCAL_PHONE_RE.search(text))
    is_foreign    = bool(_FOREIGN_PHONE_RE.search(text))
    is_intl_any   = is_local_au or is_foreign  # backward compat alias

    # URL shortener detection
    has_url_shortener = any(
        any(s in u.lower() for s in _URL_SHORTENERS)
        for u in urls
    )

    # OTP pattern detection
    has_otp_pattern = bool(_OTP_PATTERN_RE.search(text))

    # Payment request detection
    has_payment_request = any(kw in lower for kw in PAYMENT_KEYWORDS)

    # Account threat detection
    has_account_threat = any(kw in lower for kw in ACCOUNT_THREAT_KEYWORDS)

    # Suspicious domain word count (deduplicated across all URLs)
    found_domain_words: set[str] = set()
    for url in urls:
        for word in SUSPICIOUS_DOMAIN_WORDS:
            if word in url.lower():
                found_domain_words.add(word)
    suspicious_domain_word_count = len(found_domain_words)

    return Features(
        urls=urls,
        suspicious_tlds=suspicious_tlds,
        phone_numbers=phone_list,
        currency_mentions=currencies,
        urgency_keyword_count=len(urgency_found),
        urgency_keywords_found=urgency_found,
        suspicious_keyword_count=len(suspicious_found),
        suspicious_keywords_found=suspicious_found,
        message_length=len(text),
        word_count=len(words),
        has_url=len(urls) > 0,
        has_phone=len(phone_list) > 0 or bool(_FOREIGN_PHONE_RE.search(text)) or bool(AU_LOCAL_PHONE_RE.search(text)),
        has_currency=len(currencies) > 0,
        all_caps_ratio=caps_ratio,
        exclamation_count=text.count('!'),
        text_lower=lower,
        brand_detected=brand_detected,
        domain_mismatch=domain_mismatch,
        is_international=is_intl_any,
        is_known_contact=False,
        # v3
        suspicious_domain=suspicious_domain,
        is_local_au_number=is_local_au,
        is_foreign_number=is_foreign,
        has_url_shortener=has_url_shortener,
        has_otp_pattern=has_otp_pattern,
        has_payment_request=has_payment_request,
        has_account_threat=has_account_threat,
        suspicious_domain_word_count=suspicious_domain_word_count,
    )
