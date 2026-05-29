"""
Phone trust classifier — Is This Phishy.

Determines whether phone numbers in a message are likely legitimate
Australian business numbers or potential vishing risks.

No external API required — uses:
  1. AU business number format rules (13xx, 1300, 1800 = freecall/business)
  2. Known brand number registry (hard-coded, manually maintained)
  3. Brand/number cross-reference (brand in message + their real number = trust signal)
  4. Foreign number detection (non-AU international = suspect in scam context)

Returns a PhoneTrustResult with:
  trust_level: "trusted" | "neutral" | "suspect"
  reason:      plain English explanation
  numbers:     list of numbers found
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field


# ── Known AU business numbers ─────────────────────────────────────────────────
# Format: number (digits only, no spaces) → (organisation, canonical brand key)
_KNOWN_BUSINESS_NUMBERS: dict[str, tuple[str, str]] = {
    # Banks
    "132221": ("Commonwealth Bank",      "commbank"),
    "132265": ("NAB",                    "nab"),
    "132032": ("Westpac",               "westpac"),
    "133462": ("ANZ",                    "anz"),
    "132888": ("Macquarie Bank",         "macquarie"),
    "131848": ("St George Bank",         "stgeorge"),
    "133722": ("Bank of Queensland",     "boq"),
    "132663": ("Bendigo Bank",           "bendigo"),
    "1800680100": ("ING Australia",      "ing"),

    # Government
    "132861": ("Australian Taxation Office",    "ato"),
    "136240": ("Services Australia / Centrelink","centrelink"),
    "132011": ("Medicare",                      "medicare"),
    "131524": ("Australian Passport Office",    "passports"),
    "1300975707": ("ACCC / Scamwatch",          "accc"),
    "1300786179": ("AFCA",                      "afca"),

    # Telcos
    "125101": ("Telstra",   "telstra"),
    "1800015006": ("Optus Customer Service", "optus"),
    "1300650410": ("Vodafone",  "vodafone"),
    "1300734465": ("TPG",       "tpg"),

    # Delivery / Logistics
    "137678": ("Australia Post",    "auspost"),
    "1300361821": ("StarTrack",     "startrack"),
    "131150": ("DHL Australia",     "dhl"),

    # Utilities / Other
    "132004": ("Energy Australia",  "energy"),
    "133961": ("Origin Energy",     "origin"),
    "1300650155": ("Alinta Energy", "alinta"),
    "131009": ("AGL",               "agl"),

    # Emergency / Police
    "000":    ("Emergency Services", "emergency"),
    "131444": ("Police Assistance Line", "police"),
    "132444": ("NSW Police",         "police"),
}

# ── AU business number prefixes (always trusted format) ───────────────────────
# 13xx (4-digit short codes), 1300 xxxxxx, 1800 xxxxxx
_AU_BUSINESS_PREFIX_RE = re.compile(
    r'\b13\d{4}\b|'                          # 13xx short codes (6 digits total)
    r'\b1300\s*\d{3}\s*\d{3}\b|'            # 1300 xxx xxx
    r'\b1800\s*\d{3}\s*\d{3}\b',            # 1800 xxx xxx
    re.IGNORECASE,
)

# ── AU mobile / landline (neutral — could be anyone) ─────────────────────────
_AU_LOCAL_RE = re.compile(
    r'(?<!\+)0[2-478](?:[ -]?\d){8}|'       # 02/03/07/08 + mobile 04xx
    r'\+?61\s*[2-478](?:[ -]?\d){8}',
    re.IGNORECASE,
)

# ── Foreign numbers (suspect in scam context) ─────────────────────────────────
_FOREIGN_RE = re.compile(r'\+(?!61)\d[\d\s\-\(\)]{6,}')

# ── Extract all numbers from text ─────────────────────────────────────────────
_ANY_PHONE_RE = re.compile(
    r'\b000\b|'                               # emergency
    r'\b1[38]00\s*[\d\s]{7,11}|'            # 1300/1800
    r'\b13\d{4}\b|'                          # 13xx
    r'\+?61\s*[2-478][\d\s\-]{8,12}|'       # +61 / 0x
    r'\b0[2-478][\d\s\-]{8,12}|'            # 04xx / 02xx etc
    r'\+[1-9][\d\s\-\(\)]{6,18}',           # international
    re.IGNORECASE,
)


def _normalise(number: str) -> str:
    """Strip spaces, dashes, brackets, leading +61 → 0."""
    n = re.sub(r'[\s\-\(\)]', '', number)
    n = re.sub(r'^\+61', '0', n)
    return n


@dataclass
class PhoneTrustResult:
    trust_level: str          # "trusted" | "neutral" | "suspect"
    numbers_found: list[str]  = field(default_factory=list)
    known_org: str | None     = None   # e.g. "Commonwealth Bank"
    reason: str               = ""


def classify_phones(text: str, brand_detected: str | None = None) -> PhoneTrustResult:
    """
    Classify phone numbers found in a message.

    trust_level:
      trusted  — number belongs to a known AU organisation, or is a genuine
                 13/1300/1800 business number matching the brand mentioned
      neutral  — local AU mobile or landline, no suspicious context
      suspect  — foreign number, or number doesn't match the brand being impersonated
    """
    raw_numbers = _ANY_PHONE_RE.findall(text)
    numbers = [n.strip() for n in raw_numbers if n.strip()]

    if not numbers:
        return PhoneTrustResult(
            trust_level="neutral",
            numbers_found=[],
            reason="No phone numbers found in message",
        )

    # ── Check each number ─────────────────────────────────────────────────────
    trust_scores: list[tuple[str, str | None, str]] = []  # (level, org, reason)

    for num in numbers:
        normalised = _normalise(num)
        digits_only = re.sub(r'\D', '', normalised)

        # 1. Check known business registry
        known = _KNOWN_BUSINESS_NUMBERS.get(digits_only)
        if known:
            org_name, org_brand = known
            # If a brand was mentioned in the message, verify it matches
            if brand_detected and org_brand not in (brand_detected, ""):
                trust_scores.append((
                    "suspect",
                    org_name,
                    f"{num} belongs to {org_name} but message mentions {brand_detected.title()} — possible impersonation",
                ))
            else:
                trust_scores.append(("trusted", org_name, f"{num} is a verified {org_name} number"))
            continue

        # 2. AU business prefix (13xx, 1300, 1800)
        if _AU_BUSINESS_PREFIX_RE.search(num):
            trust_scores.append((
                "trusted",
                None,
                f"{num} is a legitimate Australian business / freecall number format",
            ))
            continue

        # 3. Foreign number
        if _FOREIGN_RE.search(num):
            trust_scores.append((
                "suspect",
                None,
                f"{num} is a foreign international number — higher risk in unsolicited messages",
            ))
            continue

        # 4. Local AU mobile / landline — neutral
        if _AU_LOCAL_RE.search(num):
            trust_scores.append(("neutral", None, f"{num} is a local Australian number"))
            continue

        # 5. Unclassified
        trust_scores.append(("neutral", None, f"{num} — could not verify"))

    # ── Aggregate result ──────────────────────────────────────────────────────
    # Worst level wins: suspect > neutral > trusted
    level_priority = {"suspect": 2, "neutral": 1, "trusted": 0}
    worst = max(trust_scores, key=lambda x: level_priority.get(x[0], 0))
    overall_level = worst[0]
    overall_org   = next((t[1] for t in trust_scores if t[1]), None)
    overall_reason = "; ".join(t[2] for t in trust_scores[:2])  # max 2 reasons

    return PhoneTrustResult(
        trust_level=overall_level,
        numbers_found=numbers,
        known_org=overall_org,
        reason=overall_reason,
    )
