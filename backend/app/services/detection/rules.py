"""
Rule engine — v3 (hardened).

Changes from v2:
  - brand_impersonation (no URL): score reduced from +20 to +10, only fires
    when brand + (urgency OR action keyword). Prevents FP on routine billing.
  - Suspicious domain rule: +15 for lookalike domains (commbank-secure.com)
  - Phone classification: foreign phone (+15) vs local AU (no extra penalty)
  - Callback scam rule: phone + explicit call-to-action + urgency → +28
    (without urgency → +18)
  - Signal density rule: 3+ independent signal categories → +10
  - known_contact trust reduction capped at -10 (was -20), never overrides
    scores >= 50

Public interface (unchanged):
    apply_rules(features) -> tuple[list[RuleHit], list[str]]
    evaluate_rules(features) -> list[RuleHit]  (backward compat)
"""
from __future__ import annotations
import re
from dataclasses import dataclass

from app.services.detection.features import Features, ACTION_KEYWORDS, AU_LOCAL_PHONE_RE


@dataclass
class RuleHit:
    type: str
    detail: str
    score: int


# Callback scam pattern: "call immediately on 0412..." or "ring us on +61..."
_CALLBACK_RE = re.compile(
    r'\b(?:call|phone|ring|contact)\b.{0,40}(?:\d[\d\s\-\+]{6,})',
    re.IGNORECASE,
)


def evaluate_rules(features: Features) -> list[RuleHit]:
    hits: list[RuleHit] = []

    # ── URL signals ───────────────────────────────────────────────────────────

    if features.has_url:
        hits.append(RuleHit(
            type="url_present",
            detail=f"Message contains {len(features.urls)} link(s)",
            score=15,
        ))

    if features.suspicious_tlds:
        hits.append(RuleHit(
            type="suspicious_tld",
            detail=(
                f"Link uses a high-risk domain extension "
                f"({', '.join(features.suspicious_tlds[:2])})"
            ),
            score=25,
        ))

    if features.has_url and features.word_count < 10:
        hits.append(RuleHit(
            type="short_url_message",
            detail="Very short message containing a link — typical phishing lure",
            score=10,
        ))

    # ── Domain signals ────────────────────────────────────────────────────────

    if features.domain_mismatch and features.brand_detected:
        from app.services.detection.features import _BRAND_DOMAINS
        expected = _BRAND_DOMAINS.get(features.brand_detected, 'its official domain')
        hits.append(RuleHit(
            type="domain_mismatch",
            detail=(
                f"Claims to be {features.brand_detected.title()} "
                f"but link goes to a different domain (expected {expected})"
            ),
            score=35,
        ))

    if features.suspicious_domain and not features.domain_mismatch:
        # Lookalike domain: brand name embedded in a non-official hostname
        # (domain_mismatch already covers the "brand mentioned in message" case;
        # suspicious_domain covers "brand name appears in the URL itself")
        hits.append(RuleHit(
            type="suspicious_domain",
            detail=(
                f"URL hostname contains '{features.brand_detected}' "
                f"but is not the official domain — likely a lookalike"
            ),
            score=15,
        ))

    # ── Brand impersonation (no URL) ──────────────────────────────────────────
    # Reduced score when there's no URL and no urgency/action — routine brand
    # mentions in billing/notifications are not suspicious on their own.

    if features.brand_detected and not features.has_url and not features.domain_mismatch:
        has_urgency  = features.urgency_keyword_count > 0
        has_action   = any(kw in features.text_lower for kw in ACTION_KEYWORDS)
        if has_urgency or has_action:
            # Suspicious context: brand + pressure = likely impersonation
            hits.append(RuleHit(
                type="brand_impersonation",
                detail=f"Impersonates known brand ({features.brand_detected.title()}) with pressure language",
                score=20,
            ))
        else:
            # Brand alone, no pressure — lower confidence signal
            hits.append(RuleHit(
                type="brand_mention",
                detail=f"Mentions known brand ({features.brand_detected.title()}) — may be legitimate",
                score=10,
            ))

    # ── URL shortener rule ──────────────────────────────────────────────────────
    if features.has_url_shortener:
        hits.append(RuleHit(
            type="url_shortener",
            detail="Uses a URL shortener (bit.ly, tinyurl, etc.) — hides the real destination",
            score=20,
        ))

    # ── Suspicious domain word scoring (tiered) ───────────────────────────────
    # Words like 'secure', 'login', 'verify' inside a URL hostname are a
    # moderate signal. Score is 15 for 1 word, 25 for 2+.
    if features.suspicious_domain_word_count >= 2:
        hits.append(RuleHit(
            type="suspicious_domain_words",
            detail="URL contains multiple suspicious words (secure/login/verify/account/update/alert)",
            score=25,
        ))
    elif features.suspicious_domain_word_count == 1:
        hits.append(RuleHit(
            type="suspicious_domain_words",
            detail="URL contains a suspicious keyword (secure/login/verify/account/update/alert)",
            score=15,
        ))

    # ── Payment request (named signal) ───────────────────────────────────────
    if features.has_payment_request and not features.has_currency:
        # has_currency already fires currency_mention — only add payment_request
        # if currency_mention hasn't fired, to avoid double-counting
        hits.append(RuleHit(
            type="payment_request",
            detail="Contains payment or financial action language",
            score=12,
        ))

    # ── Account threat (named signal) ────────────────────────────────────────
    if features.has_account_threat:
        existing = {h.type for h in hits}
        if 'account_suspended' not in existing:
            hits.append(RuleHit(
                type="account_threat",
                detail="Contains account suspension or compromise language",
                score=15,
            ))

    # ── OTP negative rule — reduces score for genuine verification messages ───
    # Legitimate OTP messages share surface features with scams (urgency, codes).
    # A negative-weight rule reduces score rather than trying to exclude with
    # complex conditions. Only fires when: has_otp_pattern AND no URL AND no brand.
    if features.has_otp_pattern and not features.has_url and not features.brand_detected:
        hits.append(RuleHit(
            type="otp_legitimate",
            detail="Matches a genuine OTP / verification code pattern — risk reduced",
            score=-20,
        ))

    # ── Phone signals ─────────────────────────────────────────────────────────

    if features.has_url and features.has_phone:
        hits.append(RuleHit(
            type="url_plus_phone",
            detail="Contains both a link and a phone number — common phishing combo",
            score=15,
        ))
    elif features.has_phone and not features.has_url:
        hits.append(RuleHit(
            type="phone_number",
            detail="Contains a phone number — verify the sender before calling",
            score=10,
        ))

    # Foreign phone raises risk; local AU numbers do not by themselves
    if features.is_foreign_number and not features.has_url:
        hits.append(RuleHit(
            type="foreign_phone",
            detail="Contains a foreign international number — higher risk for vishing",
            score=15,
        ))

    # Callback scam: explicit instruction to call a number
    # Requires urgency OR account_threat context (H-3 fix: prevents FP on
    # benign messages like "Call 1300 123 for Telstra support anytime").
    has_callback = bool(_CALLBACK_RE.search(features.text_lower))
    has_threat_context = (features.urgency_keyword_count > 0 or features.has_account_threat)
    if has_callback and features.has_phone and has_threat_context:
        cb_score = 33 if features.urgency_keyword_count > 0 else 20
        hits.append(RuleHit(
            type="callback_scam",
            detail="Instructs recipient to call a phone number — common vishing / callback scam",
            score=cb_score,
        ))

    # ── Financial signals ─────────────────────────────────────────────────────

    if features.has_currency:
        hits.append(RuleHit(
            type="currency_mention",
            detail="References a monetary amount — common in financial scams",
            score=10,
        ))

    # ── Urgency signals ───────────────────────────────────────────────────────

    if features.urgency_keyword_count >= 3:
        hits.append(RuleHit(
            type="high_urgency",
            detail=(
                "Uses multiple urgency phrases: "
                + ", ".join(f'"{w}"' for w in features.urgency_keywords_found[:4])
            ),
            score=20,
        ))
    elif features.urgency_keyword_count == 2:
        hits.append(RuleHit(
            type="urgency_language",
            detail=(
                "Uses urgency language: "
                + ", ".join(f'"{w}"' for w in features.urgency_keywords_found)
            ),
            score=15,
        ))
    elif features.urgency_keyword_count == 1:
        hits.append(RuleHit(
            type="urgency_language",
            detail=f'Uses urgency language: "{features.urgency_keywords_found[0]}"',
            score=10,
        ))

    # ── Suspicious keyword volume ─────────────────────────────────────────────

    if features.suspicious_keyword_count >= 4:
        hits.append(RuleHit(
            type="many_suspicious_keywords",
            detail=(
                "Contains many suspicious terms: "
                + ", ".join(features.suspicious_keywords_found[:5])
            ),
            score=20,
        ))
    elif features.suspicious_keyword_count >= 2:
        hits.append(RuleHit(
            type="suspicious_keywords",
            detail=(
                "Contains suspicious terms: "
                + ", ".join(features.suspicious_keywords_found[:3])
            ),
            score=10,
        ))

    # ── Action + URL combo (phishing delivery) ────────────────────────────────

    if features.has_url and not features.domain_mismatch:
        has_action = any(kw in features.text_lower for kw in ACTION_KEYWORDS)
        if has_action:
            existing_types = {h.type for h in hits}
            if 'click_to_verify' not in existing_types:
                hits.append(RuleHit(
                    type="action_url_combo",
                    detail="Asks you to take action (click / verify / pay) alongside a link",
                    score=12,
                ))

    # ── Signal density: multiple independent categories agree ─────────────────
    # Counts distinct signal categories (not individual hits).
    # When 3+ categories fire, the cumulative pattern is significantly more
    # suspicious than any single signal alone.

    has_action_kw = any(kw in features.text_lower for kw in ACTION_KEYWORDS)
    signal_categories = sum([
        bool(features.has_url),
        bool(features.urgency_keyword_count > 0),
        bool(has_action_kw),
        bool(features.has_currency),
        bool(features.brand_detected),
        bool(features.has_phone),
    ])
    if signal_categories >= 3:
        hits.append(RuleHit(
            type="signal_density",
            detail=(
                f"Message combines {signal_categories} independent risk categories "
                f"(URL, urgency, action, payment, brand, phone)"
            ),
            score=10,
        ))

    # ── Formatting abuse ──────────────────────────────────────────────────────

    if features.all_caps_ratio > 0.5 and features.word_count > 5:
        hits.append(RuleHit(
            type="excessive_caps",
            detail="Uses excessive capital letters — common pressure/manipulation tactic",
            score=8,
        ))

    if features.exclamation_count >= 3:
        hits.append(RuleHit(
            type="excessive_exclamation",
            detail=f"Contains {features.exclamation_count} exclamation marks — manipulative formatting",
            score=5,
        ))

    # ── Debt / legal intimidation ─────────────────────────────────────────────

    debt_signals = [
        w for w in (
            'overdue', 'outstanding', 'unpaid', 'debt', 'warrant',
            'arrest', 'court', 'legal', 'proceedings', 'penalty', 'fine'
        )
        if w in features.suspicious_keywords_found or w in features.urgency_keywords_found
    ]
    if len(debt_signals) >= 2 and features.urgency_keyword_count >= 1:
        hits.append(RuleHit(
            type="debt_intimidation",
            detail="Combines debt/legal threat with urgency — common intimidation scam",
            score=22,
        ))
    elif len(debt_signals) >= 2:
        hits.append(RuleHit(
            type="debt_threat",
            detail=f"References debt or legal action: {', '.join(debt_signals[:3])}",
            score=12,
        ))

    # ── Tech brand + threat combo ─────────────────────────────────────────────

    _tech_brands  = {'microsoft', 'apple', 'google', 'telstra', 'optus', 'norton', 'mcafee'}
    _tech_threats = {'virus', 'hacked', 'compromised', 'infected', 'breach', 'detected', 'attack'}
    found_brand  = next((b for b in _tech_brands  if b in features.suspicious_keywords_found), None)
    found_threat = next((t for t in _tech_threats if t in features.suspicious_keywords_found), None)
    if found_brand and found_threat:
        hits.append(RuleHit(
            type="tech_impersonation",
            detail=(
                f"Tech brand ({found_brand.title()}) combined with threat language "
                f"— tech support scam"
            ),
            score=22,
        ))


    # ── Family impersonation (Hi Mum, new number) ────────────────────────────
    # The pattern engine catches this, but rules add extra weight when
    # urgency or payment language is also present.
    _FAMILY_IMPERSONATION_RE = re.compile(
        r'(?:hi|hey)[,\s]+(?:mum|mom|dad|sis|bro|nan|gran|grandma|grandpa)[,\s]',
        re.IGNORECASE,
    )
    if _FAMILY_IMPERSONATION_RE.search(features.text_lower):
        if features.urgency_keyword_count > 0 or features.has_payment_request:
            hits.append(RuleHit(
                type="family_impersonation_urgent",
                detail="Impersonates family member with urgency/payment request — hi-mum scam",
                score=20,
            ))

    # ── Negation obfuscation ─────────────────────────────────────────────────
    # Messages that explicitly say "not a scam" or use double-negatives to
    # disguise urgency are strongly suspicious.
    _NEGATION_RE = re.compile(
        r'this\s+is\s+not\s+a\s+scam|not\s+(?:a\s+)?(?:spam|fraud|scam)|'
        r'(?:attention|action).{0,30}may\s+not\s+be\s+unnecessary',
        re.IGNORECASE,
    )
    if _NEGATION_RE.search(features.text_lower):
        hits.append(RuleHit(
            type="negation_obfuscation",
            detail="Explicitly denies being a scam or uses double-negative urgency — obfuscation tactic",
            score=18,
        ))

    # ── Known contact trust signal ────────────────────────────────────────────
    # Trust reduction is capped at -10 (was -20) and is never applied when
    # the score is already high (>=50 raw pts), preventing trust from masking
    # genuine high-risk messages that happen to come from a known number.

    if features.is_known_contact:
        raw_positive = sum(h.score for h in hits if h.score > 0)
        if raw_positive < 50:
            hits.append(RuleHit(
                type="known_contact",
                detail="Sender is a known and trusted contact — risk reduced",
                score=-10,  # capped at -10 (previously -20)
            ))

    return hits


def apply_rules(features: Features) -> tuple[list[RuleHit], list[str]]:
    """
    Public interface for the pipeline.

    Returns:
        rule_hits     — passed to scoring.aggregate() unchanged
        rule_triggers — human-readable strings for the reasons output
    """
    rule_hits = evaluate_rules(features)
    rule_triggers = [h.detail for h in rule_hits if h.score > 0]
    return rule_hits, rule_triggers
