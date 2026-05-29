"""
Risk aggregation — v3 (hardened).

Scoring model:
  deterministic score = sum(rule scores) + sum(pattern scores)
  det_capped  = min(raw_det * 1.25, 80)   ← capped to prevent runaway inflation
  final       = clamp(det_capped + url_bonus + nlp_bonus, 0, 100)

Changes from v2:
  - Multiplier reduced from 1.4 → 1.25 (less inflation as rule count grows)
  - Deterministic contribution hard-capped at 80 before bonuses
    (url_bonus and nlp_bonus can still push final to 100 when warranted)
  - Baseline false-positive gate: when no recognised signal category is present,
    final score is capped at 20 regardless of any residual noise
  - URL bonus logic unchanged (additive, not multiplicative)
  - NLP bonus unchanged (additive, caps at +15)

Score calibration:
  Single strong rule hit  (score ~25): 25×1.25 = 31  → medium territory ✓
  Two moderate hits       (score ~40): 40×1.25 = 50  → medium ✓
  Clear scam combo        (score ~58): 58×1.25 = 72  → high ✓
  Legit brand mention     (score ~10): 10×1.25 = 12  → low ✓
  Routine bill (brand+$)  (score ~20): 20×1.25 = 25  → low ✓

Verdict thresholds (unchanged):
  0–30  → low
  31–70 → medium
  71–100→ high
"""
from __future__ import annotations
from dataclasses import dataclass

from app.services.detection.rules import RuleHit
from app.services.detection.patterns import PatternHit
from app.services.detection.features import Features, ACTION_KEYWORDS


# Signal categories used by the baseline FP gate.
# A message with NONE of these is almost certainly benign.
_STRONG_SIGNAL_CHECKS = (
    lambda f: f.has_url,
    lambda f: f.urgency_keyword_count > 0,
    lambda f: any(kw in f.text_lower for kw in ACTION_KEYWORDS),
    lambda f: f.has_currency,
    lambda f: f.brand_detected is not None,
    lambda f: f.has_phone,
    lambda f: f.has_payment_request,   # "pay bitcoin", "send money" etc
    lambda f: f.has_account_threat,    # "suspended", "compromised" etc
)


@dataclass
class ScoringResult:
    raw_det_score: float   # raw sum of rule + pattern scores (before scaling)
    det_capped: float      # after × 1.25 and cap at 80
    url_bonus: float       # additive URL/TLD bonus
    nlp_bonus: float       # additive NLP bonus
    final_score: int       # 0–100
    confidence: float      # 0.0–1.0
    verdict: str           # "low" | "medium" | "high"
    fp_gate_applied: bool  # True when the baseline FP gate capped the score

    # Back-compat alias (pipeline checks this for NLP reason)
    @property
    def raw_nlp_score(self) -> float:
        return self.nlp_bonus / 0.30 * 100 if self.nlp_bonus > 0 else 0.0


def aggregate(
    features: Features,
    rule_hits: list[RuleHit],
    pattern_hits: list[PatternHit],
    nlp_probability: float,
) -> ScoringResult:

    # 1. Deterministic score: sum all hits (rules + patterns)
    raw_det = sum(h.score for h in rule_hits) + sum(h.score for h in pattern_hits)

    # 2. Capped scaling — prevents score inflation as the rule set grows.
    #    The cap at 80 ensures url_bonus and nlp_bonus still add meaningful
    #    weight for truly suspicious messages, but the deterministic layer
    #    alone can never reach 100 on its own.
    det_capped = min(raw_det * 1.25, 80.0)

    # 3. URL bonus (additive, unchanged)
    url_bonus = 0.0
    if features.has_url:
        url_bonus += 12.0
    if features.suspicious_tlds:
        url_bonus += 20.0

    # 4. NLP bonus — activates above 0.5 probability, max +15
    nlp_bonus = max(0.0, (nlp_probability - 0.5) * 30.0)

    # 5. Combine
    raw_total = det_capped + url_bonus + nlp_bonus
    final = max(0, min(100, round(raw_total)))

    # 6. Baseline false-positive gate
    #    If the message has none of the eight recognised signal categories,
    #    AND the raw deterministic score is low (< 50 — not many patterns fired),
    #    cap at 20 to prevent residual noise inflating benign messages.
    #    Bypassed when raw_det >= 50 because that many pattern hits IS a signal.
    has_any_signal = any(check(features) for check in _STRONG_SIGNAL_CHECKS)
    fp_gate_applied = False
    if not has_any_signal and raw_det < 50 and final > 20:
        final = 20
        fp_gate_applied = True

    # 7. Confidence: how many independent signal types agree
    signal_count = (
        (1 if rule_hits else 0) +
        (1 if pattern_hits else 0) +
        (1 if features.has_url else 0) +
        (1 if nlp_probability > 0.5 else 0)
    )
    confidence = round(min(0.5 + signal_count * 0.125, 0.97), 2)

    return ScoringResult(
        raw_det_score=raw_det,
        det_capped=det_capped,
        url_bonus=url_bonus,
        nlp_bonus=nlp_bonus,
        final_score=final,
        confidence=confidence,
        verdict=_to_verdict(final),
        fp_gate_applied=fp_gate_applied,
    )


def _to_verdict(score: int) -> str:
    if score >= 71:
        return "high"
    elif score >= 31:
        return "medium"
    else:
        return "low"
