"""
Detection pipeline — Is This Phishy v1.
Orchestrates all layers and adds scam type classification.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field

from app.services.detection.features import extract_features, Features
from app.services.detection.rules import apply_rules, RuleHit
from app.services.detection.patterns import evaluate_patterns, PatternHit
from app.services.detection.scoring import aggregate, ScoringResult
from app.services.detection.classifier import classify, ScamClassification

try:
    from app.services.detection.nlp import nlp_score as _nlp_score
    def _get_nlp_score(text: str) -> float:
        return _nlp_score(text)
except Exception:
    def _get_nlp_score(text: str) -> float:
        return 0.0


@dataclass
class ReasonItem:
    type: str
    detail: str

    def model_dump(self) -> dict:
        return {"type": self.type, "detail": self.detail}


@dataclass
class PipelineResult:
    risk_score: int
    verdict: str
    confidence: float
    reasons: list[ReasonItem]
    scam_type: str
    scam_label: str
    scam_description: str
    scam_emoji: str
    features: Features
    scoring: ScoringResult


def _normalize(text: str) -> str:
    return re.sub(r'\s+', ' ', text.strip())


def run_pipeline(raw_text: str) -> PipelineResult:
    text = _normalize(raw_text)
    features = extract_features(text)
    rule_hits, rule_triggers = apply_rules(features)
    pattern_hits = evaluate_patterns(text)
    nlp_prob = _get_nlp_score(text)
    scoring = aggregate(features, rule_hits, pattern_hits, nlp_prob)

    # Classify scam type
    classification = classify(rule_hits, pattern_hits, features, scoring.final_score)

    reasons = _build_reasons(rule_hits, pattern_hits, scoring)

    return PipelineResult(
        risk_score=scoring.final_score,
        verdict=scoring.verdict,
        confidence=scoring.confidence,
        reasons=reasons,
        scam_type=classification.scam_type,
        scam_label=classification.label,
        scam_description=classification.description,
        scam_emoji=classification.emoji,
        features=features,
        scoring=scoring,
    )


def _build_reasons(
    rule_hits: list[RuleHit],
    pattern_hits: list[PatternHit],
    scoring: ScoringResult,
) -> list[ReasonItem]:
    all_hits: list[tuple[str, str, int]] = (
        [(h.type, h.detail, h.score) for h in rule_hits if h.score > 0] +
        [(h.type, h.detail, h.score) for h in pattern_hits]
    )
    seen: set[str] = set()
    deduped: list[tuple[str, str]] = []
    for hit_type, detail, score in sorted(all_hits, key=lambda x: x[2], reverse=True):
        if hit_type not in seen:
            seen.add(hit_type)
            deduped.append((hit_type, detail))

    reasons = [ReasonItem(type=t, detail=d) for t, d in deduped[:8]]

    if not reasons and scoring.final_score > 20:
        reasons.append(ReasonItem(
            type="general_suspicion",
            detail="Message contains several low-confidence indicators",
        ))
    return reasons
