"""
Scam type classifier.
Maps fired rules + patterns onto a human-readable scam category label.
Called by the pipeline after scoring — adds scam_type to the result.

Categories (in priority order):
  blackmail    → sextortion, threatening messages
  tech_support → remote access, tech impersonation
  investment   → crypto, trading bots, guaranteed returns
  job          → work from home, easy money
  romance      → pig butchering, found your number
  government   → ATO, Medicare, Centrelink, toll roads
  delivery     → AusPost, parcel, delivery fee
  prize        → lottery, you've won, gift voucher
  phishing     → generic credential/account theft
  unknown      → low score, no clear category
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class ScamClassification:
    scam_type: str          # machine key e.g. "phishing"
    label: str              # human label e.g. "Phishing Scam"
    description: str        # one sentence plain English
    emoji: str


# Priority-ordered category definitions
_CATEGORIES = {
    "blackmail":    ("Sextortion / Blackmail",    "🔒", "Threatens to release private or intimate content unless you pay."),
    "tech_support": ("Tech Support Scam",         "💻", "Impersonates a tech company to gain remote access to your device."),
    "investment":   ("Investment Scam",           "📈", "Promises unrealistic financial returns — often crypto or trading bots."),
    "job":          ("Job / Income Scam",         "💼", "Offers easy money or work-from-home income that doesn't exist."),
    "romance":      ("Romance Scam",              "❤️", "Builds false trust before pivoting to a financial request or investment pitch."),
    "government":   ("Government Impersonation",  "🏛️", "Pretends to be the ATO, Medicare, Centrelink, or law enforcement."),
    "delivery":     ("Delivery Scam",             "📦", "Impersonates Australia Post or a courier to extract a payment or click."),
    "prize":        ("Prize / Lottery Scam",      "🎰", "Claims you've won something to get you to click or provide details."),
    "phishing":     ("Phishing Scam",             "🎣", "Tries to steal your account credentials, passwords, or banking details."),
}


def classify(
    rule_hits: list,
    pattern_hits: list,
    features,
    risk_score: int,
) -> ScamClassification:
    """
    Determine scam type from fired signals.
    Uses category votes — the category with the most combined score wins.
    Falls back to feature-based heuristics for uncategorised rule hits.
    """
    if risk_score < 15:
        return ScamClassification(
            scam_type="unknown",
            label="No Scam Detected",
            description="This message does not appear to contain scam indicators.",
            emoji="✅",
        )

    # Tally scores per category from pattern hits
    category_scores: dict[str, int] = {}
    for hit in pattern_hits:
        cat = getattr(hit, 'category', 'phishing')
        category_scores[cat] = category_scores.get(cat, 0) + hit.score

    # Add feature-based votes where no pattern fires
    if not category_scores:
        if features.has_account_threat or features.domain_mismatch:
            category_scores['phishing'] = category_scores.get('phishing', 0) + 20
        if features.is_foreign_number or features.is_local_au_number:
            # Phone-only with no patterns → vishing
            category_scores['phishing'] = category_scores.get('phishing', 0) + 10
        if features.brand_detected and features.has_url:
            category_scores['phishing'] = category_scores.get('phishing', 0) + 15

    if not category_scores:
        category_scores['phishing'] = 10

    # Pick highest scoring category (priority order breaks ties)
    priority = list(_CATEGORIES.keys())
    winner = max(
        category_scores.keys(),
        key=lambda c: (category_scores[c], -priority.index(c) if c in priority else -99)
    )

    if winner not in _CATEGORIES:
        winner = 'phishing'

    label, emoji, description = _CATEGORIES[winner]
    return ScamClassification(
        scam_type=winner,
        label=label,
        description=description,
        emoji=emoji,
    )
