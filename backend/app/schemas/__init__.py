from pydantic import BaseModel, Field
from typing import Literal
from app.config import cfg


class AnalyzeRequest(BaseModel):
    message_text: str = Field(..., min_length=1, max_length=cfg.MAX_MESSAGE_CHARS)
    sender: str | None = None


class ReasonItem(BaseModel):
    type: str
    detail: str


class PhoneTrustInfo(BaseModel):
    trust_level: str           # "trusted" | "neutral" | "suspect"
    numbers_found: list[str]
    known_org: str | None
    reason: str


class AnalyzeResponse(BaseModel):
    analysis_id: int
    risk_score: int = Field(..., ge=0, le=100)
    verdict: Literal["low", "medium", "high"]
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasons: list[ReasonItem]
    scam_type: str
    scam_label: str
    scam_description: str
    scam_emoji: str
    phone_trust: PhoneTrustInfo | None = None


class BatchAnalyzeRequest(BaseModel):
    messages: list[str] = Field(..., min_length=1, max_length=cfg.MAX_BATCH_SIZE)


class FeedbackRequest(BaseModel):
    analysis_id: int
    user_label: Literal["scam", "not_scam"]


class FeedbackResponse(BaseModel):
    status: str = "ok"
