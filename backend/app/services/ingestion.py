"""
Optional external message ingestion.
Configure EXTERNAL_API_URL and EXTERNAL_API_KEY to activate.
Always returns [] gracefully if unconfigured or unreachable.
"""
import logging
import os

logger = logging.getLogger(__name__)

EXTERNAL_API_URL: str | None = os.getenv("SCAM_INGEST_URL", None)
EXTERNAL_API_KEY: str | None = os.getenv("SCAM_INGEST_KEY", None)
TIMEOUT_SECONDS  = 5


def fetch_external_messages() -> list[str]:
    """
    Fetch messages from an optional external API.
    Returns a list of message strings, or [] if unavailable.
    Never raises — safe to call unconditionally.
    """
    if not EXTERNAL_API_URL:
        return []

    try:
        import requests
        headers = {}
        if EXTERNAL_API_KEY:
            headers["Authorization"] = f"Bearer {EXTERNAL_API_KEY}"

        resp = requests.get(EXTERNAL_API_URL, headers=headers, timeout=TIMEOUT_SECONDS)
        resp.raise_for_status()
        data = resp.json()

        # Accept list of strings OR list of dicts with a 'text'/'message' key
        messages = []
        for item in data:
            if isinstance(item, str):
                messages.append(item)
            elif isinstance(item, dict):
                text = item.get("text") or item.get("message") or item.get("content", "")
                if text:
                    messages.append(str(text))

        logger.info("Fetched %d messages from external source", len(messages))
        return messages

    except Exception as e:
        logger.warning("External ingestion failed: %s", e, exc_info=True)
        return []
