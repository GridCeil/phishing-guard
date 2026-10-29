"""
Optional integration with Google's Safe Browsing API (free tier available).
Only runs if GOOGLE_SAFE_BROWSING_API_KEY is set in the environment.

Docs: https://developers.google.com/safe-browsing/v4/lookup-api
"""
from __future__ import annotations
import logging
import requests

logger = logging.getLogger(__name__)

API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def check_safe_browsing(raw_url: str, api_key: str) -> dict | None:
    if not api_key:
        return None

    body = {
        "client": {"clientId": "phishing-detector-extension", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": raw_url}],
        },
    }

    try:
        resp = requests.post(API_URL, params={"key": api_key}, json=body, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        matches = data.get("matches", [])
        if matches:
            threat_types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
            return {
                "type": "safe_browsing_match",
                "message": f"Flagged by Google Safe Browsing: {', '.join(threat_types)}",
                "weight": 0.9,  # near-certain if Google already flagged it
                "threat_types": threat_types,
            }
        return None
    except requests.RequestException as exc:
        # Exception text can include the request URL, which contains the API key.
        logger.warning("Safe Browsing API call failed (%s)", type(exc).__name__)
        return None
