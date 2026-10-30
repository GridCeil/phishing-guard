"""
Checks how recently a domain was registered. Phishing domains are very
often registered days or weeks before use, then abandoned.

This is a *network call* (WHOIS lookup) so it's slower than the pure
heuristics above -- callers should feel free to skip it for fast/bulk checks
and only run it for domains that already look suspicious, or run it async.
"""
from __future__ import annotations
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

try:
    import whois  # python-whois package
except ImportError:  # pragma: no cover
    whois = None

NEW_DOMAIN_THRESHOLD_DAYS = 90


def _coerce_date(value):
    """Normalize WHOIS creation dates before selecting the earliest."""
    values = value if isinstance(value, (list, tuple)) else (value,)
    dates = (
        d.replace(tzinfo=timezone.utc) if d.utcoffset() is None else d.astimezone(timezone.utc)
        for d in values if isinstance(d, datetime)
    )
    return min(dates, default=None)


def check_domain_age(registrable_domain: str) -> dict | None:
    if whois is None:
        logger.warning("python-whois not installed; skipping domain age check")
        return None

    try:
        w = whois.whois(registrable_domain)
        created = _coerce_date(w.creation_date)
        if created is None:
            return None

        age_days = (datetime.now(timezone.utc) - created).days
        if age_days < 0:
            return None  # clock skew / bad data, don't penalize

        if age_days <= NEW_DOMAIN_THRESHOLD_DAYS:
            return {
                "type": "new_domain",
                "message": f"Domain was registered only {age_days} day(s) ago",
                "weight": 0.3 if age_days <= 14 else 0.15,
                "age_days": age_days,
            }
        return None
    except Exception as exc:  # WHOIS lookups fail often (rate limits, no server, etc.)
        logger.info("WHOIS lookup failed for %s: %s", registrable_domain, exc)
        return None
