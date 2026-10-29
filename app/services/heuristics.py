"""
Lightweight, dependency-free heuristics on URL structure. Each check returns
either None (no finding) or a dict: {type, message, weight}.
`weight` contributes to the overall risk score (0.0-1.0 scale, summed and capped).
"""
from __future__ import annotations
import ipaddress
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "secure", "banking",
    "confirm", "webscr", "suspend", "unlock", "password", "wallet",
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "work", "click",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
}


def check_no_https(parsed) -> dict | None:
    if parsed.scheme != "https":
        return {
            "type": "no_https",
            "message": "Site does not use HTTPS",
            "weight": 0.15,
        }
    return None


def check_ip_host(parsed) -> dict | None:
    host = (parsed.hostname or "").strip("[]")  # strip IPv6 brackets
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None
    else:
        return {
            "type": "ip_host",
            "message": f"URL uses a raw IP address ({host}) instead of a domain name",
            "weight": 0.3,
        }


def check_excessive_subdomains(parsed, max_allowed: int = 3) -> dict | None:
    host = parsed.hostname or ""
    parts = host.split(".")
    if len(parts) - 2 > max_allowed:  # subtract domain + TLD
        return {
            "type": "excessive_subdomains",
            "message": f"URL has an unusually high number of subdomains ({host})",
            "weight": 0.2,
        }
    return None


def check_suspicious_keywords_in_subdomain(registrable_domain: str, parsed) -> dict | None:
    """Keywords like 'login', 'secure' stuffed into a subdomain of an
    unrelated domain is a common phishing pattern, e.g.
    secure-login-paypal.verify-account.com"""
    host = parsed.hostname or ""
    subdomain_part = host[: -len(registrable_domain)] if host.endswith(registrable_domain) else host
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in subdomain_part.lower()]
    if hits:
        return {
            "type": "suspicious_keywords",
            "message": f"Suspicious keyword(s) in subdomain: {', '.join(hits)}",
            "weight": 0.15 * min(len(hits), 2),
        }
    return None


def check_suspicious_tld(registrable_domain: str) -> dict | None:
    tld = registrable_domain.rsplit(".", 1)[-1].lower()
    if tld in SUSPICIOUS_TLDS:
        return {
            "type": "suspicious_tld",
            "message": f"Domain uses a TLD commonly abused for phishing (.{tld})",
            "weight": 0.15,
        }
    return None


def check_url_shortener(registrable_domain: str) -> dict | None:
    if registrable_domain.lower() in URL_SHORTENERS:
        return {
            "type": "url_shortener",
            "message": "URL uses a link shortener, which can mask the real destination",
            "weight": 0.1,
        }
    return None


def check_at_symbol(raw_url: str) -> dict | None:
    """URLs with '@' can trick browsers into treating everything before
    it as a username, hiding the real host after it."""
    parsed = urlparse(raw_url)
    netloc_section = raw_url.split("://", 1)[-1].split("/", 1)[0]
    if "@" in netloc_section:
        return {
            "type": "at_symbol",
            "message": "URL contains '@', which can be used to disguise the real destination",
            "weight": 0.25,
        }
    return None


def check_excessive_hyphens(registrable_domain: str, max_allowed: int = 2) -> dict | None:
    hyphens = registrable_domain.count("-")
    if hyphens > max_allowed:
        return {
            "type": "excessive_hyphens",
            "message": f"Domain has an unusually high number of hyphens ({registrable_domain})",
            "weight": 0.1,
        }
    return None


def run_all_heuristics(raw_url: str, registrable_domain: str) -> list[dict]:
    parsed = urlparse(raw_url)
    checks = [
        check_no_https(parsed),
        check_ip_host(parsed),
        check_excessive_subdomains(parsed),
        check_suspicious_keywords_in_subdomain(registrable_domain, parsed),
        check_suspicious_tld(registrable_domain),
        check_url_shortener(registrable_domain),
        check_at_symbol(raw_url),
        check_excessive_hyphens(registrable_domain),
    ]
    return [c for c in checks if c is not None]
