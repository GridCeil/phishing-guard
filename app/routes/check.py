from __future__ import annotations
import logging
from urllib.parse import urlparse

from flask import Blueprint, current_app, jsonify, request

from app.services.typosquat import check_typosquat, check_brand_in_subdomain
from app.services.heuristics import run_all_heuristics
from app.services.domain_age import check_domain_age
from app.services.safe_browsing import check_safe_browsing
from app.services.scoring import score_findings
from app.utils.domain import get_registrable_domain

logger = logging.getLogger(__name__)
bp = Blueprint("check", __name__)


def _is_valid_url(raw_url: str) -> bool:
    if len(raw_url) > 8192 or any(ord(char) < 32 or char.isspace() for char in raw_url):
        return False
    try:
        parsed = urlparse(raw_url)
        # Accessing .port also validates that an explicit port is numeric and
        # within the valid TCP port range.
        _ = parsed.port
        return parsed.scheme in ("http", "https") and bool(parsed.hostname)
    except ValueError:
        return False


@bp.post("/check-url")
def check_url():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    raw_value = payload.get("url")
    if raw_value is not None and not isinstance(raw_value, str):
        return jsonify({"error": "'url' must be a string"}), 400
    raw_url = (raw_value or "").strip()

    if not raw_url:
        return jsonify({"error": "Missing 'url' in request body"}), 400
    if not _is_valid_url(raw_url):
        return jsonify({"error": "Invalid URL"}), 400

    # Optional flags from the client so a content-script "quick check" on every
    # navigation doesn't have to pay for a WHOIS lookup every time.
    deep_scan = payload.get("deep_scan", False)
    if not isinstance(deep_scan, bool):
        return jsonify({"error": "'deep_scan' must be a boolean"}), 400

    registrable_domain = get_registrable_domain(raw_url)

    findings = []
    findings += run_all_heuristics(raw_url, registrable_domain)

    typosquat_finding = check_typosquat(registrable_domain)
    if typosquat_finding:
        findings.append(typosquat_finding)

    brand_subdomain_finding = check_brand_in_subdomain(
        registrable_domain, urlparse(raw_url).hostname or ""
    )
    if brand_subdomain_finding:
        findings.append(brand_subdomain_finding)

    if deep_scan:
        age_finding = None
        if current_app.config.get("WHOIS_LOOKUP_ENABLED"):
            age_finding = check_domain_age(registrable_domain)
        if age_finding:
            findings.append(age_finding)

        api_key = current_app.config.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
        sb_finding = check_safe_browsing(raw_url, api_key)
        if sb_finding:
            findings.append(sb_finding)

    result = score_findings(findings)
    result["url"] = raw_url
    result["domain"] = registrable_domain
    result["deep_scan"] = deep_scan

    logger.info("Checked domain %s -> %s (%.2f)", registrable_domain, result["verdict"], result["risk_score"])
    return jsonify(result)
