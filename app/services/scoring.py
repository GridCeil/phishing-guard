"""
Combines findings from all detectors into a single risk score + verdict.
"""
from __future__ import annotations

VERDICT_THRESHOLDS = (
    ("malicious", 0.75),
    ("suspicious", 0.4),
    ("low_risk", 0.15),
    ("safe", 0.0),
)


def score_findings(findings: list[dict]) -> dict:
    # Simple capped sum of weights. Swap this out for a trained model's
    # predict_proba() later without touching any calling code.
    raw_score = sum(f.get("weight", 0) for f in findings)
    score = min(raw_score, 1.0)

    verdict = "safe"
    for label, threshold in VERDICT_THRESHOLDS:
        if score >= threshold:
            verdict = label
            break

    return {
        "risk_score": round(score, 2),
        "verdict": verdict,
        "reasons": [f["message"] for f in findings],
        "findings": findings,  # structured, for UI badges/icons per reason type
    }
