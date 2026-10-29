# Phishing Detection Backend (Flask)

Backend API for a browser-extension phishing detector. Scores a URL by
combining several signals and returns a risk score + verdict + human-readable
reasons.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # optional: add a Safe Browsing API key
python run.py
```

Set `API_TOKEN` in `.env` to a long random value. Set the same value as
`WXT_API_TOKEN` in the extension's `.env.local` before running/building it.
The API rejects scan requests when the token is missing or invalid.

Server runs on `http://localhost:5000` by default.

## API

### `GET /health`
Liveness check.

### `POST /api/check-url`

Include `Authorization: Bearer <API_TOKEN>` on scan requests. The extension
reads the matching token from `WXT_API_TOKEN` in its `.env.local` file.

**Request**
```json
{
  "url": "http://secure-login-paypal.account-verify.tk/signin",
  "deep_scan": false
}
```

- `url` (required)
- `deep_scan` (optional, default `false`) — also runs WHOIS domain-age lookup
  and Google Safe Browsing check. Slower (network calls), so the extension
  should probably only set this `true` for a popup "scan this page" action,
  not on every single navigation event.

**Response**
```json
{
  "url": "http://secure-login-paypal.account-verify.tk/signin",
  "domain": "account-verify.tk",
  "risk_score": 0.75,
  "verdict": "suspicious",
  "deep_scan": false,
  "reasons": [
    "Site does not use HTTPS",
    "Suspicious keyword(s) in subdomain: login, verify",
    "Domain uses a TLD commonly abused for phishing (.tk)",
    "'account-verify.tk' is suspiciously similar to 'paypal.com' ..."
  ],
  "findings": [ { "type": "no_https", "message": "...", "weight": 0.15 }, ... ]
}
```

`verdict` is one of: `safe`, `low_risk`, `suspicious`, `malicious`.

## What it checks

| Check | File | Needs network? |
|---|---|---|
| Typosquatting vs. known brands (Levenshtein distance) | `app/services/typosquat.py` | No |
| No HTTPS, IP-literal host, excessive subdomains/hyphens, `@` tricks, suspicious keywords/TLDs, shorteners | `app/services/heuristics.py` | No |
| Domain age via WHOIS (new domains are a red flag) | `app/services/domain_age.py` | Yes (WHOIS) |
| Google Safe Browsing threat list match | `app/services/safe_browsing.py` | Yes (API, optional key) |

Each check returns a finding with a `weight`; `app/services/scoring.py` sums
weights (capped at 1.0) into a final score. Swap `score_findings()` for a
trained ML model's `predict_proba()` later — nothing else needs to change.

## Extending

- Add more brands to `KNOWN_BRAND_DOMAINS` in `typosquat.py`, or load from a file/DB.
- Add a `/api/report` endpoint if you want users to flag false positives/negatives.
- Add simple rate limiting (e.g. `Flask-Limiter`) before exposing this publicly.
- For production, run behind `gunicorn` (already in requirements.txt):
  ```bash
  gunicorn -w 1 -b 127.0.0.1:5000 run:app
  ```

## CORS note

CORS is pre-configured in `app/__init__.py` to allow `chrome-extension://*`
and `moz-extension://*` origins, since that's what a WXT extension's
background/content script will call from. Tighten this to your specific
extension ID before shipping.
