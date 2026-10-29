"""
Quick manual smoke test against a running server:
    python run.py &
    python test_api.py
"""
import os
import requests
from dotenv import load_dotenv

load_dotenv()

BASE = "http://localhost:5000"
API_TOKEN = os.environ.get("API_TOKEN", "")
if not API_TOKEN:
    raise SystemExit("Set API_TOKEN in the backend .env file before running this smoke test.")

HEADERS = {"Authorization": f"Bearer {API_TOKEN}"}

cases = [
    ("https://www.google.com", "safe"),
    ("http://secure-login-verify.paypal.account-update.tk/signin", "suspicious_or_worse"),
    ("http://192.168.1.1/login", "flagged_ip"),
    ("https://bit.ly/3xample", "flagged_shortener"),
]

for url, label in cases:
    resp = requests.post(f"{BASE}/api/check-url", json={"url": url}, headers=HEADERS)
    print(f"\n[{label}] {url}")
    print(resp.status_code, resp.json())
