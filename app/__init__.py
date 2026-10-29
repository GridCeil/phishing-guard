import os
import time
import hmac
from threading import Lock
from flask import Flask
from flask import jsonify, request
from flask_cors import CORS


def create_app(config_object: str | None = None) -> Flask:
    """Application factory."""
    app = Flask(__name__)

    # --- Config ---
    app.config.from_mapping(
        GOOGLE_SAFE_BROWSING_API_KEY=os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", ""),
        API_TOKEN=os.environ.get("API_TOKEN", ""),
        RATE_LIMIT_PER_MINUTE=int(os.environ.get("RATE_LIMIT_PER_MINUTE", "60")),
        WHOIS_LOOKUP_ENABLED=os.environ.get("WHOIS_LOOKUP_ENABLED", "true").lower() == "true",
    )
    if config_object:
        app.config.from_object(config_object)

    # --- CORS ---
    # Browser extensions call this from a chrome-extension:// / moz-extension:// origin,
    # not a normal https:// origin, so we allow those explicitly.
    CORS(
        app,
        resources={r"/api/*": {"origins": [
            "chrome-extension://*",
            "moz-extension://*",
            "http://localhost:*",
        ]}},
        allow_headers=["Content-Type", "Authorization"],
    )

    # --- Blueprints ---
    from app.routes.check import bp as check_bp
    from app.routes.health import bp as health_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(check_bp, url_prefix="/api")

    # Lightweight per-process limit for the scan endpoint. For multiple
    # workers, enforce the same limit in a shared store or at the proxy.
    rate_state = {"window": None, "counts": {}}
    rate_lock = Lock()

    @app.before_request
    def limit_url_checks():
        if request.path.startswith("/api/") and request.method != "OPTIONS":
            expected_token = app.config.get("API_TOKEN", "")
            if not expected_token:
                return jsonify({"error": "API authentication is not configured"}), 503

            scheme, separator, supplied_token = request.headers.get("Authorization", "").partition(" ")
            if (
                not separator
                or scheme.lower() != "bearer"
                or not hmac.compare_digest(supplied_token, expected_token)
            ):
                return jsonify({"error": "Unauthorized"}), 401, {"WWW-Authenticate": "Bearer"}

        if request.endpoint != "check.check_url":
            return None

        now = time.time()
        window = int(now // 60)
        client_ip = request.remote_addr or "unknown"
        limit = max(1, int(app.config.get("RATE_LIMIT_PER_MINUTE", 60)))

        with rate_lock:
            if rate_state["window"] != window:
                rate_state["window"] = window
                rate_state["counts"] = {}

            count = rate_state["counts"].get(client_ip, 0)
            if count >= limit:
                response = jsonify({"error": "Rate limit exceeded"})
                response.status_code = 429
                response.headers["Retry-After"] = str(60 - int(now % 60))
                return response

            rate_state["counts"][client_ip] = count + 1

        return None

    return app
