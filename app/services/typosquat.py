"""
Detects URLs that are suspiciously close (edit-distance-wise) to well-known
brand domains -- a classic phishing technique (e.g. "paypa1.com", "faceboook.com").
"""
from __future__ import annotations

# A small seed list -- extend this with whatever brands matter for your users,
# or load from a file/DB. Keep it to the *registrable domain* (no subdomains).
KNOWN_BRAND_DOMAINS = [
    "google.com", "paypal.com", "facebook.com", "apple.com", "microsoft.com",
    "amazon.com", "netflix.com", "instagram.com", "linkedin.com", "chase.com",
    "bankofamerica.com", "wellsfargo.com", "dropbox.com", "github.com",
    "outlook.com", "live.com", "yahoo.com", "ebay.com", "steamcommunity.com",
    "coinbase.com", "binance.com",
]


def levenshtein(a: str, b: str) -> int:
    """Standard edit distance, no external deps needed."""
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr_row = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr_row[j] = min(
                prev_row[j] + 1,      # deletion
                curr_row[j - 1] + 1,  # insertion
                prev_row[j - 1] + cost,  # substitution
            )
        prev_row = curr_row
    return prev_row[-1]


def check_typosquat(registrable_domain: str, max_distance: int = 2) -> dict | None:
    """
    Compares the domain against the known-brand list. Returns a finding dict
    if it's suspiciously close to a brand but NOT an exact match (exact match
    means it IS that brand, which is fine), else None.
    """
    domain = registrable_domain.lower()

    if domain in KNOWN_BRAND_DOMAINS:
        return None  # it's the real domain

    best_match = None
    best_distance = None

    for brand in KNOWN_BRAND_DOMAINS:
        dist = levenshtein(domain, brand)
        if best_distance is None or dist < best_distance:
            best_distance = dist
            best_match = brand

    if best_match and best_distance is not None and 0 < best_distance <= max_distance:
        return {
            "type": "typosquat",
            "brand": best_match,
            "distance": best_distance,
            "message": f"'{domain}' is suspiciously similar to '{best_match}' "
                       f"(edit distance {best_distance})",
            "weight": 0.35,
        }
    return None


def check_brand_in_subdomain(registrable_domain: str, hostname: str) -> dict | None:
    """Flag a known brand domain placed before an unrelated registrable domain."""
    domain = registrable_domain.lower().rstrip(".")
    host = hostname.lower().rstrip(".")
    suffix = f".{domain}"
    if not domain or not host.endswith(suffix):
        return None

    subdomain = host[: -len(suffix)]
    padded_subdomain = f".{subdomain}."
    for brand in KNOWN_BRAND_DOMAINS:
        if f".{brand}." in padded_subdomain:
            return {
                "type": "brand_in_subdomain",
                "brand": brand,
                "message": f"Brand domain '{brand}' appears in the subdomain of '{domain}'",
                "weight": 0.5,
            }
    return None
