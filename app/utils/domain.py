"""
Extracts the "registrable domain" (a.k.a. eTLD+1) from a URL, e.g.
"login.accounts.secure-paypal.co.uk" -> "secure-paypal.co.uk".

Uses `tldextract` because correctly handling multi-part public suffixes
(.co.uk, .com.au, etc.) requires the public suffix list -- a naive
"split on dots" approach gets this wrong.
"""
import tldextract


def get_registrable_domain(url_or_host: str) -> str:
    ext = tldextract.extract(url_or_host)
    if not ext.domain or not ext.suffix:
        # Fallback for malformed input / raw IPs -- just return as-is.
        return url_or_host
    return f"{ext.domain}.{ext.suffix}"
