"""
WAF (Web Application Firewall) & CDN Detection Module.
"""
from core.config import WAF_SIGNATURES

def detect_waf(headers: dict, body: str = "") -> str:
    """
    Analyzes HTTP response headers and body content to identify active WAFs or CDNs.
    """
    headers_str = " ".join([f"{k.lower()}: {str(v).lower()}" for k, v in headers.items()])
    body_lower = body.lower() if body else ""

    detected = []

    for waf_name, sigs in WAF_SIGNATURES.items():
        matched = False
        for h in sigs.get("headers", []):
            if h.lower() in headers_str:
                matched = True
                break
        if not matched and body_lower:
            for b in sigs.get("body", []):
                if b.lower() in body_lower:
                    matched = True
                    break
        if matched:
            detected.append(waf_name)

    return ", ".join(detected) if detected else "None / Direct"
