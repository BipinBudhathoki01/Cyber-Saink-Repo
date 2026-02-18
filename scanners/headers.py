import requests

SEC_HEADERS = {
    "strict-transport-security": ("HSTS", "Enable HSTS with a long max-age and includeSubDomains."),
    "content-security-policy": ("CSP", "Add a Content-Security-Policy to reduce XSS risk."),
    "x-frame-options": ("Clickjacking", "Set X-Frame-Options or use CSP frame-ancestors."),
    "x-content-type-options": ("MIME sniffing", "Set X-Content-Type-Options: nosniff."),
    "referrer-policy": ("Referrer policy", "Set a strict Referrer-Policy."),
    "permissions-policy": ("Permissions policy", "Restrict powerful features with Permissions-Policy."),
}

def scan_headers(url: str, timeout: int = 15):
    findings = []
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        headers = {k.lower(): v for k, v in r.headers.items()}

        for key, (cat, rec) in SEC_HEADERS.items():
            if key not in headers:
                findings.append({
                    "title": f"Missing {key} header",
                    "severity": "Medium" if key in ("strict-transport-security", "content-security-policy") else "Low",
                    "confidence": "High",
                    "evidence": f"{key} not present in response headers",
                    "affected_url": r.url,
                    "category": f"Security Headers / {cat}",
                    "recommendation": rec,
                })
    except Exception as e:
        print(f"Error scanning headers: {e}")
        
    return findings
