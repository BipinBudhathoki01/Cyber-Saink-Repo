import re

# Common Secret Patterns
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9\/+=]{40})",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Stripe Publishable Key": r"pk_live_[0-9a-zA-Z]{24}",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Generic Private Key": r"-----BEGIN PRIVATE KEY-----",
    "Basic Auth": r"Authorization:\s*Basic\s+[a-zA-Z0-9+/=]+",
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})"
}

def scan_for_secrets(content: str, url: str):
    findings = []
    
    for name, pattern in SECRET_PATTERNS.items():
        matches = re.finditer(pattern, content)
        for match in matches:
            # Mask the secret in the evidence
            secret = match.group(0)
            masked = secret[:4] + "*" * (len(secret) - 8) + secret[-4:] if len(secret) > 8 else "***"
            
            findings.append({
                "title": f"Potential Secret Found: {name}",
                "severity": "Critical",
                "confidence": "Medium", # Regex can validly match random strings
                "evidence": f"Found pattern matching {name}: {masked}",
                "affected_url": url,
                "category": "Code & Data / Secrets",
                "recommendation": "Rotate this key immediately and remove it from codebase/responses.",
            })
            # Limit to one match per type to avoid spam
            break
            
    return findings
