import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "' UNION SELECT 1,2,3 --",
    "admin' --",
    "' AND 1=1 --"
]
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>"
]

def scan_sql_injection(target_url):
    print("    [+] Probing for SQL Injection...")
    findings = []
    
    parsed = urlparse(target_url)
    params = parse_qs(parsed.query)
    
    if not params:
        print("        [i] No URL parameters found to test.")
        return []

    for param, value in params.items():
        for payload in SQLI_PAYLOADS:
            # Inject payload
            params_copy = params.copy()
            params_copy[param] = [payload]
            query_string = urlencode(params_copy, doseq=True)
            vuln_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_string, parsed.fragment))
            
            try:
                # Check response
                res = requests.get(vuln_url, timeout=5)
                # Look for SQL errors
                errors = ["syntax error", "mysql_fetch", "ora-01756", "unclosed quotation mark"]
                if any(e in res.text.lower() for e in errors):
                     print(f"        [!] Possible SQLi Found: {param}")
                     findings.append({
                         "title": "Possible SQL Injection",
                         "severity": "Critical",
                         "category": "Injection",
                         "evidence": payload,
                         "affected_url": vuln_url,
                         "recommendation": "Use parameterized queries/prepared statements."
                     })
                     break # Stop testing this parameter if vuln found
            except:
                pass
                
    return findings

def scan_xss(target_url):
    print("    [+] Probing for Reflected XSS...")
    findings = []
    
    parsed = urlparse(target_url)
    params = parse_qs(parsed.query)
    
    if not params:
        return []

    for param, value in params.items():
        for payload in XSS_PAYLOADS:
            params_copy = params.copy()
            params_copy[param] = [payload]
            query_string = urlencode(params_copy, doseq=True)
            vuln_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_string, parsed.fragment))
            
            try:
                res = requests.get(vuln_url, timeout=5)
                if payload in res.text:
                     print(f"        [!] Possible XSS Found: {param}")
                     findings.append({
                         "title": "Reflected XSS",
                         "severity": "High",
                         "category": "Cross-Site Scripting",
                         "evidence": payload,
                         "affected_url": vuln_url,
                         "recommendation": "Sanitize input and escape output (HTML encoding)."
                     })
                     break
            except:
                pass
                
    return findings
