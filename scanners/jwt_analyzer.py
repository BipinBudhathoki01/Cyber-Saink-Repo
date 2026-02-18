import re
import json
import base64
import requests

def extract_jwts(text):
    # Regex to find potential JWTs (header.payload.signature)
    jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
    return re.findall(jwt_pattern, text)

def decode_base64_url(data):
    # Add padding if needed
    padding = '=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data + padding).decode('utf-8')

def analyze_jwt(token):
    try:
        header_b64, payload_b64, signature = token.split('.')
        header = json.loads(decode_base64_url(header_b64))
        payload = json.loads(decode_base64_url(payload_b64))
        
        issues = []
        
        # Check Algorithm
        alg = header.get('alg', 'none')
        if alg.lower() == 'none':
            issues.append("Critical: 'alg' is 'none' (Signature bypass possible)")
        elif alg == 'HS256':
            issues.append("Info: Using symmetric key (HS256). Ensure strong secret.")
            
        # Check Expiration
        if 'exp' not in payload:
            issues.append("Medium: No expiration ('exp') claim found.")
            
        return {
            "token": token[:20] + "...",
            "header": header,
            "payload": payload,
            "issues": issues
        }
    except Exception as e:
        return {"error": f"Failed to decode JWT: {e}"}

def scan_jwt(target_url):
    print("    [+] Checking for JWT Weaknesses...")
    findings = []
    
    try:
        res = requests.get(target_url, timeout=10)
        
        # Check Cookies
        for cookie in res.cookies:
            jwts = extract_jwts(cookie.value)
            for token in jwts:
                analysis = analyze_jwt(token)
                if analysis.get('issues'):
                    print(f"        [!] JWT Issue in Cookie: {cookie.name}")
                    findings.append({
                        "title": "Weak JWT Configuration",
                        "severity": "High" if "Critical" in str(analysis['issues']) else "Medium",
                        "category": "Broken Authentication",
                        "evidence": f"Cookie: {cookie.name}\nIssues: {analysis['issues']}",
                        "affected_url": target_url,
                        "recommendation": "Use strong signing algorithms (RS256) and set expiration."
                    })
        
        # Check Body/Headers
        all_text = res.text + str(res.headers)
        jwts = extract_jwts(all_text)
        for token in jwts:
            analysis = analyze_jwt(token)
            if analysis.get('issues'):
                print(f"        [!] JWT Issue found in response")
                findings.append({
                    "title": "Weak JWT Configuration",
                    "severity": "High" if "Critical" in str(analysis['issues']) else "Medium",
                    "category": "Broken Authentication",
                    "evidence": f"Token starts with: {token[:10]}...\nIssues: {analysis['issues']}",
                    "affected_url": target_url,
                    "recommendation": "Use strong signing algorithms (RS256) and set expiration."
                })
                
    except:
        pass
        
    return findings
