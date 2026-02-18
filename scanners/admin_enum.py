import requests
import concurrent.futures

COMMON_PATHS = [
    "admin", "login", "dashboard", "wp-admin", "administrator",
    "backend", "backup", "db", "sql", "config", "env", ".env",
    "git", ".git/HEAD", "user", "auth", "portal", "cpanel",
    "phpmyadmin", "test", "dev", "staging", "api", "api/v1",
    "swagger", "docs", "robots.txt", "sitemap.xml"
]

def check_path(target, path):
    url = f"{target.rstrip('/')}/{path}"
    try:
        # Use a proper User-Agent to avoid immediate blocking
        headers = {'User-Agent': 'Mozilla/5.0 (CyberSaink-Pentest)'}
        res = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
        
        # 200 OK, 401 Unauthorized, 403 Forbidden are interesting
        if res.status_code in [200, 401, 403]:
            return {
                "path": path,
                "url": url,
                "status": res.status_code,
                "title": f"Sensitive Path Found: /{path}",
                "severity": "Medium" if res.status_code != 200 else "High",
                "evidence": f"Status Code: {res.status_code}",
                "description": f"The path /{path} is accessible or exists.",
                "remediation": "Restrict access to sensitive paths or ensure robust authentication."
            }
    except:
        pass
    return None

def scan_admin_paths(target_url):
    print(f"    [+] Enumerating {len(COMMON_PATHS)} common admin/sensitive paths...")
    findings = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_path = {executor.submit(check_path, target_url, path): path for path in COMMON_PATHS}
        for future in concurrent.futures.as_completed(future_to_path):
            result = future.result()
            if result:
                print(f"        [!] Found: {result['url']} ({result['status']})")
                findings.append({
                    "title": result["title"],
                    "severity": result["severity"],
                    "category": "Admin Enumeration",
                    "evidence": result["evidence"],
                    "affected_url": result["url"],
                    "recommendation": result["remediation"]
                })
                
    return findings
