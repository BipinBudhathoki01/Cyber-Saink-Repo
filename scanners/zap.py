import time
from zapv2 import ZAPv2

class ZapScanner:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.api_key = api_key
        self.zap = ZAPv2(apikey=api_key, proxies={'http': base_url, 'https': base_url})

    def is_available(self):
        try:
            version = self.zap.core.version
            print(f"    [DEBUG] Connected to ZAP v{version}")
            return True
        except Exception as e:
            print(f"    [DEBUG] Failed to connect to ZAP: {e}")
            return False

    def scan(self, target_url, active=False):
        findings = []
        try:
            print(f"    Accessing {target_url} through ZAP...")
            # Proxy access to seed passive scan
            self.zap.urlopen(target_url)
            time.sleep(2)
            
            # Spider
            print("    Starting Spider...")
            scan_id = self.zap.spider.scan(target_url)
            while int(self.zap.spider.status(scan_id)) < 100:
                time.sleep(1)
            print("    Spider Complete.")

            if active:
                print("    Starting Active Scan (Attack Mode)...")
                scan_id = self.zap.ascan.scan(target_url)
                while int(self.zap.ascan.status(scan_id)) < 100:
                    prog = self.zap.ascan.status(scan_id)
                    print(f"    Active Scan: {prog}%", end='\r')
                    time.sleep(5)
                print("\n    Active Scan Complete.")

            alerts = self.zap.core.alerts(baseurl=target_url)
            for alert in alerts:
                findings.append({
                    "title": alert.get("alert"),
                    "severity": alert.get("risk"),
                    "confidence": alert.get("confidence"),
                    "evidence": alert.get("evidence"),
                    "affected_url": alert.get("url"),
                    "category": "OWASP ZAP",
                    "recommendation": alert.get("solution"),
                })
                
        except Exception as e:
            print(f"Error during ZAP scan: {e}")
            
        return findings
