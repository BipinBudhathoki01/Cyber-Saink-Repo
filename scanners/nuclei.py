import os
import subprocess
import json
import shutil

class NucleiScanner:
    def __init__(self):
        self.binary = shutil.which("nuclei")
        if not self.binary:
            try:
                from .nuclei_launcher import get_nuclei_path
                local_path = get_nuclei_path()
                if os.path.exists(local_path):
                    self.binary = local_path
            except ImportError:
                pass
        
        if self.binary:
            self.update_templates()

    def update_templates(self):
        """Updates Nuclei templates."""
        print("    [+] Updating Nuclei Templates (this may take a moment)...")
        try:
            subprocess.run([self.binary, "-update-templates"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("    [+] Templates updated.")
        except Exception as e:
            print(f"    [-] Template update failed: {e}")

    def is_available(self):
        return self.binary is not None

    def scan(self, target_url):
        findings = []
        
        # Optimized scan command to be faster but still powerful
        print("    [+] Starting extensive vulnerability scan (CVEs, Misconfigs)...")
        print("    [+] This may take 2-5 minutes depending on the target speed.")
        
        cmd = [
            self.binary,
            "-u", target_url,
            "-tags", "cve,misconfig,exposure,panel", 
            "-severity", "critical,high,medium", # Focus on important issues
            "-timeout", "5", # Reduce timeout to prevent hanging
            "-retries", "1",
            "-j", # JSON output
            "-silent"
        ]
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()
            
            for line in stdout.splitlines():
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                    findings.append({
                        "title": data.get("info", {}).get("name"),
                        "severity": data.get("info", {}).get("severity"),
                        "confidence": "High", # Nuclei is generally actionable
                        "evidence": data.get("matched-at"),
                        "affected_url": data.get("matched-at"),
                        "category": f"Nuclei / {data.get('type', 'unknown')}",
                        "recommendation": data.get("info", {}).get("description"),
                    })
                except:
                    pass
                    
        except Exception as e:
            print(f"Error running Nuclei: {e}")

        return findings
