import os
import sys
import json
import getpass
import requests
from config import Settings
from scanners.headers import scan_headers
from scanners.zap import ZapScanner
from scanners.nuclei import NucleiScanner
from scanners.network import scan_network
from scanners.secrets import scan_for_secrets
from llm.router import get_llm
from reporting.pdf_report import write_pdf

def prompt_for_inputs():
    print("--- Cyber Audit Agent ---")
    target = os.getenv("TARGET_URL")
    if not target:
        target = input("Enter Target URL (e.g., https://example.com): ").strip()
    
    # Provider selection
    provider = os.getenv("LLM_PROVIDER")
    if not provider:
        print("\nSelect LLM Provider:")
        print("1. OpenAI (GPT-4)")
        print("2. Google Gemini")
        print("3. Anthropic Claude")
        choice = input("Choice [1-3]: ").strip()
        provider_map = {"1": "openai", "2": "gemini", "3": "anthropic"}
        provider = provider_map.get(choice, "openai")
        os.environ["LLM_PROVIDER"] = provider

    # API Key
    env_var_name = f"{provider.upper()}_API_KEY"
    api_key = os.getenv(env_var_name)
    if not api_key:
        api_key = getpass.getpass(f"Enter {provider.upper()} API Key: ").strip()
        os.environ[env_var_name] = api_key

    return target

def main():
    target = prompt_for_inputs()
    settings = Settings(target_url=target)
    
    print(f"\n[+] Starting Audit for: {settings.target_url}")
    print(f"[+] LLM Provider: {settings.llm_provider}")
    print(f"[+] Safe Mode: {settings.safe_mode}")

    findings = []
    
    # 1. Network Scan (Open Ports)
    print("\n[+] Running Network Port Scan...")
    findings += scan_network(settings.target_url)

    # 2. Header Scan
    print("\n[+] Running Header Scan...")
    findings += scan_headers(settings.target_url)
    
    # 2a. Quick Secrets Scan on Homepage
    print("\n[+] Checking Homepage for Secrets...")
    try:
        resp = requests.get(settings.target_url, timeout=10)
        findings += scan_for_secrets(resp.text, settings.target_url)
    except:
        pass

    # 3. ZAP Scan
    print("\n[+] Running ZAP Scan (Passive)...")
    zap = ZapScanner(settings.zap_base_url, settings.zap_api_key)
    
    if not zap.is_available():
        print("[-] ZAP API not reachable. Attempting to launch ZAP...")
        try:
            from scanners.zap_launcher import start_zap_daemon, is_zap_installed, download_and_extract_zap
            
            if not is_zap_installed():
                print("    ZAP not found locally. Downloading cross-platform package...")
                if download_and_extract_zap():
                    print("    Download successful.")
                else:
                    print("    Download failed.")
            
            if is_zap_installed():
                proc = start_zap_daemon(port=8080)
                if proc:
                    # Give it a moment to fully initialize API
                    import time
                    time.sleep(5)
                    # Re-initialize client
                    zap = ZapScanner("http://127.0.0.1:8080", None)
        except ImportError:
            print("    Could not import zap_launcher. Ensure dependencies are installed.")
        except Exception as e:
            print(f"    Error launching ZAP: {e}")

    if zap.is_available():
        findings += zap.scan(settings.target_url, active=not settings.safe_mode)
    else:
        print("[-] ZAP still not reachable. Skipping scan.")

    # 4. Nuclei Scan
    print("\n[+] Running Nuclei Scan...")
    from scanners.nuclei import NucleiScanner
    nuclei = NucleiScanner()
    
    if not nuclei.is_available():
        print("[-] Nuclei not found. Attempting to auto-install...")
        try:
            from scanners.nuclei_launcher import download_and_extract_nuclei, is_nuclei_installed
            if download_and_extract_nuclei():
                # Re-initialize to pick up the new binary
                nuclei = NucleiScanner()
        except Exception as e:
            print(f"    Error installing Nuclei: {e}")

    if nuclei.is_available():
        findings += nuclei.scan(settings.target_url)
    else:
        print("[-] Nuclei still not found. Skipping.")

    print(f"\n[+] Total Findings: {len(findings)}")

    # 5. LLM Analysis
    print("\n[+] Generating Report with LLM...")
    try:
        llm = get_llm(settings)
        prompt = {
            "target": settings.target_url,
            "findings": findings,
            "instructions": (
                "You are an expert Cyber Security Auditor acting as an agent."
                "Review the provided security findings and categorize them into the following buckets:\n"
                "- Web & API (Auth, Injection, XSS, Headers)\n"
                "- Network & Infrastructure (Ports, TLS, DNS)\n"
                "- Cloud & IAM (Metadata, Buckets, Permissions)\n"
                "- Code & Dependency (Secrets, CVEs, Supply Chain)\n\n"
                "For EACH finding:\n"
                "1. Assign a mapping to OWASP Top 10 (2021) or API Top 10 if applicable.\n"
                "2. Assign a relevant CWE ID if possible.\n"
                "3. Provide a clear, non-destructive reproduction step (e.g., 'Check header X').\n"
                "4. Provide a remediation snippet (code or config).\n\n"
                "Finally, write a Professional Executive Summary highlighting the top 3 critical risks "
                "and the overall security posture."
            )
        }
        summary = llm.summarize(prompt)
    except Exception as e:
        print(f"[-] LLM Error: {e}")
        import traceback
        traceback.print_exc()
        summary = "Error generating summary. See findings list."

    # 6. Report Generation
    report_path = "DAST_Report_Automated_Vulnerability_Assessment.pdf"
    write_pdf(report_path, settings.target_url, summary, findings)
    
    print(f"\n[+] Report Saved: {os.path.abspath(report_path)}")
    # Dump raw JSON for debugging
    with open("findings.json", "w") as f:
        json.dump(findings, f, indent=2)

if __name__ == "__main__":
    main()
