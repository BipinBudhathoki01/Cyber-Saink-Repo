# Cyber Saink - Automated Red Team & DAST Scanner 🛡️

**The Ultimate Automated Vulnerability Assessment & Penetration Testing Tool**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Security](https://img.shields.io/badge/Security-Red%20Team-red)
![License](https://img.shields.io/badge/License-MIT-green)

**Cyber Saink** is an advanced, AI-powered security auditor that bridges the gap between passive scanning and active penetration testing. It orchestrates industry-standard tools (**OWASP ZAP**, **Nuclei**, **Nmap**) and uses **LLMs (Gemini, OpenAI, Claude)** to valid findings and generate professional **"Red Team" quality reports**.

---

## 🚀 Key Features

### ⚔️ Full Pentest Mode (Active Exploitation)
Unlike simple scanners, Cyber Saink includes a **"Red Team Mode"** that actively probes for:
-   **SQL Injection (SQLi)**: Fuzzes parameters with error-based payloads.
-   **Cross-Site Scripting (XSS)**: Tests for reflected script injection.
-   **Admin Panel Enumeration**: Brute-forces sensitive administrative paths (`/admin`, `.env`, `/.git`).
-   **JWT Security Analysis**: Decodes and audits JSON With Tokens for weak signatures (`alg: none`) and expiration.

### 🔍 DAST & Vulnerability Scanning
-   **OWASP ZAP Integration**: Automated spidering and active scanning (Attack Mode).
-   **Nuclei Powered**: Runs thousands of community-curated templates for CVEs, misconfigurations, and exposures.
-   **Network Recon**: Fast port scanning and service detection.
-   **Secret Detection**: Real-time regex matching for API keys and tokens in HTTP responses.

### 🧠 AI-Powered Reporting
-   **Intelligence Layer**: Aggregates findings from all scanners.
-   **LLM Analysis**: Uses **GPT-4** or **Gemini 1.5** to categorize risks, explain impact, and provide remediation code.
-   **Executive PDF Report**: Generates a polished `DAST_Report_Automated_Vulnerability_Assessment.pdf` ready for stakeholders.

---

## 🛠️ Installation

```bash
# 1. Clone the repository
git clone https://github.com/BipinBudhathoki01/Cyber-Saink-Repo.git
cd Cyber-Saink-Repo

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure API Keys
# Rename sample.env to .env and add your LLM Keys (OpenAI/Gemini)
cp sample.env .env
```

## ⚡ Usage

Run the agent and follow the interactive prompts:

```bash
python app.py
```

### Choose Your Mode:
1.  **Standard Audit**: Safe, passive scan. Good for initial recon.
2.  **Full Pentest Mode**: **[⚠️ WARNING]** Active exploitation. Triggers WAFs. Only use on authorized targets.

---

## 📊 Sample Output

```text
[+] Starting Audit for: https://example.com
[+] Mode: Red Team / Pentest

[+] Running Active Exploitation Probes...
    [!] Possible SQLi Found: id (Critical)
    [!] Possible XSS Found: search (High)

[+] Running Nuclei Scan...
    [+] Templates updated.
    [+] Vulnerabilities found: 12

[+] Generating Report with LLM...
[+] Report Saved: DAST_Report_Automated_Vulnerability_Assessment.pdf
```

## ⚠️ Legal Disclaimer

**Cyber Saink** is designed for **security professionals, bug bounty hunters, and authorized auditors**. The authors are not responsible for any illegal use of this tool. **Do not scan targets without explicit written permission.**

---

**Keywords**: *DAST, Pentest, Red Team, Vulnerability Scanner, Cyber Security, Bug Bounty, OWASP ZAP, Nuclei, Python, Automation, SQL Injection, XSS, LLM Security*
