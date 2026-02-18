# Cyber Saink Repo - DAST Report & Automated Vulnerability Assessment

**Automated Vulnerability Assessment | Web Security Hardening Assessment | Surface-Level Security Scan Report**

A powerful, all-in-one defensive security scanning agent that orchestrates industry-standard tools (OWASP ZAP, Nuclei, Nmap) and uses advanced LLMs (Gemini, OpenAI, Claude) to generate professional, executive-level PDF reports.

## 🚀 Features

-   **Automated DAST**: Integrates **OWASP ZAP** for spidering and passive/active scanning.
-   **Advanced Vulnerability Scanning**: Uses **Nuclei** with thousands of templates for CVEs and misconfigurations.
-   **Surface-Level Hardening**: Checks for missing security headers and sensitive information exposure.
-   **AI-Powered Analysis**: Uses **Google Gemini**, **OpenAI GPT-4**, or **Anthropic Claude** to analyze findings and provide remediation advice.
-   **Professional Reporting**: Generates a detailed PDF report titled **"DAST Report: Automated Vulnerability Assessment"**.

## 🛠️ System Architecture

1.  **Scanners**:
    -   **Network**: Port scanning.
    -   **Headers**: Security header analysis.
    -   **Secrets**: Regex-based secret detection.
    -   **ZAP**: Web application scanning.
    -   **Nuclei**: Template-based vulnerability scanning (Auto-installs!).

2.  **Intelligence Layer**:
    -   Aggregates findings from all tools.
    -   Sends data to the selected LLM for risk assessment and summarization.

3.  **Reporting**:
    -   Produces a polished PDF report.

## 📋 Prerequisites

-   **Python 3.10+**
-   **OWASP ZAP**: The agent can auto-download it, or you can run your own instance.
-   **API Keys**: Required for the LLM provider (Gemini, OpenAI, etc.).

## 📦 Installation

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/yourusername/Cyber-Saink-Repo.git
    cd Cyber-Saink-Repo
    ```

2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configuration**:
    Copy `sample.env` to `.env` and configure your keys:
    ```bash
    cp sample.env .env
    # Edit .env with your API keys
    ```

## 🚀 Usage

Run the main application:
```bash
python app.py
```

Follow the interactive prompts to:
1.  Enter the **Target URL**.
2.  Select your **LLM Provider** (if not configured in `.env`).
3.  Sit back while **Cyber Saink** performs a comprehensive audit.

## 📄 Output

-   **Console Logs**: Real-time progress of all scans.
-   **`DAST_Report_Automated_Vulnerability_Assessment.pdf`**: The final professional report.
-   **`findings.json`**: Raw data for further analysis.

## ⚠️ Disclaimer

This tool is for **authorized security auditing only**. Do not use it on targets you do not own or have explicit permission to test. The authors are not responsible for any misuse.
