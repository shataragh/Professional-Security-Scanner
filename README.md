# Professional Security Assessment Framework (PSAF) v14.0

<div align="center">

[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-yellow?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)](https://github.com/shataragh/Professional-Security-Scanner)
[![Version](https://img.shields.io/badge/Version-v14.0-orange?style=for-the-badge)](https://github.com/shataragh/Professional-Security-Scanner/releases)
[![Security](https://img.shields.io/badge/Security-Red%20Team-red?style=for-the-badge)](https://github.com/shataragh/Professional-Security-Scanner)
[![Modules](https://img.shields.io/badge/Modules-34-purple?style=for-the-badge)](https://github.com/shataragh/Professional-Security-Scanner)
[![Tools](https://img.shields.io/badge/Tools-11%2B-cyan?style=for-the-badge)](https://github.com/shataragh/Professional-Security-Scanner)

</div>

A sophisticated, modular red team automation framework designed for authorized penetration testing and academic research. Unlike basic scanners, PSAF actively exploits vulnerabilities, chains findings into full compromises, and validates results with an intelligence engine to filter false positives and detect honeypots.

> **⚠️ Important**: This tool is for **authorized security assessments only**. Use it on systems you own or have explicit written permission to test.

## 📌 Key Features

| Feature | Description |
|---------|-------------|
| **Active Exploitation** | Goes beyond detection: Proves vulnerabilities by extracting `/etc/passwd`, executing `id`, and gaining admin access. |
| **Attack Chain Engine** | 6 intelligent chains (e.g., LFI → Credentials → Admin Access, Race Condition → Logic Bypass) that use findings from one module to enable the next. |
| **Intelligence Validation Engine** | Multi-stage analysis to distinguish real vulnerabilities from false positives and honeypots with confidence scoring. |
| **Self-Protection System** | Optional operational security with proxy rotation, realistic headers, timing jitter, and circuit breakers to evade detection. |
| **Comprehensive Tool Integration** | Orchestration of 11+ industry-standard tools: Nmap, Nikto, SQLMap, Nuclei, Hashcat, ffuf, httpx, dalfox, gau, paramminer, subfinder. |
| **Logic Flaw Detection** | Advanced race condition (TOCTOU) testing using multi-threaded requests to exploit business logic flaws. |
| **Modular Architecture** | 34 independent modules allowing easy extension and customization for specific engagement requirements. |

## 🧰 Installation & Setup

### Prerequisites
-   Debian-based system (Ubuntu, Kali, Debian)
-   Python 3.8+
-   Git
-   Go 1.19+ (for Go-based tools)

### Step-by-Step Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/shataragh/Professional-Security-Scanner.git
    cd Professional-Security-Scanner
    ```

2.  **Create and Activate a Virtual Environment**
    ```bash
    python3 -m venv hack_env
    source hack_env/bin/activate
    ```

3.  **Install Python Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Install System Tools**
    ```bash
    sudo apt update
    sudo apt install -y nmap nikto sqlmap hashcat hydra golang-go
    ```

5.  **Install Go-Based Tools**
    ```bash
    export PATH=$PATH:$(go env GOPATH)/bin
    echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
    
    go install github.com/ffuf/ffuf/v2@latest
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install github.com/hahwul/dalfox/v2@latest
    go install github.com/lc/gau/v2/cmd/gau@latest
    # Note: subfinder requires Go 1.20+. On Go 1.19 systems, install v2.6.3:
    # go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.3
    ```

6.  **Download Data Resources**
    ```bash
    # SecLists Wordlists
    git clone https://github.com/danielmiessler/SecLists.git /root/SecLists
    
    # Nuclei Templates
    git clone https://github.com/projectdiscovery/nuclei-templates.git ~/nuclei-templates
    ```

For a detailed troubleshooting guide, see [`Toolkit Installation.md`](Toolkit%20Installation.md).

## 🚀 Usage

### Basic Scan (Fastest - Lab Testing)
```bash
python3 professional-security-scanner.py -t http://localhost:8080 -p aggressive
```
### Full Red Team Operation (With Self-Protection)
```bash
python3 professional-security-scanner.py -t http://target.com -p extreme --self-protect
```
### With Proxy Rotation
```bash
python3 professional-security-scanner.py -t http://target.com -p aggressive --self-protect --proxies /root/proxies.txt
```
### With Hydra Brute-Force
```bash
python3 professional-security-scanner.py -t http://target.com -p extreme --hydra --user admin
```
### Stealth Mode (Slow, Hard to Detect)
```bash
python3 professional-security-scanner.py -t http://target.com -p stealth --self-protect
```
### Available Scan Profiles

| Profile | Threads | Delay | Speed | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| `stealth` | 2 | 1.0s | Very Slow | Evasion against strict WAFs/IDS |
| `normal` | 5 | 0.3s | Medium | General-purpose scanning |
| `aggressive` | 20 | 0.02s | Fast | Default for most engagements |
| `extreme` | 40 | 0.01s | Very Fast | Local lab testing only |

### Command-Line Arguments

| Argument | Description |
| :--- | :--- |
| `-t, --target` | Target URL (required) |
| `-p, --profile` | Scan profile: stealth, normal, aggressive, extreme |
| `-c, --config` | Path to YAML configuration file |
| `-o, --output` | Output directory (default: /tmp/scan_results) |
| `--self-protect` | Enable self-protection system (slower but stealthier) |
| `--proxies` | Path to proxies file (one per line: ip:port or user:pass@ip:port) |
| `--hydra` | Enable Hydra brute-force module |
| `--user` | Username for Hydra brute-force (default: admin) |
| `--wordlist` | Custom wordlist path for Hydra |

### 📊 Output & Reports

After a scan completes, results are saved in the output directory (default: `/tmp/scan_results/`):

| File | Description |
| :--- | :--- |
| `report.json` | Machine-readable JSON with all findings, performance metrics, and attack context |
| `report.html` | Interactive HTML report with color-coded severity levels and attack context summary |
| `scanner.log` | Detailed timestamped log file for debugging and audit trails |
| `scan_state.pkl` | Pickled state file for resuming interrupted scans |
| `nuclei_results.json` | Raw Nuclei scan output (JSON format) |
| `sqlmap_results/` | SQLMap session files, extracted data, and logs |
| `chain_hashes.txt` | Extracted password hashes from database dumps for offline cracking |
| `chain_cracked.txt` | Successfully cracked credentials (from Hashcat) |
| `ffuf_results.json` | ffuf directory fuzzing results |
| `httpx_results.json` | httpx HTTP probing and technology detection results |
| `dalfox_results.json` | dalfox XSS verification results |
| `gau_results.txt` | Historical URLs discovered by gau |

The Intelligence Engine provides a validation summary at the end, including:
- **Total findings analyzed**
- **Valid findings** with confidence scores (0–100%)
- **Detected honeypots/decoy endpoints**
- **Filtered false positives** with rejection reasons
- **Target defensive posture profile** (WAF, IDS, honeypot probability)

## 🔒 Operational Security (Self-Protection)

The `--self-protect` flag enables a suite of anti-detection features designed to mimic legitimate human traffic and evade automated blocking systems:

| Component | Function |
| :--- | :--- |
| **Block Detector** | Classifies blocking type in real-time: rate limit, WAF block, CAPTCHA challenge, or IP ban. |
| **Proxy Rotator** | Automatically rotates through a provided list of proxies to avoid IP-based blacklisting. |
| **User-Agent Rotator** | Cycles through realistic browser fingerprints (Chrome, Firefox, Safari, Edge) for every request. |
| **Timing Controller** | Introduces human-like random jitter and occasional long pauses to defeat behavioral analysis. |
| **Circuit Breaker** | Automatically pauses all operations after 15 consecutive failures to prevent lockouts. |
| **Realistic Headers** | Adds standard browser headers (`Sec-Fetch-*`, `Accept-Encoding`, `Cache-Control`) to blend in with normal traffic. |

### Proxy File Format (`proxies.txt`)
Create a text file with one proxy per line:
```text
192.168.1.100:8080
192.168.1.101:8080
user:pass@192.168.1.102:8080
```
## 🏗️ Module Architecture

The framework is built on a modular architecture of **34 independent modules**, organized into six functional layers:

### 1. Reconnaissance & Discovery (Modules 1–9, 15–16, 27–32)
-   **Core Scanning**: Async HTTP scanning, technology fingerprinting, form auto-discovery.
-   **Security Analysis**: Header analysis, SSL/TLS inspection, WAF detection.
-   **Asset Discovery**: Subdomain enumeration (`subfinder`), historical URL discovery (`gau`), directory brute-forcing (`ffuf`).
-   **Tech Detection**: Fast HTTP probing (`httpx`) and hidden parameter discovery (`paramminer`).

### 2. Injection Testing (Modules 10–14, 22–23)
-   **Standard Payloads**: XSS, SQLi, LFI, and Command Injection using verified SecLists wordlists.
-   **Advanced Techniques**: Time-based blind SQLi, mutation XSS, CSP bypass, and DOM-based XSS (`dalfox`).
-   **Proof of Exploitation (PoE)**: Actively reads `/etc/passwd` or executes `id` to confirm vulnerability impact.

### 3. Advanced Red Team (Modules 20–25)
-   **Protocol Attacks**: HTTP request smuggling and WebSocket abuse.
-   **Auth Bypass**: JWT None algorithm attacks, session fixation, and path traversal in auth flows.
-   **Logic Flaws**: Multi-threaded race condition testing to exploit TOCTOU vulnerabilities.
-   **Evasion**: Unicode normalization bypasses and double-encoding techniques.

### 4. Attack Chain Engine (Module 26)
Automates the "Kill Chain" by chaining findings into full compromises:
-   **LFI → Admin**: Extracts credentials via LFI → Logs in → Verifies admin access.
-   **CVE → Shell**: Detects version → Finds CVE → Exploits via Nuclei → Verifies RCE.
-   **DB → Creds**: Finds DB dump → Extracts hashes → Cracks with Hashcat → Reuses credentials.
-   **Backup → Secrets**: Downloads `.env`/`.git` → Extracts API keys → Accesses admin endpoints.
-   **WAF → Bypass**: Detects WAF type → Crafts specific bypass payloads → Executes exploit.
-   **Race → Logic**: Identifies race endpoint → High-concurrency exploit → Verifies business logic impact.

### 5. Intelligence Validation Engine (Module 33)
A 5-stage validation pipeline that runs before any chain execution:
1.  **Honeypot Detection**: Identifies canary tokens, decoy headers, and tracking parameters.
2.  **False Positive Filtering**: Removes generic errors, default pages, and CAPTCHA responses.
3.  **Cross-Reference**: Requires corroboration from multiple tools or data sources.
4.  **Behavioral Analysis**: Flags suspicious response times or unusually large payloads.
5.  **Contextual Validation**: Ensures findings match the target’s technology stack and protocol.
   
*Output*: Each finding receives a **0–100% Confidence Score** and a classification (Valid, Honeypot, False Positive).

### 6. External Tool Orchestration
Seamlessly integrates industry-standard tools for depth and coverage:
-   **Nmap**: Service/version detection and OS fingerprinting.
-   **Nikto**: Web server vulnerability scanning.
-   **SQLMap**: Deep SQL injection testing with WAF tamper scripts.
-   **Nuclei**: 13,000+ template-based vulnerability scanning.
-   **Hashcat**: Automated password hash cracking integration.
