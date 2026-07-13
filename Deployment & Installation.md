# ️ Professional Red Team Penetration Testing Framework (PSAF) v14.0

A sophisticated, multi-module red team automation framework designed for active exploitation, attack chaining, intelligence validation, and authorized penetration testing. This guide provides complete instructions for deploying the framework and initializing its operational environment on Debian-based systems.

---

## 🚀 Complete Deployment Guide

Follow these sequential steps to deploy the framework, install all dependencies, and verify readiness for red team operations.

### 1. Clone the Repository
Clone the codebase from GitHub and navigate into the project root directory:
```bash
git clone https://github.com/shataragh/professional-security-scanner.git
cd professional-security-scanner
```
### 2. Setup Python Virtual Environment
It is strongly recommended to use a virtual environment to isolate dependencies:
```bash
python3 -m venv pentest_env
source pentest_env/bin/activate
```
### 3. Install Python Dependencies
Install all required external libraries using the included requirements file:
```bash
pip install -r requirements.txt
```
### 4. Install Core Security Utilities
Install standard network mapping, web vulnerability assessment, database exploitation, credential cracking, and brute-force tools via the system package manager:
```bash
sudo apt update && sudo apt install -y nmap nikto sqlmap hashcat hydra golang-go
```
### 5. Deploy Go-Based Toolchain
The framework integrates several high-performance Go tools for fuzzing, probing, and discovery. Ensure your $GOPATH is configured, then install each tool:
```bash
export PATH=$PATH:$(go env GOPATH)/bin
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc

go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.3
```
Note: subfinder is installed at v2.6.3 for compatibility with Go 1.19. If you are running Go 1.20+, you may use @latest instead.

### 6. Deploy Nuclei & Templates
Nuclei provides template-based vulnerability scanning with 13,000+ community-curated templates.
If not already installed via apt, deploy via Go:
```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```
### 7. Deploy Wordlists & Payloads (SecLists)
SecLists provides usernames, passwords, URLs, sensitive data patterns, and fuzzing payloads required by all injection and discovery modules.
Clone directly into the expected environment directory:
```bash
git clone https://github.com/danielmiessler/SecLists.git /root/SecLists
```
### 8. Verify Complete Installation
Run the built-in dependency verification script to confirm all components are correctly installed and accessible:
```bash
chmod +x check_deps.sh
./check_deps.sh
```
Alternatively, verify manually:
```bash
# Verify Python packages
python3 -c "import aiohttp, bs4, tqdm, yaml, requests, colorama, jinja2, lxml, websocket; print('✓ Python OK')"

# Verify system tools
nmap --version && nikto -Version && sqlmap --version && hashcat --version && hydra -h && nuclei -version

# Verify Go tools
ffuf -V && httpx -version && dalfox version && gau --version && subfinder -version

# Verify data resources
ls /root/SecLists/Discovery/Web-Content/common.txt && ls ~/nuclei-templates/http/ | head -5
```
### 9. Test Framework Initialization
Confirm the scanner loads correctly and displays the help menu:
```bash
python3 professional-security-scanner.py --help
```
### Post-Installation Notes
32-bit Systems: If running on i386/i686 architecture, some modern Go tools may not compile. The framework includes graceful degradation and will skip missing modules with warnings.

Proxy Configuration: For self-protection mode, create a /root/proxies.txt file with one proxy per line in format ip:port or user:pass@ip:port.

NVD API Key: For CVE lookups without rate limits, add your free NVD API key to config.yaml under nvd_api_key.

First Run: Always test against authorized targets only. Start with -p stealth profile when testing against defended systems to establish baseline behavior before escalating to -p extreme.
