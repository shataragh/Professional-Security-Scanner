# Red Team Penetration Testing Toolkit Installation (v14.0)

This guide details the installation of essential security assessment tools, active exploitation frameworks, reconnaissance utilities, and wordlists required for the **Professional Security Assessment Framework (PSAF) v14.0**.

> **⚠️ Note for 32-bit Systems:** Some modern Go-based tools require Go 1.20+. On older 32-bit Debian systems (Go 1.19), certain tools may fail to compile. The framework is designed with graceful degradation and will skip missing modules automatically.

---

## 🐍 Python Environment & Dependencies

Ensure you have Python 3.9+ installed. Create and activate a virtual environment before installing dependencies:

```bash
python3 -m venv ~/pentest_env
source ~/pentest_env/bin/activate
pip install aiohttp beautifulsoup4 tqdm pyyaml requests colorama jinja2 lxml websocket-client
```
## 🛡️ Core Security Utilities

Install standard network mapping, vulnerability assessment, database exploitation, and credential cracking tools via the system package manager:
```bash
sudo apt update && sudo apt install -y nmap nikto sqlmap hashcat hydra golang-go
```
## 🔧 Go-Based Reconnaissance & Exploitation Tools

These tools significantly enhance discovery speed and XSS detection. Ensure Go is in your PATH:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```
## Fast Web Fuzzer (ffuf)

High-speed directory brute-forcing and parameter fuzzing:
```bash
go install github.com/ffuf/ffuf/v2@latest
```
## HTTP Probing (httpx)

Fast HTTP probing with technology detection:
```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```
## Advanced XSS Scanner (dalfox)

Specialized XSS detection with DOM analysis:
```bash
go install github.com/hahwul/dalfox/v2@latest
```
## Historical URL Discovery (gau)

Retrieves URLs from Wayback Machine, Common Crawl, etc.:
```bash
go install github.com/lc/gau/v2/cmd/gau@latest
```
## Passive Subdomain Enumerator (subfinder)

> **⚠️Note:** Requires Go 1.20+. Skip if on Go 1.19.
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.3
```
## Hidden Parameter Discovery (paramminer)

Finds unlinked parameters via brute-force:
```bash
go install github.com/PortSwigger/param-miner@latest
```
## 🔍 Vulnerability Scanning (Nuclei)

Nuclei is a fast, customizable vulnerability scanner based on simple DSL templates.
Installation via Go
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```
Template Initialization
Download and update the latest community-curated vulnerability templates:
```bash
nuclei -update-templates
```
Troubleshooting 32-bit Systems: If -update-templates fails due to version parsing errors, manually clone templates:
```bash
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git ~/nuclei-templates
```
## Wordlists & Payloads (SecLists)
SecLists is a security tester's companion containing usernames, passwords, URLs, sensitive data patterns, and fuzzing payloads.
Clone the repository directly into the preferred environment directory:
```bash
git clone https://github.com/danielmiessler/SecLists.git /root/SecLists
```
## Verified Paths for PSAF v14.0
The framework expects these specific paths:
>/root/SecLists/Discovery/Web-Content/common.txt

>/root/SecLists/Fuzzing/XSS/human-friendly/XSS-BruteLogic.txt

>/root/SecLists/Fuzzing/Databases/SQLi/Generic-SQLi.txt

>/root/SecLists/Fuzzing/LFI/Linux/LFI-gracefulsecurity-linux.txt

>/root/SecLists/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt

>/root/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
---







