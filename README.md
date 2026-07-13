<div align="center">

# Professional Red Team Penetration Testing Framework (PSAF) v14.0

![GitHub License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge&logo=opensourceinitiative)
![Version: 14.0](https://img.shields.io/badge/Version-14.0-red.svg?style=for-the-badge&logo=semver)
![Status: Active Exploitation](https://img.shields.io/badge/Status-Red%20Team-orange.svg?style=for-the-badge&logo=statuspage)
![Python Version](https://img.shields.io/badge/Python-3.9+-3776AB.svg?style=for-the-badge&logo=python)

*A sophisticated, multi-module red team automation framework designed for active exploitation, attack chaining, and authorized penetration testing.*

</div>

---

## 🏛️ Executive Summary
PSAF v14.0 evolves beyond traditional assessment into a full-spectrum **Red Team Automation Framework**. It integrates 34+ advanced modules with an intelligent **Attack Chain Engine** that actively exploits vulnerabilities, chains findings into compromise paths, and validates results using a built-in **Intelligence Engine** to filter false positives and detect honeypots. Designed for scalability, stealth, and precision in authorized engagements.

> **⚠️ Legal Disclaimer:** This tool is intended for **authorized security testing and academic research only**. Use only on systems you own or have explicit written permission to test. Unauthorized access is illegal.

---

## 🎯 Features

### Core Red Team Capabilities
*   **Active Exploitation & PoE:** Automatically proves vulnerabilities by extracting data (e.g., reading `/etc/passwd` via LFI, executing commands via RCE).
*   **Attack Chain Engine:** Intelligently chains findings into kill-chain scenarios (e.g., *LFI → Extract Credentials → Login → Admin Access*).
*   **Intelligence Validation Engine:** Multi-stage validation protocol that filters false positives, detects honeypots/canary tokens, and assigns confidence scores.
*   **Logic Flaw Detection:** Multi-threaded race condition testing to bypass business logic limits.
*   **Self-Protection System (Optional):** Operational security features including proxy rotation, User-Agent spoofing, timing jitter, and circuit breakers to evade defensive controls.
*   **Protocol-Level Attacks:** HTTP request smuggling, WebSocket abuse, and JWT authentication bypass.

### 34+ Integrated Modules
1.  **Async HTTP Scanning:** High-speed parallel execution via `aiohttp`.
2.  **Technology Fingerprinting:** Auto-detects CMS, frameworks, servers, and versions.
3.  **Form Auto-Discovery:** Identifies login forms and tests for injection points.
4.  **Security Headers Analysis:** Validates HSTS, CSP, X-Frame-Options, etc.
5.  **Progress Tracking:** Real-time feedback via `tqdm`.
6.  **YAML Configuration:** Fully customizable scan profiles and wordlists.
7.  **Multi-Format Reporting:** Detailed HTML, JSON, and Markdown reports with context tracking.
8.  **SSL/TLS Analysis:** Certificate inspection and weak protocol detection.
9.  **Subdomain Enumeration:** Passive discovery via `subfinder` + active brute-force.
10. **CVE Database Integration:** NVD API lookups for known vulnerabilities.
11. **Tool Benchmarking:** Compare scanner effectiveness against baselines.
12. **False Positive Analysis:** Confidence scoring and cross-referencing.
13. **Performance Metrics:** Real-time speed and resource utilization tracking.
14. **Resume Functionality:** Pick up interrupted scans seamlessly.
15. **WAF Detection & Bypass:** Identifies WAFs and crafts specific bypass payloads.
16. **API Endpoint Testing:** Discovery for REST, GraphQL, and Swagger endpoints.
17. **Enhanced SQLMap:** Deep SQLi testing with automated tamper scripts.
18. **Nuclei Integration:** 13,000+ specialized vulnerability templates.
19. **Hashcat Analysis:** Automated password hash cracking from extracted dumps.
20. **Race Condition Attacks:** Concurrent request testing for TOCTOU flaws.
21. **JWT Authentication Bypass:** Tests for None algorithm and weak secrets.
22. **Advanced XSS:** Mutation XSS, CSP bypass, and DOM-based detection.
23. **Advanced Evasion:** Unicode normalization, double encoding, and HPP.
24. **Protocol Smuggling:** Raw socket testing for HTTP desync attacks.
25. **Credential Stuffing:** Automated login attempts with discovered credentials.
26. **Hidden Parameter Discovery:** Finds unlinked parameters via `paramminer`.
27. **Historical URL Recovery:** Uncovers forgotten endpoints via `gau`.
28. **Fast Web Fuzzing:** High-speed directory brute-forcing via `ffuf`.
29. **HTTP Probing:** Technology detection and status checking via `httpx`.
30. **XSS Verification:** Specialized XSS scanning via `dalfox`.
31. **Network Reconnaissance:** Port scanning and service versioning via `nmap`.
32. **Web Server Scanning:** Vulnerability detection via `nikto`.
33. **Passive Subdomain Discovery:** API-based enumeration via `subfinder`.
34. **Intelligence Engine:** Honeypot detection and finding validation.

### External Toolchain
*   **SQLMap:** Advanced SQL injection exploitation.
*   **Nuclei:** Template-based vulnerability scanning.
*   **Hashcat:** Password hash cracking.
*   **Nmap:** Network reconnaissance.
*   **Nikto:** Web server vulnerability scanning.
*   **Hydra:** Brute-force authentication testing.
*   **ffuf:** Fast web fuzzer.
*   **httpx:** HTTP probing toolkit.
*   **dalfox:** XSS scanner.
*   **gau:** Historical URL finder.
*   **subfinder:** Passive subdomain enumerator.
*   **paramminer:** Hidden parameter discovery.

### Comprehensive SecLists Integration
Automated utilization of verified SecLists wordlists for:
*   Directory discovery & Subdomain enumeration
*   XSS, SQLi, LFI/RFI, and Command Injection payloads
*   Credential (password/username) testing
*   Parameter fuzzing

---

## 📋 Requirements

### Python Environment
Ensure you have Python 3.9+ installed. Install the necessary dependencies via pip:

```bash
pip install aiohttp beautifulsoup4 tqdm pyyaml requests colorama jinja2 lxml websocket-client
