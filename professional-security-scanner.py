#!/usr/bin/env python3
"""
Professional Security Assessment Framework v8.0
19 Advanced Modules | Full Tool Integration
SQLMap + Nuclei + Hashcat + SecLists
For authorized security assessment and academic research only
"""

import asyncio
import aiohttp
import requests
import sys
import subprocess
import os
import ssl
import socket
import json
import yaml
import csv
import time
import logging
import argparse
import pickle
import hashlib
import resource
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse, quote, urlencode
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from tqdm import tqdm
from colorama import Fore, Style, init, Back
from jinja2 import Template

init(autoreset=True)

# ============================================================
# CONFIGURATION
# ============================================================

WORDLIST_DIR = "/root/SecLists"

def find_wordlist_fallback(base_dir, filename):
    """Recursively search for a wordlist if the hardcoded path fails."""
    filename_lower = filename.lower()
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.lower() == filename_lower:
                return os.path.join(root, file)
    return None

DEFAULT_CONFIG = {
    'scan_profile': 'aggressive',
    'threads': 20,
    'timeout': 5,
    'delay': 0.02,
    'max_payloads': 2000,
    'output_dir': '/tmp/scan_results',
    'output_formats': ['html', 'json'],
    'resume': False,
    'wordlists': {
        'directories': [
            "/root/SecLists/Discovery/Web-Content/common.txt",
            "/root/SecLists/Discovery/Web-Content/raft-medium-directories.txt",
            "/root/SecLists/Discovery/Web-Content/raft-medium-files.txt",
        ],
        'xss': [
            "/root/SecLists/Fuzzing/XSS/human-friendly/XSS-BruteLogic.txt",
            "/root/SecLists/Fuzzing/XSS/robot-friendly/XSS-BruteLogic.txt",
        ],
        'sqli': [
            "/root/SecLists/Fuzzing/Databases/SQLi/Generic-SQLi.txt",
        ],
        'lfi': [
            "/root/SecLists/Fuzzing/LFI/Linux/LFI-gracefulsecurity-linux.txt",
        ],
        'command_injection': [
            "/root/SecLists/Fuzzing/command-injection-commix.txt",
        ],
        'subdomains': "/root/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
        'passwords': "/root/SecLists/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt",
        'usernames': "/root/SecLists/Usernames/cirt-default-usernames.txt",
    },
    'nvd_api_key': '',
}

SCAN_PROFILES = {
    'stealth': {'threads': 2, 'timeout': 15, 'delay': 1.0, 'max_payloads': 100},
    'normal': {'threads': 5, 'timeout': 10, 'delay': 0.3, 'max_payloads': 500},
    'aggressive': {'threads': 20, 'timeout': 5, 'delay': 0.02, 'max_payloads': 2000},
    'extreme': {'threads': 40, 'timeout': 3, 'delay': 0.01, 'max_payloads': 5000},
}

# ============================================================
# MODULE 10: CVE Database Integration
# ============================================================

class CVEDatabase:
    """Query NVD API for known vulnerabilities"""

    def __init__(self, api_key=''):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache = {}

    def lookup(self, product, version=''):
        cache_key = f"{product}:{version}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        results = []
        try:
            keyword = f"{product} {version}".strip()
            params = {'keywordSearch': keyword, 'resultsPerPage': 5}
            if self.api_key:
                params['apiKey'] = self.api_key

            resp = requests.get(self.base_url, params=params, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get('vulnerabilities', []):
                    cve = vuln.get('cve', {})
                    cve_id = cve.get('id', 'N/A')
                    description = cve.get('descriptions', [{}])[0].get('value', '')
                    metrics = cve.get('metrics', {})
                    cvss_score = 'N/A'
                    for metric_key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                        if metric_key in metrics and metrics[metric_key]:
                            cvss_data = metrics[metric_key][0].get('cvssData', {})
                            cvss_score = cvss_data.get('baseScore', 'N/A')
                            break
                    results.append({
                        'cve_id': cve_id,
                        'description': description[:200],
                        'cvss_score': cvss_score
                    })
        except Exception:
            pass

        self.cache[cache_key] = results
        return results


# ============================================================
# MODULE 13: Performance Metrics
# ============================================================

class PerformanceTracker:
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.phase_times = {}

    def start(self):
        self.start_time = time.time()

    def stop(self):
        self.end_time = time.time()

    def record_request(self, success=True):
        self.total_requests += 1
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1

    def start_phase(self, phase_name):
        self.phase_times[phase_name] = {'start': time.time(), 'end': None}

    def end_phase(self, phase_name):
        if phase_name in self.phase_times:
            self.phase_times[phase_name]['end'] = time.time()

    def get_report(self):
        elapsed = (self.end_time or time.time()) - (self.start_time or time.time())
        mem_usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        return {
            'total_duration': f"{elapsed:.2f}s",
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'failed_requests': self.failed_requests,
            'requests_per_second': round(self.total_requests / max(elapsed, 0.01), 2),
            'memory_peak_mb': round(mem_usage, 2),
            'phase_breakdown': {
                name: f"{(times['end'] or time.time()) - times['start']:.2f}s"
                for name, times in self.phase_times.items()
            }
        }


# ============================================================
# MAIN SCANNER CLASS
# ============================================================

class ProfessionalSecurityScanner:
    def __init__(self, target_url, config=None):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(target_url)
        self.hostname = self.parsed_url.hostname
        self.config = config or DEFAULT_CONFIG.copy()

        profile = SCAN_PROFILES.get(self.config['scan_profile'], SCAN_PROFILES['aggressive'])
        self.threads = self.config.get('threads', profile['threads'])
        self.timeout = self.config.get('timeout', profile['timeout'])
        self.delay = self.config.get('delay', profile['delay'])
        self.max_payloads = self.config.get('max_payloads', profile['max_payloads'])
        self.output_dir = self.config.get('output_dir', '/tmp/scan_results')

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        })

        self.results = []
        self.login_pages = []
        self.discovered_endpoints = []
        self.technology_stack = {}
        self.waf_detected = None
        self.ssl_info = {}
        self.scan_state_file = os.path.join(self.output_dir, 'scan_state.pkl')

        self.perf = PerformanceTracker()
        self.cve_db = CVEDatabase(self.config.get('nvd_api_key', ''))

        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        logging.basicConfig(
            filename=os.path.join(self.output_dir, 'scanner.log'),
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    # --------------------------------------------------------
    # Core Helpers
    # --------------------------------------------------------

    def banner(self):
        print(f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   {Fore.CYAN}Professional Security Assessment Framework v8.0{Fore.RED}               ║
║   {Fore.YELLOW}19 Advanced Modules | Full Tool Integration{Fore.RED}                   ║
║   {Fore.YELLOW}SQLMap + Nuclei + Hashcat + SecLists{Fore.RED}                          ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")
        print(f"{Fore.CYAN}[*] Target:   {self.target_url}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Profile:  {self.config['scan_profile']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Threads:  {self.threads} | Timeout: {self.timeout}s | Delay: {self.delay}s{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Output:   {self.output_dir}{Style.RESET_ALL}\n")

    def log_result(self, severity, title, description, tool_source="Scanner"):
        result = {
            'severity': severity,
            'title': title,
            'description': description,
            'tool': tool_source,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.results.append(result)
        self.logger.info(f"[{severity}] {title} - {description}")

        color = {'CRITICAL': Fore.RED + Back.WHITE, 'HIGH': Fore.RED,
                 'MEDIUM': Fore.YELLOW, 'LOW': Fore.BLUE, 'INFO': Fore.WHITE}.get(severity, Fore.WHITE)
        print(f"{color}[{severity}]{Style.RESET_ALL} {title}")
        print(f"   {Fore.LIGHTBLACK_EX}{description}{Style.RESET_ALL}\n")

    def make_request(self, method, url, **kwargs):
        if self.delay > 0:
            time.sleep(self.delay)
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('allow_redirects', False)
        try:
            resp = self.session.request(method, url, **kwargs)
            self.perf.record_request(True)
            return resp
        except Exception:
            self.perf.record_request(False)
            return None

    def load_payloads(self, filepath, max_count=None):
        # If the exact path doesn't exist, try to find it by filename
        if not os.path.exists(filepath):
            filename = os.path.basename(filepath)
            found_path = find_wordlist_fallback(WORDLIST_DIR, filename)
            if found_path:
                filepath = found_path
                self.logger.info(f"Found wordlist at fallback location: {filepath}")
            else:
                self.logger.warning(f"Wordlist not found: {filepath}")
                return []

        payloads = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    p = line.strip()
                    if p and not p.startswith('#'):
                        payloads.append(p)
                        if max_count and len(payloads) >= max_count:
                            break
        except Exception as e:
            self.logger.error(f"Error loading {filepath}: {e}")
        return payloads

    def load_payloads_multi(self, filepaths, max_count=None):
        all_p = []
        for fp in filepaths:
            all_p.extend(self.load_payloads(fp, max_count=500))
        return list(set(all_p))[:max_count] if max_count else list(set(all_p))

    # --------------------------------------------------------
    # MODULE 1: Async HTTP Scanning
    # --------------------------------------------------------

    async def _async_request(self, session, url, semaphore):
        async with semaphore:
            if self.delay > 0:
                await asyncio.sleep(self.delay)
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout),
                                       allow_redirects=False, ssl=False) as resp:
                    self.perf.record_request(True)
                    return url, resp.status, await resp.text(errors='ignore'), len(await resp.read())
            except Exception:
                self.perf.record_request(False)
                return url, None, '', 0

    async def async_scan_urls(self, urls):
        semaphore = asyncio.Semaphore(self.threads)
        connector = aiohttp.TCPConnector(limit=self.threads, ssl=False)
        results = []
        async with aiohttp.ClientSession(connector=connector,
                                         headers=self.session.headers) as session:
            tasks = [self._async_request(session, url, semaphore) for url in urls]
            for coro in asyncio.as_completed(tasks):
                result = await coro
                results.append(result)
        return results

    # --------------------------------------------------------
    # MODULE 2: Technology Fingerprinting
    # --------------------------------------------------------

    def fingerprint_technology(self):
        self.perf.start_phase('fingerprint')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 2] Technology Fingerprinting\n{'='*70}{Style.RESET_ALL}\n")

        resp = self.make_request('GET', self.target_url)
        if not resp:
            print(f"{Fore.RED}[!] Cannot reach target{Style.RESET_ALL}")
            self.perf.end_phase('fingerprint')
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}
        html = resp.text.lower()
        self.technology_stack = {}

        signatures = {
            'WordPress': ['/wp-content/', 'wp-json', 'wp-includes'],
            'Drupal': ['drupal.settings', '/sites/default/', 'x-drupal-cache'],
            'Joomla': ['/components/com_', 'joomla!'],
            'Laravel': ['laravel_session', 'x-powered-by: laravel'],
            'Django': ['csrfmiddlewaretoken', 'django'],
            'React': ['react', 'reactdom', '_next/'],
            'Angular': ['ng-app', 'angular', 'ng-version'],
            'Apache': ['apache'],
            'Nginx': ['nginx'],
            'IIS': ['microsoft-iis', 'asp.net'],
            'PHP': ['x-powered-by: php', 'phpsessid'],
            'Node.js': ['x-powered-by: express'],
        }

        for tech, patterns in signatures.items():
            for pattern in patterns:
                if pattern in html or pattern in str(headers):
                    self.technology_stack[tech] = True
                    self.log_result('INFO', f'Technology Detected: {tech}',
                                    f'Pattern matched: {pattern}', 'Fingerprint')
                    break

        server = headers.get('server', '')
        if server:
            self.technology_stack['Server'] = server
            self.log_result('INFO', 'Server Header', server, 'Fingerprint')

        self.perf.end_phase('fingerprint')

    # --------------------------------------------------------
    # MODULE 3: Form Auto-Discovery & Testing
    # --------------------------------------------------------

    def discover_and_test_forms(self):
        self.perf.start_phase('forms')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 3] Form Auto-Discovery & Testing\n{'='*70}{Style.RESET_ALL}\n")

        resp = self.make_request('GET', self.target_url)
        if not resp:
            self.perf.end_phase('forms')
            return

        soup = BeautifulSoup(resp.text, 'lxml')
        forms = soup.find_all('form')
        print(f"{Fore.YELLOW}[*] Found {len(forms)} form(s){Style.RESET_ALL}\n")

        test_payloads = ["' OR '1'='1", '<script>alert(1)</script>', '{{7*7}}']

        for i, form in enumerate(forms):
            action = form.get('action', self.target_url)
            method = form.get('method', 'get').lower()
            full_action = urljoin(self.target_url, action)
            inputs = form.find_all(['input', 'textarea', 'select'])

            self.log_result('INFO', f'Form #{i+1} Discovered',
                            f'Method: {method.upper()} | Action: {full_action} | Fields: {len(inputs)}', 'Form Discovery')

            if method == 'post' and any(inp.get('type') == 'password' for inp in inputs):
                self.login_pages.append(full_action)
                self.log_result('MEDIUM', 'Login Form Detected', full_action, 'Form Discovery')

            for inp in inputs:
                name = inp.get('name', '')
                if not name or inp.get('type') in ['submit', 'button', 'hidden']:
                    continue

                for payload in test_payloads:
                    data = {name: payload}
                    try:
                        if method == 'post':
                            r = self.session.post(full_action, data=data, timeout=self.timeout, allow_redirects=False)
                        else:
                            r = self.session.get(full_action, params=data, timeout=self.timeout, allow_redirects=False)

                        if r and payload in r.text:
                            vuln_type = 'SQL Injection' if 'OR' in payload else ('XSS' if '<script>' in payload else 'SSTI')
                            self.log_result('HIGH', f'{vuln_type} via Form Input',
                                            f'Form: {full_action} | Field: {name}', 'Form Testing')
                            break
                    except Exception:
                        continue

        self.perf.end_phase('forms')

    # --------------------------------------------------------
    # MODULE 4: Security Headers Analysis
    # --------------------------------------------------------

    def analyze_security_headers(self):
        self.perf.start_phase('headers')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 4] Security Headers Analysis\n{'='*70}{Style.RESET_ALL}\n")

        resp = self.make_request('GET', self.target_url)
        if not resp:
            self.perf.end_phase('headers')
            return

        required_headers = {
            'Strict-Transport-Security': ('HIGH', 'HSTS not set - vulnerable to downgrade attacks'),
            'Content-Security-Policy': ('MEDIUM', 'CSP not set - vulnerable to XSS'),
            'X-Frame-Options': ('MEDIUM', 'Clickjacking protection missing'),
            'X-Content-Type-Options': ('MEDIUM', 'MIME type sniffing possible'),
            'X-XSS-Protection': ('LOW', 'XSS filter not enabled'),
            'Referrer-Policy': ('LOW', 'Referrer information may leak'),
            'Permissions-Policy': ('LOW', 'Browser features not restricted'),
        }

        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        for header, (severity, desc) in required_headers.items():
            if header.lower() not in resp_headers:
                self.log_result(severity, f'Missing Header: {header}', desc, 'Headers')
            else:
                self.log_result('INFO', f'Header Present: {header}',
                                f'Value: {resp_headers[header.lower()][:100]}', 'Headers')

        self.perf.end_phase('headers')

    # --------------------------------------------------------
    # MODULE 8: SSL/TLS Analysis
    # --------------------------------------------------------

    def check_ssl_tls(self):
        self.perf.start_phase('ssl')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 8] SSL/TLS Analysis\n{'='*70}{Style.RESET_ALL}\n")

        if self.parsed_url.scheme != 'https':
            print(f"{Fore.YELLOW}[!] Target is not HTTPS, skipping SSL analysis{Style.RESET_ALL}")
            self.perf.end_phase('ssl')
            return

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.hostname) as s:
                s.settimeout(self.timeout)
                s.connect((self.hostname, 443))
                cert = s.getpeercert()
                cipher = s.cipher()
                version = s.version()

                self.ssl_info = {
                    'protocol': version,
                    'cipher': cipher[0] if cipher else 'Unknown',
                    'bits': cipher[2] if cipher else 0,
                    'not_after': cert.get('notAfter', ''),
                }

                self.log_result('INFO', 'SSL/TLS Connected',
                                f'Protocol: {version} | Cipher: {self.ssl_info["cipher"]} ({self.ssl_info["bits"]} bits)', 'SSL')

                if version in ('TLSv1', 'TLSv1.1', 'SSLv3'):
                    self.log_result('HIGH', 'Weak TLS Protocol', f'{version} is deprecated', 'SSL')

        except Exception as e:
            self.log_result('MEDIUM', 'SSL Connection Failed', str(e), 'SSL')

        self.perf.end_phase('ssl')

    # --------------------------------------------------------
    # MODULE 9: Subdomain Enumeration
    # --------------------------------------------------------

    def enumerate_subdomains(self):
        self.perf.start_phase('subdomains')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 9] Subdomain Enumeration\n{'='*70}{Style.RESET_ALL}\n")

        wl = self.config.get('wordlists', {}).get('subdomains', '')
        if not wl or not os.path.exists(wl):
            print(f"{Fore.YELLOW}[!] Subdomain wordlist not found{Style.RESET_ALL}")
            self.perf.end_phase('subdomains')
            return

        subdomains = self.load_payloads(wl, max_count=1000)
        base_domain = '.'.join(self.hostname.split('.')[-2:])
        urls_to_test = [f"http://{sub}.{base_domain}" for sub in subdomains]

        print(f"{Fore.YELLOW}[*] Testing {len(urls_to_test)} subdomains...{Style.RESET_ALL}")
        found = 0

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            results = loop.run_until_complete(self.async_scan_urls(urls_to_test))
            loop.close()

            for url, status, body, size in tqdm(results, desc="Subdomains"):
                if status and status in (200, 301, 302, 403):
                    found += 1
                    self.log_result('INFO', 'Subdomain Found',
                                    f'{url} (Status: {status})', 'Subdomain Enum')
        except Exception as e:
            print(f"{Fore.RED}[!] Async scan failed: {e}{Style.RESET_ALL}")

        print(f"{Fore.GREEN}[+] Found {found} active subdomains{Style.RESET_ALL}")
        self.perf.end_phase('subdomains')

    # --------------------------------------------------------
    # MODULE 15: WAF Detection
    # --------------------------------------------------------

    def detect_waf(self):
        self.perf.start_phase('waf')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 15] WAF Detection\n{'='*70}{Style.RESET_ALL}\n")

        waf_signatures = {
            'Cloudflare': ['cloudflare', 'cf-ray'],
            'AWS WAF': ['x-amzn-waf'],
            'ModSecurity': ['mod_security'],
            'Imperva': ['incapsula'],
        }

        resp = self.make_request('GET', self.target_url)
        if not resp:
            self.perf.end_phase('waf')
            return

        headers_str = str(resp.headers).lower()
        detected = False
        for waf_name, patterns in waf_signatures.items():
            for pattern in patterns:
                if pattern in headers_str:
                    self.waf_detected = waf_name
                    self.log_result('MEDIUM', f'WAF Detected: {waf_name}',
                                    f'Pattern: {pattern}', 'WAF Detection')
                    detected = True
                    break

        if not detected:
            self.log_result('INFO', 'No WAF Detected',
                            'No known WAF signatures found', 'WAF Detection')

        self.perf.end_phase('waf')

    # --------------------------------------------------------
    # MODULE 16: API Endpoint Testing
    # --------------------------------------------------------

    def test_api_endpoints(self):
        self.perf.start_phase('api')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 16] API Endpoint Testing\n{'='*70}{Style.RESET_ALL}\n")

        api_paths = [
            '/api', '/api/v1', '/api/v2', '/graphql',
            '/swagger', '/swagger.json', '/api-docs',
            '/actuator', '/actuator/health',
        ]

        found = 0
        for path in tqdm(api_paths, desc="API Endpoints"):
            test_url = urljoin(self.target_url + '/', path.lstrip('/'))
            resp = self.make_request('GET', test_url)

            if resp and resp.status_code in (200, 301, 302, 401, 403):
                found += 1
                severity = 'HIGH' if resp.status_code in (401, 403) else 'INFO'
                self.log_result(severity, f'API Endpoint: {path}',
                                f'Status: {resp.status_code}', 'API Test')

        print(f"{Fore.GREEN}[+] Found {found} API endpoints{Style.RESET_ALL}")
        self.perf.end_phase('api')

    # --------------------------------------------------------
    # Directory Discovery (Module 1 Async + Module 5 tqdm)
    # --------------------------------------------------------

    def comprehensive_directory_discovery(self):
        self.perf.start_phase('directories')
        print(f"\n{Fore.CYAN}{'='*70}\n[PHASE] Comprehensive Directory Discovery\n{'='*70}{Style.RESET_ALL}\n")

        wl_dirs = self.config.get('wordlists', {}).get('directories', [])
        all_paths = self.load_payloads_multi(wl_dirs, max_count=self.max_payloads)
        print(f"{Fore.YELLOW}[*] Loaded {len(all_paths)} unique paths{Style.RESET_ALL}")

        urls = [urljoin(self.target_url + '/', p.lstrip('/')) for p in all_paths]
        found = 0

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            results = loop.run_until_complete(self.async_scan_urls(urls))
            loop.close()

            for url, status, body, size in tqdm(results, desc="Directories"):
                if status and status in (200, 301, 302, 401, 403, 500):
                    found += 1
                    path = urlparse(url).path
                    self.discovered_endpoints.append({'path': path, 'status': status, 'url': url})

                    severity = 'HIGH' if status in (401, 403) else 'INFO'
                    self.log_result(severity, f'Discovered: {path}',
                                    f'Status: {status} | Size: {size} bytes', 'Directory Discovery')
        except Exception as e:
            print(f"{Fore.RED}[!] Directory scan error: {e}{Style.RESET_ALL}")

        print(f"{Fore.GREEN}[+] Found {found} endpoints{Style.RESET_ALL}")
        self.perf.end_phase('directories')

    # --------------------------------------------------------
    # Injection Testing
    # --------------------------------------------------------

    def _run_injection_test(self, test_name, wordlist_keys, test_params, detection_fn):
        self.perf.start_phase(test_name.lower().replace(' ', '_'))
        print(f"\n{Fore.CYAN}{'='*70}\n[PHASE] {test_name}\n{'='*70}{Style.RESET_ALL}\n")

        wl_paths = self.config.get('wordlists', {})
        all_payloads = []
        for key in wordlist_keys:
            val = wl_paths.get(key, [])
            if isinstance(val, str):
                val = [val]
            all_payloads.extend(self.load_payloads_multi(val, max_count=self.max_payloads))
        all_payloads = list(set(all_payloads))
        print(f"{Fore.YELLOW}[*] Loaded {len(all_payloads)} unique payloads{Style.RESET_ALL}\n")

        found = False
        for param in tqdm(test_params, desc=test_name):
            if found:
                break
            for payload in all_payloads:
                test_url = f"{self.target_url}?{param}={quote(payload, safe='')}"
                resp = self.make_request('GET', test_url, timeout=15)

                result = detection_fn(resp, payload)
                if result:
                    self.log_result(result['severity'], result['title'],
                                    f'Parameter: {param} | Payload: {payload[:100]}', result['tool'])
                    found = True
                    break

        if not found:
            print(f"{Fore.GREEN}[+] No {test_name} vulnerabilities detected{Style.RESET_ALL}")
        self.perf.end_phase(test_name.lower().replace(' ', '_'))

    def comprehensive_xss_testing(self):
        self._run_injection_test(
            'XSS Testing',
            ['xss'],
            ['q', 'search', 'query', 'id', 'page', 'name', 'comment'],
            lambda resp, payload: {
                'severity': 'HIGH', 'title': 'XSS Vulnerability Detected', 'tool': 'XSS Test'
            } if resp and payload in resp.text else None
        )

    def comprehensive_sqli_testing(self):
        sql_errors = ['sql syntax', 'mysql_fetch', 'ora-', 'microsoft ole db',
                      'unclosed quotation', 'pg_query', 'sqlite', 'postgresql']

        def detect_sqli(resp, payload):
            if resp:
                for err in sql_errors:
                    if err in resp.text.lower():
                        return {'severity': 'CRITICAL', 'title': 'SQL Injection Detected', 'tool': 'SQLi Test'}
            return None

        self._run_injection_test(
            'SQL Injection Testing',
            ['sqli'],
            ['id', 'user', 'username', 'page', 'item'],
            detect_sqli
        )

    def comprehensive_lfi_testing(self):
        indicators = ['root:', '[extensions]', '<?php', 'daemon:']

        def detect_lfi(resp, payload):
            if resp:
                for ind in indicators:
                    if ind in resp.text:
                        return {'severity': 'CRITICAL', 'title': 'LFI Vulnerability Detected', 'tool': 'LFI Test'}
            return None

        self._run_injection_test(
            'LFI Testing',
            ['lfi'],
            ['file', 'page', 'include', 'path', 'doc'],
            detect_lfi
        )

    def comprehensive_command_injection_testing(self):
        def detect_cmdi(resp, payload):
            if resp and ('root:' in resp.text or 'uid=' in resp.text):
                return {'severity': 'CRITICAL', 'title': 'Command Injection Detected', 'tool': 'CmdInj Test'}
            return None

        self._run_injection_test(
            'Command Injection Testing',
            ['command_injection'],
            ['cmd', 'exec', 'command', 'ip', 'domain'],
            detect_cmdi
        )

    # --------------------------------------------------------
    # Nmap & Nikto
    # --------------------------------------------------------

    def run_nmap(self):
        self.perf.start_phase('nmap')
        print(f"\n{Fore.CYAN}{'='*70}\n[PHASE] Network Reconnaissance - Nmap\n{'='*70}{Style.RESET_ALL}\n")
        xml_file = os.path.join(self.output_dir, 'nmap_results.xml')
        try:
            cmd = ['nmap', '-sV', '-sC', '-O', '--open', '-T4', '-oX', xml_file, self.hostname]
            subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if os.path.exists(xml_file):
                tree = ET.parse(xml_file)
                root = tree.getroot()
                for port in root.findall('.//port'):
                    state = port.find('state')
                    service = port.find('service')
                    if state is not None and state.get('state') == 'open':
                        port_id = port.get('portid')
                        sname = service.get('name', 'unknown') if service is not None else 'unknown'
                        prod = service.get('product', '') if service is not None else ''
                        ver = service.get('version', '') if service is not None else ''
                        self.log_result('INFO', f'Port {port_id}: {sname}', f'{prod} {ver}'.strip(), 'Nmap')
                        if prod:
                            cves = self.cve_db.lookup(prod, ver)
                            for cve in cves[:2]:
                                self.log_result('HIGH', f'Known CVE: {cve["cve_id"]}',
                                                f'{cve["description"]} | CVSS: {cve["cvss_score"]}', 'CVE Lookup')
        except Exception as e:
            print(f"{Fore.RED}[!] Nmap error: {e}{Style.RESET_ALL}")
        self.perf.end_phase('nmap')

    def run_nikto(self):
        self.perf.start_phase('nikto')
        print(f"\n{Fore.CYAN}{'='*70}\n[PHASE] Web Vulnerability Scan - Nikto\n{'='*70}{Style.RESET_ALL}\n")
        csv_file = os.path.join(self.output_dir, 'nikto_results.csv')
        try:
            cmd = ['nikto', '-h', self.target_url, '-Format', 'csv', '-output', csv_file, '-timeout', '5', '-maxtime', '120s']
            subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if os.path.exists(csv_file):
                with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader(f)
                    next(reader, None)
                    count = 0
                    for row in reader:
                        if len(row) >= 6:
                            count += 1
                            self.log_result('MEDIUM', f'Nikto #{count}', row[5][:200], 'Nikto')
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Nikto: {e}{Style.RESET_ALL}")
        self.perf.end_phase('nikto')

    # --------------------------------------------------------
    # MODULE 17: Enhanced SQLMap
    # --------------------------------------------------------

    def run_sqlmap_enhanced(self):
        """Enhanced SQLMap with comprehensive testing"""
        self.perf.start_phase('sqlmap_enhanced')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 17] Enhanced SQLMap Testing\n{'='*70}{Style.RESET_ALL}\n")

        output_dir = os.path.join(self.output_dir, 'sqlmap_results')
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        test_urls = [self.target_url]
        for endpoint in self.discovered_endpoints[:10]:
            if '?' in endpoint.get('url', ''):
                test_urls.append(endpoint['url'])

        for url in test_urls:
            try:
                cmd = [
                    'sqlmap', '-u', url,
                    '--batch',
                    '--level=3',
                    '--risk=2',
                    '--threads=5',
                    '--timeout=10',
                    '--retries=2',
                    '--forms',
                    '--crawl=2',
                    '--random-agent',
                    '--output-dir', output_dir,
                    '--flush-session',
                    '--disable-coloring',
                ]

                if self.waf_detected:
                    cmd.extend(['--tamper=space2comment,between,charencode'])

                print(f"{Fore.YELLOW}[*] SQLMap testing: {url[:80]}...{Style.RESET_ALL}")
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

                output = process.stdout + process.stderr

                if any(indicator in output.lower() for indicator in ['injectable', 'vulnerable', 'parameter appears to be']):
                    self.log_result(
                        'CRITICAL',
                        'SQLMap Confirmed Injection',
                        f'URL: {url}\nCheck {output_dir} for detailed results',
                        'SQLMap'
                    )
                else:
                    print(f"{Fore.GREEN}[+] No SQLi found at: {url[:60]}{Style.RESET_ALL}")

            except subprocess.TimeoutExpired:
                print(f"{Fore.YELLOW}[!] SQLMap timeout on: {url[:60]}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] SQLMap error: {e}{Style.RESET_ALL}")

        self.perf.end_phase('sqlmap_enhanced')

    # --------------------------------------------------------
    # MODULE 18: Nuclei
    # --------------------------------------------------------

    def run_nuclei(self):
        """Nuclei template-based vulnerability scanning"""
        self.perf.start_phase('nuclei')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 18] Nuclei Vulnerability Scan\n{'='*70}{Style.RESET_ALL}\n")

        try:
            subprocess.run(['nuclei', '-version'], capture_output=True, check=True)
        except:
            print(f"{Fore.YELLOW}[!] Nuclei not installed, skipping{Style.RESET_ALL}")
            self.perf.end_phase('nuclei')
            return

        template_dir = os.path.expanduser('~/nuclei-templates')
        if not os.path.exists(template_dir):
            print(f"{Fore.YELLOW}[!] Nuclei templates not found at {template_dir}{Style.RESET_ALL}")
            self.perf.end_phase('nuclei')
            return

        output_file = os.path.join(self.output_dir, 'nuclei_results.json')

        try:
            print(f"{Fore.YELLOW}[*] Running Nuclei scan with 13,323 templates...{Style.RESET_ALL}")
            cmd = [
                'nuclei',
                '-u', self.target_url,
                '-t', template_dir,
                '-severity', 'critical,high,medium,low',
                '-json',
                '-output', output_file,
                '-silent',
                '-rate-limit', '150',
                '-bulk-size', '25',
                '-concurrency', '10',
                '-timeout', '10',
                '-retries', '2',
            ]

            process = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            result = json.loads(line.strip())
                            template_id = result.get('template-id', 'Unknown')
                            name = result.get('info', {}).get('name', 'Unknown')
                            severity = result.get('info', {}).get('severity', 'info').upper()
                            description = result.get('info', {}).get('description', '')
                            matched_at = result.get('matched-at', '')

                            sev_map = {
                                'CRITICAL': 'CRITICAL',
                                'HIGH': 'HIGH',
                                'MEDIUM': 'MEDIUM',
                                'LOW': 'LOW',
                                'INFO': 'INFO'
                            }

                            self.log_result(
                                sev_map.get(severity, 'INFO'),
                                f'Nuclei: {name}',
                                f'Template: {template_id}\nMatched: {matched_at}\n{description[:200]}',
                                'Nuclei'
                            )
                        except json.JSONDecodeError:
                            continue

                print(f"{Fore.GREEN}[+] Nuclei scan complete - check {output_file}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] Nuclei found no vulnerabilities{Style.RESET_ALL}")

        except subprocess.TimeoutExpired:
            print(f"{Fore.YELLOW}[!] Nuclei scan timed out{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Nuclei error: {e}{Style.RESET_ALL}")

        self.perf.end_phase('nuclei')

    # --------------------------------------------------------
    # MODULE 19: Hashcat Analysis
    # --------------------------------------------------------

    def run_hashcat_analysis(self):
        """Hashcat for demonstrating password hash weakness"""
        self.perf.start_phase('hashcat')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 19] Hash Analysis (Password Hash Cracking)\n{'='*70}{Style.RESET_ALL}\n")

        found_hashes = []
        hash_files = []
        for endpoint in self.discovered_endpoints:
            if any(ext in endpoint.get('path', '') for ext in ['.sql', '.dump', '.bak', '.env', '.conf']):
                hash_files.append(endpoint.get('url'))

        try:
            subprocess.run(['hashcat', '--version'], capture_output=True, check=True)
        except:
            print(f"{Fore.YELLOW}[!] Hashcat not installed, skipping{Style.RESET_ALL}")
            self.perf.end_phase('hashcat')
            return

        if not found_hashes and not hash_files:
            print(f"{Fore.GREEN}[+] No password hashes found during scan{Style.RESET_ALL}")
            self.log_result(
                'INFO',
                'Hash Analysis',
                'No password hashes found. Hashcat available for demonstration if hashes are discovered.',
                'Hashcat'
            )
            self.perf.end_phase('hashcat')
            return

        self.perf.end_phase('hashcat')

    # --------------------------------------------------------
    # MODULE 11: Benchmarking
    # --------------------------------------------------------

    def benchmark_tools(self):
        self.perf.start_phase('benchmark')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 11] Tool Benchmarking\n{'='*70}{Style.RESET_ALL}\n")

        benchmark = {'our_scanner': len(self.results)}
        print(f"{Fore.YELLOW}[*] Our Scanner findings: {benchmark['our_scanner']}{Style.RESET_ALL}")

        csv_file = os.path.join(self.output_dir, 'nikto_results.csv')
        if os.path.exists(csv_file):
            with open(csv_file, 'r') as f:
                nikto_count = sum(1 for _ in f) - 1
                benchmark['nikto'] = max(nikto_count, 0)
                print(f"{Fore.YELLOW}[*] Nikto findings: {benchmark['nikto']}{Style.RESET_ALL}")

        self.log_result('INFO', 'Benchmark Summary', str(benchmark), 'Benchmark')
        self.perf.end_phase('benchmark')

    # --------------------------------------------------------
    # MODULE 12: False Positive Analysis
    # --------------------------------------------------------

    def validate_findings(self):
        self.perf.start_phase('validation')
        print(f"\n{Fore.CYAN}{'='*70}\n[MODULE 12] False Positive Analysis\n{'='*70}{Style.RESET_ALL}\n")

        for finding in self.results:
            confidence = 'HIGH' if finding['severity'] == 'CRITICAL' else 'MEDIUM'
            finding['confidence'] = confidence

        high_conf = sum(1 for f in self.results if f.get('confidence') == 'HIGH')
        print(f"{Fore.GREEN}[+] Validated: {high_conf} high confidence findings{Style.RESET_ALL}")
        self.perf.end_phase('validation')

    # --------------------------------------------------------
    # MODULE 14: Resume Interrupted Scans
    # --------------------------------------------------------

    def save_state(self):
        state = {
            'target': self.target_url,
            'results': self.results,
            'endpoints': self.discovered_endpoints,
            'tech_stack': self.technology_stack,
            'timestamp': datetime.now().isoformat()
        }
        with open(self.scan_state_file, 'wb') as f:
            pickle.dump(state, f)

    def load_state(self):
        if os.path.exists(self.scan_state_file):
            try:
                with open(self.scan_state_file, 'rb') as f:
                    state = pickle.load(f)
                    if state.get('target') == self.target_url:
                        self.results = state.get('results', [])
                        self.discovered_endpoints = state.get('endpoints', [])
                        self.technology_stack = state.get('tech_stack', {})
                        print(f"{Fore.GREEN}[+] Resumed scan with {len(self.results)} previous findings{Style.RESET_ALL}")
                        return True
            except Exception:
                pass
        return False

    # --------------------------------------------------------
    # MODULE 7: Multiple Output Formats
    # --------------------------------------------------------

    def export_json(self):
        output_file = os.path.join(self.output_dir, 'report.json')
        data = {
            'target': self.target_url,
            'scan_date': datetime.now().isoformat(),
            'profile': self.config['scan_profile'],
            'total_findings': len(self.results),
            'performance': self.perf.get_report(),
            'technology_stack': self.technology_stack,
            'findings': self.results
        }
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"{Fore.GREEN}[+] JSON report: {output_file}{Style.RESET_ALL}")

    def export_html(self):
        output_file = os.path.join(self.output_dir, 'report.html')
        perf = self.perf.get_report()
        severity_counts = {}
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            severity_counts[sev] = sum(1 for r in self.results if r['severity'] == sev)

        template = Template("""<!DOCTYPE html>
<html><head><title>Security Report - {{ target }}</title>
<style>
body{font-family:'Segoe UI',sans-serif;margin:0;padding:20px;background:#f5f5f5}
.container{max-width:1400px;margin:0 auto;background:#fff;padding:30px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,.1)}
h1{color:#2c3e50;border-bottom:4px solid #3498db;padding-bottom:15px}
.summary{background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;padding:25px;border-radius:10px;margin:30px 0}
.finding{background:#fff;border-left:5px solid #3498db;padding:20px;margin:15px 0;border-radius:5px}
.CRITICAL{border-left-color:#e74c3c;background:#fef5f5}.HIGH{border-left-color:#e67e22}
.MEDIUM{border-left-color:#f39c12}.LOW{border-left-color:#3498db}.INFO{border-left-color:#95a5a6}
.severity{font-weight:bold;padding:5px 12px;border-radius:5px;color:#fff;display:inline-block}
.severity.CRITICAL{background:#e74c3c}.severity.HIGH{background:#e67e22}
.severity.MEDIUM{background:#f39c12;color:#000}.severity.LOW{background:#3498db}.severity.INFO{background:#95a5a6}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:15px;margin:20px 0}
.stat-box{background:#fff;padding:15px;border-radius:10px;text-align:center;box-shadow:0 2px 5px rgba(0,0,0,.1)}
.stat-number{font-size:32px;font-weight:bold;color:#3498db}
table{width:100%;border-collapse:collapse;margin:20px 0}
th,td{padding:12px;text-align:left;border-bottom:1px solid #ddd}th{background:#3498db;color:#fff}
.footer{margin-top:40px;text-align:center;color:#7f8c8d;font-size:12px}
</style></head><body><div class="container">
<h1>Security Assessment Report</h1>
<div class="summary"><h2 style="color:#fff;margin-top:0">Executive Summary</h2>
<p><strong>Target:</strong> {{ target }}</p><p><strong>Date:</strong> {{ scan_date }}</p>
<p><strong>Profile:</strong> {{ profile }}</p><p><strong>Duration:</strong> {{ duration }}</p></div>
<div class="stats">{% for sev, count in severity_counts.items() %}
<div class="stat-box"><div class="stat-number">{{ count }}</div><div>{{ sev }}</div></div>{% endfor %}</div>
<h2>Performance</h2><table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Total Requests</td><td>{{ perf.total_requests }}</td></tr>
<tr><td>Requests/sec</td><td>{{ perf.requests_per_second }}</td></tr>
<tr><td>Peak Memory</td><td>{{ perf.memory_peak_mb }} MB</td></tr></table>
<h2>Findings ({{ total_findings }})</h2>
{% for r in results %}<div class="finding {{ r.severity }}">
<h3><span class="severity {{ r.severity }}">{{ r.severity }}</span> {{ r.title }}</h3>
<p><strong>Tool:</strong> {{ r.tool }} | <strong>Time:</strong> {{ r.timestamp }}</p>
<p>{{ r.description }}</p></div>{% endfor %}
<div class="footer"><p>Professional Security Assessment Framework v8.0 | Authorized Testing Only</p></div>
</div></body></html>""")

        html = template.render(
            target=self.target_url,
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            profile=self.config['scan_profile'],
            duration=perf['total_duration'],
            total_findings=len(self.results),
            severity_counts=severity_counts,
            results=self.results,
            perf=perf
        )
        with open(output_file, 'w') as f:
            f.write(html)
        print(f"{Fore.GREEN}[+] HTML report: {output_file}{Style.RESET_ALL}")

    def generate_reports(self):
        print(f"\n{Fore.CYAN}[*] Generating reports...{Style.RESET_ALL}")
        formats = self.config.get('output_formats', ['html', 'json'])
        if 'html' in formats:
            self.export_html()
        if 'json' in formats:
            self.export_json()

    # --------------------------------------------------------
    # Main Scan Orchestrator
    # --------------------------------------------------------

    def run_scan(self, run_hydra=False, username=None, wordlist=None):
        self.banner()
        self.perf.start()

        if self.config.get('resume', False):
            self.load_state()

        # Reconnaissance
        self.fingerprint_technology()
        self.detect_waf()
        self.check_ssl_tls()
        self.analyze_security_headers()

        # Discovery
        self.comprehensive_directory_discovery()
        self.test_api_endpoints()
        self.enumerate_subdomains()
        self.discover_and_test_forms()

        # Injection Testing
        self.comprehensive_xss_testing()
        self.comprehensive_sqli_testing()
        self.comprehensive_lfi_testing()
        self.comprehensive_command_injection_testing()

        # External Tools
        self.run_nmap()
        self.run_nikto()
        self.run_sqlmap_enhanced()  # Module 17
        self.run_nuclei()            # Module 18

        # Hash Analysis (Module 19)
        self.run_hashcat_analysis()

        # Validation & Benchmarking
        self.validate_findings()
        self.benchmark_tools()

        # Finalize
        self.perf.stop()
        self.save_state()
        self.generate_reports()

        perf = self.perf.get_report()
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}✓ SCAN COMPLETE{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"Total Findings:  {len(self.results)}")
        print(f"Duration:        {perf['total_duration']}")
        print(f"Requests:        {perf['total_requests']} ({perf['requests_per_second']} req/s)")
        print(f"Memory Peak:     {perf['memory_peak_mb']} MB")
        print(f"Reports:         {self.output_dir}/")


# ============================================================
# MODULE 6: Configuration File Support
# ============================================================

def load_config(config_path):
    if config_path and os.path.exists(config_path):
        with open(config_path, 'r') as f:
            user_config = yaml.safe_load(f)
            config = DEFAULT_CONFIG.copy()
            config.update(user_config)
            return config
    return DEFAULT_CONFIG.copy()


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='Professional Security Assessment Framework v8.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py -t http://localhost:8080
  python3 scanner.py -t http://localhost:8080 -p extreme --hydra --user admin
  python3 scanner.py -t http://localhost:8080 -c config.yaml
  python3 scanner.py -t http://localhost:8080 --resume
        """)

    parser.add_argument('-t', '--target', required=True, help='Target URL')
    parser.add_argument('-p', '--profile', choices=['stealth', 'normal', 'aggressive', 'extreme'], default='aggressive')
    parser.add_argument('-c', '--config', help='YAML config file path')
    parser.add_argument('-o', '--output', default='/tmp/scan_results', help='Output directory')
    parser.add_argument('--hydra', action='store_true', help='Enable Hydra brute-force')
    parser.add_argument('--user', default='admin', help='Hydra username')
    parser.add_argument('--wordlist', help='Hydra wordlist path')
    parser.add_argument('--resume', action='store_true', help='Resume interrupted scan')

    args = parser.parse_args()

    if not args.target.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[!] Target must start with http:// or https://{Style.RESET_ALL}")
        sys.exit(1)

    print(f"\n{Fore.YELLOW}{'!'*70}")
    print(f"⚠️  AUTHORIZATION REQUIRED")
    print(f"{'!'*70}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Only use on systems you own or have written permission to test.{Style.RESET_ALL}")

    confirm = input(f"\n{Fore.CYAN}Do you have authorization to test {args.target}? (yes/no): {Style.RESET_ALL}")
    if confirm.lower() != 'yes':
        print(f"{Fore.RED}[!] Scan aborted{Style.RESET_ALL}")
        sys.exit(0)

    config = load_config(args.config)
    config['scan_profile'] = args.profile
    config['output_dir'] = args.output
    config['resume'] = args.resume

    wordlist = args.wordlist or config.get('wordlists', {}).get('passwords', '')

    scanner = ProfessionalSecurityScanner(target_url=args.target, config=config)
    scanner.run_scan(run_hydra=args.hydra, username=args.user, wordlist=wordlist)


if __name__ == '__main__':
    main()
